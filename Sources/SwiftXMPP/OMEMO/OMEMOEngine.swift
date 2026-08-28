//
// SwiftXMPP — an XMPP client core written from the specifications.
// Copyright (C) 2026 Baseco.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details. You should have received a copy of it in the LICENSE file.
//

import CryptoKit
import Foundation

/// Ties the OMEMO pieces into two operations: encrypt a body for a contact's
/// devices, and decrypt an `<encrypted>` element from one. Everything below
/// this — X3DH, the ratchet, the wire shapes — is stateless machinery; the
/// engine is where the state lives: our own keys, and one ratchet session per
/// remote device.
///
/// It is deliberately transport-agnostic. It turns plaintext into an
/// `EncryptedElement.Message` and back, and asks its delegate for bundles it
/// does not have; how those travel over XMPP is the session's job. That seam is
/// what lets the whole thing be tested by wiring two engines to each other with
/// no server at all.
public protocol OMEMOBundleSource: AnyObject {
    /// Fetch a device's prekey bundle. Called when we must start a session with
    /// a device we have not encrypted to before.
    func bundle(for jid: String, deviceID: UInt32) async throws -> OMEMOBundle
    /// The device ids a contact has published.
    func deviceIDs(for jid: String) async throws -> [UInt32]
}

public actor OMEMOEngine {
    /// Our long-term identity, and this installation's device id. The device id
    /// is random and published in our device list; a JID is one person across
    /// many of these.
    private let identity: IdentityKey
    public nonisolated let deviceID: UInt32

    /// Our own prekeys, kept so we can answer an incoming PreKeySignalMessage.
    private let signedPreKey: Curve25519.KeyAgreement.PrivateKey
    private let signedPreKeyID: UInt32
    private var oneTimePreKeys: [UInt32: Curve25519.KeyAgreement.PrivateKey]

    /// One ratchet per remote device we are talking to, keyed by "jid/deviceID".
    private var sessions: [String: DoubleRatchet] = [:]

    // Strong: the bundle source is a collaborator the engine cannot work
    // without, not a delegate that may come and go. A weak reference here
    // silently nils out and turns every encrypt into a malformed-message error
    // the moment the caller stops holding the source itself.
    private var bundleSource: OMEMOBundleSource?

    public init(identity: IdentityKey = IdentityKey(), deviceID: UInt32? = nil) {
        self.identity = identity
        self.deviceID = deviceID ?? UInt32.random(in: 1...UInt32.max)
        signedPreKey = Curve25519.KeyAgreement.PrivateKey()
        signedPreKeyID = UInt32.random(in: 1...UInt32.max)
        var otks: [UInt32: Curve25519.KeyAgreement.PrivateKey] = [:]
        for _ in 0..<100 { otks[UInt32.random(in: 1...UInt32.max)] = Curve25519.KeyAgreement.PrivateKey() }
        oneTimePreKeys = otks
    }

    public func setBundleSource(_ source: OMEMOBundleSource) {
        bundleSource = source
    }

    public var identityPublicKey: Data { identity.publicKey }

    /// The 32-byte seed to persist. Restoring from it reconstructs the same
    /// identity and therefore the same published key.
    public var identitySeed: Data { identity.rawRepresentation }

    /// Our bundle to publish. The one-time prekeys are all we currently hold;
    /// each is consumed the first time a peer uses it.
    public func bundle() throws -> OMEMOBundle {
        // libsignal convention: keys carry a 0x05 DJB type byte, and the
        // signed-prekey signature covers that 33-byte serialized form. Both are
        // required for Conversations/Dino/Gajim to verify us; signing the bare
        // 32 bytes is the interop bug that looks fine in isolation.
        OMEMOBundle(
            signedPreKeyID: signedPreKeyID,
            signedPreKeyPublic: SignalWire.serialize(publicKey: signedPreKey.publicKey.rawRepresentation),
            signedPreKeySignature: try identity.sign(SignalWire.serialize(publicKey: signedPreKey.publicKey.rawRepresentation)),
            identityKey: SignalWire.serialize(publicKey: identity.publicKey),
            // Every public key in a bundle travels in libsignal network format
            // (0x05-prefixed), one-time prekeys included; a bare 32-byte prekey
            // makes real clients reject the whole bundle at parse time.
            preKeys: oneTimePreKeys.map { ($0.key, SignalWire.serialize(publicKey: $0.value.publicKey.rawRepresentation)) }
        )
    }

    // MARK: encrypting

    /// Encrypt a body for every device a contact has published, starting a
    /// session (via the peer's bundle) with any we have not met.
    public func encrypt(_ plaintext: Data, for jid: String) async throws -> EncryptedElement.Message {
        guard let source = bundleSource else { throw OMEMOError.malformedMessage }
        let devices = try await source.deviceIDs(for: jid)
        let (payload, iv, keyAndTag) = try EncryptedElement.encryptBody(plaintext)

        var keys: [EncryptedElement.Key] = []
        for device in devices {
            let sessionKey = "\(jid)/\(device)"
            var isPreKey = false

            if sessions[sessionKey] == nil {
                let bundle = try await source.bundle(for: jid, deviceID: device)
                try startOutgoingSession(with: bundle, key: sessionKey)
                isPreKey = true
            }

            // A struct in a dictionary is not a mutable lvalue; take it out,
            // advance it, put it back, or the ratchet never moves.
            var ratchet = sessions[sessionKey]!
            let encrypted = try ratchet.encrypt(keyAndTag)
            sessions[sessionKey] = ratchet

            // The first message of a session is a PreKeySignalMessage: it wraps
            // the ratchet message together with everything the recipient needs
            // to run X3DH. Later messages are the ratchet message alone.
            let blob: Data
            if isPreKey, let ctx = pendingPreKeyHeaders.removeValue(forKey: sessionKey) {
                blob = PreKeySignalMessage(
                    registrationId: deviceID,
                    preKeyId: ctx.oneTimePreKeyID,
                    signedPreKeyId: ctx.signedPreKeyID,
                    baseKey: ctx.ephemeral,
                    identityKey: ctx.identity,
                    message: encrypted.ciphertext
                ).serialize()
            } else {
                blob = encrypted.ciphertext
            }
            keys.append(.init(deviceID: device, data: blob, isPreKey: isPreKey))
        }

        return EncryptedElement.Message(senderDeviceID: deviceID, keys: keys, payload: payload, iv: iv)
    }

    // MARK: decrypting

    /// Decrypt an `<encrypted>` message from a contact. Returns nil for a
    /// key-transport message (no body) after processing its session material,
    /// which is how a peer silently establishes or heals a session.
    public func decrypt(
        _ message: EncryptedElement.Message, from jid: String
    ) async throws -> Data? {
        let sessionKey = "\(jid)/\(message.senderDeviceID)"

        // Find the key blob addressed to us.
        guard let ourKey = message.keys.first(where: { $0.deviceID == deviceID }) else {
            // Not for this device. Common and not an error - a message fans out
            // to every device, including ones that are not us.
            return nil
        }

        let keyAndTag: Data
        if ourKey.isPreKey {
            keyAndTag = try startIncomingSession(
                preKeyData: ourKey.data, from: jid, sessionKey: sessionKey
            )
        } else {
            guard var ratchet = sessions[sessionKey] else { throw OMEMOError.malformedMessage }
            keyAndTag = try ratchet.decrypt(
                DoubleRatchet.EncryptedMessage(
                    header: .init(ratchetKey: Data(), previousChainLength: 0, messageNumber: 0),
                    ciphertext: ourKey.data
                )
            )
            sessions[sessionKey] = ratchet
        }

        guard let payload = message.payload, let iv = message.iv else { return nil } // key-transport
        return try EncryptedElement.decryptBody(payload: payload, iv: iv, keyAndTag: keyAndTag)
    }

    // MARK: sessions

    private func startOutgoingSession(with bundle: OMEMOBundle, key: String) throws {
        let result = try X3DH.initiate(ourIdentity: identity, theirBundle: OMEMOBundle.x3dh(from: bundle))
        // The first message's key blob is a PreKeySignalMessage, so the header
        // carries our ephemeral and the prekey ids the peer must use. That is
        // assembled in the ratchet's first output, below, via the pre-key path.
        let ratchet = try DoubleRatchet.initiating(
            sharedSecret: result.sharedSecret,
            remoteRatchetKey: SignalWire.normalize(bundle.signedPreKeyPublic),
            selfIdentity: identity.publicKey,
            remoteIdentity: SignalWire.normalize(bundle.identityKey)
        )
        sessions[key] = ratchet
        pendingPreKeyHeaders[key] = PreKeyContext(
            ephemeral: result.ephemeralPublicKey,
            identity: identity.publicKey,
            signedPreKeyID: bundle.signedPreKeyID,
            oneTimePreKeyID: bundle.preKeys.first?.id
        )
    }

    private func startIncomingSession(
        preKeyData: Data, from jid: String, sessionKey: String
    ) throws -> Data {
        let preKey = try PreKeySignalMessage.parse(preKeyData)
        guard let preKeyId = preKey.preKeyId, let otk = oneTimePreKeys[preKeyId] else {
            // The one-time prekey is gone: already used, or a replay. Either way
            // X3DH cannot complete, and completing it with the wrong key would
            // be worse than failing.
            throw OMEMOError.malformedMessage
        }
        let secret = try X3DH.respond(
            ourIdentity: identity,
            ourSignedPreKey: signedPreKey,
            ourOneTimePreKey: otk,
            theirIdentityPublicKey: preKey.identityKey,
            theirEphemeralPublicKey: preKey.baseKey
        )
        oneTimePreKeys[preKeyId] = nil // consumed exactly once

        var ratchet = DoubleRatchet.responding(
            sharedSecret: secret, ourRatchetPrivate: signedPreKey,
            selfIdentity: identity.publicKey, remoteIdentity: SignalWire.normalize(preKey.identityKey)
        )
        let plaintext = try ratchet.decrypt(
            DoubleRatchet.EncryptedMessage(
                header: .init(ratchetKey: Data(), previousChainLength: 0, messageNumber: 0),
                ciphertext: preKey.message
            )
        )
        sessions[sessionKey] = ratchet
        return plaintext
    }

    private struct PreKeyContext {
        let ephemeral: Data
        let identity: Data
        let signedPreKeyID: UInt32
        let oneTimePreKeyID: UInt32?
    }
    private var pendingPreKeyHeaders: [String: PreKeyContext] = [:]
}

extension OMEMOBundle {
    /// The subset X3DH needs, taking the first available one-time prekey.
    static func x3dh(from bundle: OMEMOBundle) -> X3DH.Bundle {
        X3DH.Bundle(
            identityKey: bundle.identityKey,
            signedPreKey: bundle.signedPreKeyPublic,
            signedPreKeySignature: bundle.signedPreKeySignature,
            oneTimePreKey: bundle.preKeys.first?.publicKey
        )
    }
}
