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

/// The Double Ratchet (Signal), which gives every message its own key and
/// heals the session forward after a compromise.
///
/// Two ratchets turn together. The Diffie-Hellman ratchet steps whenever a new
/// public key arrives, mixing fresh key material into the root chain so a
/// leaked message key does not compromise later messages. The symmetric
/// ratchet advances a sending or receiving chain one message at a time. Every
/// message key is used exactly once.
///
/// Two properties matter and both are quiet when broken: message keys are
/// never reused (a reused key voids the guarantees the whole thing exists to
/// provide) and out-of-order messages are handled by deriving and storing the
/// keys that were skipped, so a message that arrives late still decrypts and a
/// message that never arrives does not stall the ones behind it.
struct DoubleRatchet {
    /// Skipped message keys, kept until their message arrives. Bounded, because
    /// an attacker who can make us skip keys can otherwise make us allocate
    /// without limit.
    private static let maxSkip = 1000

    private var rootKey: SymmetricKey
    private var sendingChainKey: SymmetricKey?
    private var receivingChainKey: SymmetricKey?

    private var selfRatchetPrivate: Curve25519.KeyAgreement.PrivateKey
    private var remoteRatchetPublic: Data?

    /// Bound into every message's MAC (Signal's associated data), so a
    /// ciphertext cannot be replayed into a different pair of identities.
    let selfIdentity: Data
    let remoteIdentity: Data

    private var sendCount = 0
    private var receiveCount = 0
    /// Messages in the previous sending chain, carried in each header so the
    /// far side knows how many to skip when we ratchet.
    private var previousSendCount = 0

    /// Keyed by (ratchet public, message number). A missing message's key
    /// waits here until it turns up.
    private var skipped: [SkippedKey: SymmetricKey] = [:]

    private struct SkippedKey: Hashable {
        let ratchet: Data
        let index: Int
    }

    /// Header sent in the clear alongside each ciphertext.
    struct Header: Equatable {
        let ratchetKey: Data
        let previousChainLength: Int
        let messageNumber: Int
    }

    /// The bytes that go on the wire: a serialized, authenticated
    /// `SignalMessage`. Self-describing - the ratchet key and counters are
    /// inside it - so nothing rides alongside.
    struct EncryptedMessage {
        let header: Header
        let ciphertext: Data
    }

    // MARK: setup

    /// Initiator: we already hold the shared secret and the responder's signed
    /// prekey public, and step the DH ratchet once immediately so our first
    /// message carries a fresh ratchet key.
    static func initiating(
        sharedSecret: SymmetricKey, remoteRatchetKey: Data,
        selfIdentity: Data, remoteIdentity: Data
    ) throws -> DoubleRatchet {
        var ratchet = DoubleRatchet(
            rootKey: sharedSecret,
            selfRatchetPrivate: Curve25519.KeyAgreement.PrivateKey(),
            remoteRatchetPublic: remoteRatchetKey,
            selfIdentity: selfIdentity, remoteIdentity: remoteIdentity
        )
        try ratchet.stepDHRatchetForSending()
        return ratchet
    }

    /// Responder: we hold the shared secret and the private ratchet key the
    /// initiator will encrypt to (our signed prekey). Our chains open when the
    /// initiator's first message arrives and we see their ratchet key.
    static func responding(
        sharedSecret: SymmetricKey, ourRatchetPrivate: Curve25519.KeyAgreement.PrivateKey,
        selfIdentity: Data, remoteIdentity: Data
    ) -> DoubleRatchet {
        DoubleRatchet(
            rootKey: sharedSecret,
            selfRatchetPrivate: ourRatchetPrivate,
            remoteRatchetPublic: nil,
            selfIdentity: selfIdentity, remoteIdentity: remoteIdentity
        )
    }

    private init(
        rootKey: SymmetricKey,
        selfRatchetPrivate: Curve25519.KeyAgreement.PrivateKey,
        remoteRatchetPublic: Data?,
        selfIdentity: Data,
        remoteIdentity: Data
    ) {
        self.rootKey = rootKey
        self.selfRatchetPrivate = selfRatchetPrivate
        self.remoteRatchetPublic = remoteRatchetPublic
        self.selfIdentity = selfIdentity
        self.remoteIdentity = remoteIdentity
    }

    // MARK: sending

    mutating func encrypt(_ plaintext: Data, associatedData: Data = Data()) throws -> EncryptedMessage {
        guard let chainKey = sendingChainKey else {
            throw OMEMOError.malformedMessage // no sending chain yet
        }
        let (nextChain, messageKey) = Self.advanceChain(chainKey)
        sendingChainKey = nextChain

        let material = Self.messageKeyMaterial(messageKey)
        let ciphertext = try CBC.encrypt(plaintext, key: material.cipherKey, iv: material.iv)

        let signal = SignalMessage(
            ratchetKey: selfRatchetPrivate.publicKey.rawRepresentation,
            counter: UInt32(sendCount),
            previousCounter: UInt32(previousSendCount),
            ciphertext: ciphertext
        )
        sendCount += 1
        let wire = signal.serialize(
            macKey: material.macKey, senderIdentity: selfIdentity, receiverIdentity: remoteIdentity
        )
        let header = Header(
            ratchetKey: signal.ratchetKey,
            previousChainLength: previousSendCount,
            messageNumber: signal.counter == 0 && sendCount == 1 ? 0 : Int(signal.counter)
        )
        return EncryptedMessage(header: header, ciphertext: wire)
    }

    // MARK: receiving

    mutating func decrypt(_ message: EncryptedMessage) throws -> Data {
        let (signal, body, mac) = try SignalMessage.parse(message.ciphertext)
        let number = Int(signal.counter)

        if let key = skipped[SkippedKey(ratchet: signal.ratchetKey, index: number)] {
            let plaintext = try open(signal, body: body, mac: mac, messageKey: key)
            skipped[SkippedKey(ratchet: signal.ratchetKey, index: number)] = nil
            return plaintext
        }

        // A ratchet key we have not seen means the far side stepped its DH
        // ratchet. Bank the remaining keys of the current receiving chain, then
        // step ours to match.
        if signal.ratchetKey != remoteRatchetPublic {
            try skipReceivingKeys(until: Int(signal.previousCounter))
            try stepDHRatchetForReceiving(remoteRatchetKey: signal.ratchetKey)
        }

        try skipReceivingKeys(until: number)

        guard let chainKey = receivingChainKey else { throw OMEMOError.malformedMessage }
        let (nextChain, messageKey) = Self.advanceChain(chainKey)
        receivingChainKey = nextChain
        receiveCount += 1

        return try open(signal, body: body, mac: mac, messageKey: messageKey)
    }

    /// Derive and store the keys for messages numbered [receiveCount, target),
    /// so they can still be decrypted when they arrive out of order.
    private mutating func skipReceivingKeys(until target: Int) throws {
        guard let chainKey = receivingChainKey, let ratchet = remoteRatchetPublic else { return }
        guard target - receiveCount <= Self.maxSkip else {
            throw OMEMOError.skippedTooManyMessages
        }
        var chain = chainKey
        while receiveCount < target {
            let (next, messageKey) = Self.advanceChain(chain)
            skipped[SkippedKey(ratchet: ratchet, index: receiveCount)] = messageKey
            chain = next
            receiveCount += 1
        }
        receivingChainKey = chain
    }

    // MARK: the DH ratchet

    private mutating func stepDHRatchetForSending() throws {
        guard let remote = remoteRatchetPublic else { return }
        let dh = try selfRatchetPrivate.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: remote)
        )
        (rootKey, sendingChainKey) = Self.stepRoot(rootKey, dh)
    }

    private mutating func stepDHRatchetForReceiving(remoteRatchetKey: Data) throws {
        previousSendCount = sendCount
        sendCount = 0
        receiveCount = 0
        remoteRatchetPublic = remoteRatchetKey

        // Receiving chain from the incoming key against our current ratchet key.
        let dhRecv = try selfRatchetPrivate.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteRatchetKey)
        )
        (rootKey, receivingChainKey) = Self.stepRoot(rootKey, dhRecv)

        // New ratchet key of our own, and a sending chain from it, so our next
        // message advances the ratchet in turn.
        selfRatchetPrivate = Curve25519.KeyAgreement.PrivateKey()
        let dhSend = try selfRatchetPrivate.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteRatchetKey)
        )
        (rootKey, sendingChainKey) = Self.stepRoot(rootKey, dhSend)
    }

    // MARK: KDFs

    /// Root KDF: HKDF over the DH output, salted by the current root key. Out
    /// come the next root key and a fresh chain key.
    private static func stepRoot(_ rootKey: SymmetricKey, _ dh: SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let derived = dh.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: rootKey.withUnsafeBytes { Data($0) },
            sharedInfo: Data("WhisperRatchet".utf8), // libsignal RootKey info, verbatim
            outputByteCount: 64
        )
        let bytes = derived.withUnsafeBytes { Data($0) }
        return (SymmetricKey(data: bytes.prefix(32)), SymmetricKey(data: bytes.suffix(32)))
    }

    /// Chain KDF: two fixed-label HMACs off the chain key give the next chain
    /// key and this message's key. Distinct labels keep the two independent.
    private static func advanceChain(_ chainKey: SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let nextChain = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: chainKey)
        let messageKey = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: chainKey)
        return (SymmetricKey(data: Data(nextChain)), SymmetricKey(data: Data(messageKey)))
    }

    private func open(_ signal: SignalMessage, body: Data, mac: Data, messageKey: SymmetricKey) throws -> Data {
        let material = Self.messageKeyMaterial(messageKey)
        // The MAC binds both identities; when receiving, the sender is the
        // remote. A wrong key or an altered message fails here and is a
        // security event, not a decode hiccup.
        guard SignalMessage.verify(
            body: body, mac: mac, macKey: material.macKey,
            senderIdentity: remoteIdentity, receiverIdentity: selfIdentity
        ) else {
            throw OMEMOError.messageAuthenticationFailed
        }
        return try CBC.decrypt(signal.ciphertext, key: material.cipherKey, iv: material.iv)
    }

    /// A message key expands to an AES key, a MAC key and an IV, the way legacy
    /// OMEMO derives them: HKDF-SHA-256 with a 32-byte zero salt and libsignal's
    /// "WhisperMessageKeys" info, split 32 (cipher) / 32 (mac) / 16 (iv).
    private static func messageKeyMaterial(
        _ messageKey: SymmetricKey
    ) -> (cipherKey: Data, macKey: SymmetricKey, iv: Data) {
        let expanded = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: messageKey,
            salt: Data(repeating: 0, count: 32),
            info: Data("WhisperMessageKeys".utf8),
            outputByteCount: 80
        ).withUnsafeBytes { Data($0) }
        return (
            cipherKey: expanded.prefix(32),
            macKey: SymmetricKey(data: expanded.subdata(in: 32..<64)),
            iv: expanded.subdata(in: 64..<80)
        )
    }
}
