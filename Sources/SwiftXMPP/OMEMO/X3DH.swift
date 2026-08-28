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

/// X3DH, the key agreement that starts an OMEMO session (Signal's "Extended
/// Triple Diffie-Hellman").
///
/// The idea is to derive a shared secret from four DH operations so that the
/// result depends on both parties' long-term identity *and* fresh ephemeral
/// keys, giving forward secrecy and cryptographic deniability at once. Getting
/// the four DHs into the wrong order, or dropping one, produces two peers that
/// each compute a different secret and simply cannot talk — no error, just
/// silence. So the order is stated once, here, and both sides read from it.
///
///     DH1 = DH(IK_a, SPK_b)     our identity  × their signed prekey
///     DH2 = DH(EK_a, IK_b)      our ephemeral × their identity
///     DH3 = DH(EK_a, SPK_b)     our ephemeral × their signed prekey
///     DH4 = DH(EK_a, OPK_b)     our ephemeral × their one-time prekey (if any)
///     SK  = HKDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4)
///
/// The initiator and responder compute the same four values with the roles of
/// the DH inputs swapped, which is the whole trick and the whole hazard.
enum X3DH {
    /// OMEMO uses the legacy libsignal KDF: HKDF-SHA-256 with an all-zero salt
    /// and a 32-byte 0xFF prefix on the input keying material.
    static let info = Data("OMEMO X3DH".utf8)

    /// What the recipient of a signed-prekey bundle needs to start a session.
    struct Bundle {
        let identityKey: Data          // IK_b, Montgomery form
        let signedPreKey: Data         // SPK_b public
        let signedPreKeySignature: Data
        let oneTimePreKey: Data?       // OPK_b public, consumed if present
    }

    /// The result: the shared secret, plus the ephemeral public the responder
    /// needs (it never saw our ephemeral otherwise) and which one-time prekey
    /// we consumed, so the responder knows which private key to use.
    struct InitiatorResult {
        let sharedSecret: SymmetricKey
        let ephemeralPublicKey: Data
        let usedOneTimePreKey: Data?
        /// Our identity public, so the responder can run its side.
        let identityPublicKey: Data
    }

    /// Initiator side. Verifies the signed prekey before using it: an
    /// unsigned or wrongly-signed prekey is an impersonation attempt, and the
    /// signature is the only thing tying the prekey to the identity we think
    /// we are talking to.
    static func initiate(
        ourIdentity: IdentityKey, theirBundle bundle: Bundle
    ) throws -> InitiatorResult {
        // Peer keys may arrive with the 0x05 DJB prefix; strip it for the raw
        // 32-byte curve point, but verify the signature over the serialized
        // signed prekey exactly as it was signed.
        let peerIdentity = SignalWire.normalize(bundle.identityKey)
        guard IdentityKey.verify(
            bundle.signedPreKeySignature, for: bundle.signedPreKey, publicKey: peerIdentity
        ) else {
            throw OMEMOError.untrustedSignedPreKey
        }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let peerSignedPreKey = SignalWire.normalize(bundle.signedPreKey)

        let dh1 = try ourIdentity.sharedSecret(with: peerSignedPreKey)
        let dh2 = try ephemeral.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerIdentity)
        )
        let dh3 = try ephemeral.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerSignedPreKey)
        )
        var ikm = concat(dh1, dh2, dh3)
        if let opk = bundle.oneTimePreKey {
            let dh4 = try ephemeral.sharedSecretFromKeyAgreement(
                with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: SignalWire.normalize(opk))
            )
            ikm += dh4.withUnsafeBytes { Data($0) }
        }

        return InitiatorResult(
            sharedSecret: deriveSecret(from: ikm),
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            usedOneTimePreKey: bundle.oneTimePreKey,
            identityPublicKey: ourIdentity.publicKey
        )
    }

    /// Responder side. Given the initiator's identity and ephemeral publics and
    /// our own private keys, recompute the same secret with the DH roles
    /// swapped.
    static func respond(
        ourIdentity: IdentityKey,
        ourSignedPreKey: Curve25519.KeyAgreement.PrivateKey,
        ourOneTimePreKey: Curve25519.KeyAgreement.PrivateKey?,
        theirIdentityPublicKey: Data,
        theirEphemeralPublicKey: Data
    ) throws -> SymmetricKey {
        let theirIdentity = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: SignalWire.normalize(theirIdentityPublicKey)
        )
        let theirEphemeral = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: SignalWire.normalize(theirEphemeralPublicKey)
        )

        // DH1: their identity × our signed prekey (mirror of initiator's DH1).
        let dh1 = try ourSignedPreKey.sharedSecretFromKeyAgreement(with: theirIdentity)
        // DH2: their ephemeral × our identity.
        let dh2 = try ourIdentity.sharedSecret(with: SignalWire.normalize(theirEphemeralPublicKey))
        // DH3: their ephemeral × our signed prekey.
        let dh3 = try ourSignedPreKey.sharedSecretFromKeyAgreement(with: theirEphemeral)
        var ikm = concat(dh1, dh2, dh3)
        if let opk = ourOneTimePreKey {
            let dh4 = try opk.sharedSecretFromKeyAgreement(with: theirEphemeral)
            ikm += dh4.withUnsafeBytes { Data($0) }
        }
        return deriveSecret(from: ikm)
    }

    private static func concat(_ secrets: SharedSecret...) -> Data {
        secrets.reduce(Data()) { $0 + $1.withUnsafeBytes { Data($0) } }
    }

    private static func deriveSecret(from ikm: Data) -> SymmetricKey {
        // libsignal's F ‖ KM convention: 32 bytes of 0xFF ahead of the DH
        // outputs, all-zero salt.
        let prefixed = Data(repeating: 0xFF, count: 32) + ikm
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: prefixed),
            salt: Data(repeating: 0, count: 32),
            info: info,
            outputByteCount: 32
        )
        return key
    }
}

public enum OMEMOError: Error, LocalizedError {
    case untrustedSignedPreKey
    case messageAuthenticationFailed
    case skippedTooManyMessages
    case malformedMessage

    public var errorDescription: String? {
        switch self {
        case .untrustedSignedPreKey:
            "The other device's prekey was not signed by the identity it claims."
        case .messageAuthenticationFailed:
            "A message failed its authentication check and was not decrypted."
        case .skippedTooManyMessages:
            "Too many messages are missing to safely catch up."
        case .malformedMessage:
            "The encrypted message was malformed."
        }
    }
}
