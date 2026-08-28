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

/// An OMEMO identity key: one Curve25519 key that both agrees (X25519) and
/// signs (XEdDSA), as the Signal protocol requires.
///
/// CryptoKit keeps agreement and signing as separate, unrelated key types.
/// The trick that makes one key do both without reimplementing either:
///
/// 1. Generate an Ed25519 key. Its private scalar is `clamp(SHA-512(seed))`,
///    and Ed25519's clamping is X25519's clamping, so that same scalar handed
///    to CryptoKit as an X25519 private key yields the *same point* on the
///    curve — the agreement public key is the Montgomery form of the signing
///    public key.
/// 2. Keep only seeds whose Ed25519 public key has a zero sign bit. XEdDSA
///    verifiers reconstruct the Edwards key from the Montgomery one with the
///    sign forced to zero; when ours already is, an ordinary Ed25519 signature
///    from CryptoKit is byte-for-byte what an XEdDSA verifier expects.
///
/// Half of all seeds qualify, so generation loops twice on average. Every
/// private-key operation stays inside CryptoKit; the only arithmetic of ours
/// involved anywhere is the public-key conversion used to verify *other*
/// parties, in `Curve25519Conversion`.
public struct IdentityKey {
    private let signing: Curve25519.Signing.PrivateKey
    private let agreement: Curve25519.KeyAgreement.PrivateKey

    /// The Montgomery-form public key, which is what OMEMO publishes and what
    /// other clients address us by.
    public var publicKey: Data { agreement.publicKey.rawRepresentation }

    /// The 32-byte seed. Store this and nothing else; both keys derive from it.
    public var rawRepresentation: Data { signing.rawRepresentation }

    public init() {
        var candidate = Curve25519.Signing.PrivateKey()
        while candidate.publicKey.rawRepresentation[31] & 0x80 != 0 {
            candidate = Curve25519.Signing.PrivateKey()
        }
        self.init(unchecked: candidate)
    }

    /// Restore from a stored seed. Rejects a seed whose public key has a set
    /// sign bit, because signatures from it would not verify as XEdDSA — such
    /// a seed can only come from somewhere other than `init()`.
    public init?(rawRepresentation seed: Data) {
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed),
              key.publicKey.rawRepresentation[31] & 0x80 == 0 else { return nil }
        self.init(unchecked: key)
    }

    private init(unchecked signing: Curve25519.Signing.PrivateKey) {
        self.signing = signing
        // RFC 8032 §5.1.5: the private scalar is the clamped first half of
        // SHA-512(seed). Clamping matches RFC 7748 §5, so this scalar is a
        // valid X25519 private key for the same point.
        var scalar = Data(SHA512.hash(data: signing.rawRepresentation).prefix(32))
        scalar[0] &= 248
        scalar[31] &= 127
        scalar[31] |= 64
        // Cannot fail: any 32 bytes are a valid X25519 scalar.
        agreement = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    }

    // MARK: signing

    /// An XEdDSA-compatible signature over `data`.
    public func sign(_ data: Data) throws -> Data {
        try signing.signature(for: data)
    }

    /// Verify a signature made by another party's identity key, given in the
    /// Montgomery form they published. This is the XEdDSA verification path:
    /// convert to Edwards with the sign bit clear, then verify as Ed25519.
    public static func verify(_ signature: Data, for data: Data, publicKey: Data) -> Bool {
        guard publicKey.count == 32, signature.count == 64,
              var edwards = Curve25519Conversion.edwardsPublicKey(fromMontgomery: publicKey) else {
            return false
        }
        // XEdDSA (libsignal) convention: the montgomery public key fixes only y,
        // so the sign of x is carried in bit 255 of s. Recover it, clear it from
        // the scalar, and set it on the Edwards public key we reconstruct — then
        // it is an ordinary Ed25519 signature. Our own signatures have this bit
        // clear (sign forced to 0), so they pass through unchanged.
        var sig = signature
        let signBit = sig[sig.startIndex + 63] & 0x80
        sig[sig.startIndex + 63] &= 0x7F
        edwards[edwards.startIndex + 31] = (edwards[edwards.startIndex + 31] & 0x7F) | signBit

        // Cofactored check (RFC 8032 §5.1.7), because CryptoKit rejects a subset
        // of valid XEdDSA signatures that libsodium and pyca accept.
        return Ed25519Verify.isValid(signature: sig, message: data, publicKey: edwards)
    }

    // MARK: agreement

    /// X25519 with another party's public key.
    public func sharedSecret(with publicKey: Data) throws -> SharedSecret {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        return try agreement.sharedSecretFromKeyAgreement(with: peer)
    }
}
