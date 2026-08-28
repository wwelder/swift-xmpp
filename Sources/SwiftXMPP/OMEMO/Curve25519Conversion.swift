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

import Foundation

/// The bridge between X25519 keys and Ed25519 keys.
///
/// Curve25519 in Montgomery form (what X25519 and OMEMO identity keys use) and
/// in twisted Edwards form (what Ed25519 signs with) are the same curve seen
/// through a birational map:
///
///     y = (u − 1) / (u + 1)        u = (1 + y) / (1 − y)
///
/// XEdDSA — the signature scheme OMEMO and Signal use — is Ed25519 performed
/// on an X25519 key by converting it with exactly this map and fixing the sign
/// of x to zero. CryptoKit exposes neither the map nor XEdDSA, so a signed
/// prekey published by another client cannot be verified without this file.
enum Curve25519Conversion {
    /// The compressed Edwards point an XEdDSA verifier derives from a
    /// Montgomery public key: y from the map, sign bit clear.
    ///
    /// Returns nil for u = −1, which has no Edwards image; a key that decodes to
    /// it is not a valid public key.
    static func edwardsPublicKey(fromMontgomery u: Data) -> Data? {
        let u = FieldElement(bytes: u)
        let denominator = u + .one
        guard !denominator.isZero else { return nil }
        let y = (u - .one) * denominator.inverse()
        var encoded = y.bytes
        encoded[31] &= 0x7F // sign of x: zero, by XEdDSA's definition
        return encoded
    }

    /// The Montgomery u-coordinate of a compressed Edwards point. The sign bit
    /// is discarded: u does not depend on it.
    ///
    /// Returns nil for y = 1, the neutral element, which has no finite u.
    static func montgomeryPublicKey(fromEdwards point: Data) -> Data? {
        let y = FieldElement(bytes: point) // init masks the sign bit
        let denominator = FieldElement.one - y
        guard !denominator.isZero else { return nil }
        return ((.one + y) * denominator.inverse()).bytes
    }
}
