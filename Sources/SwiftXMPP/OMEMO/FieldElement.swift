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

/// Arithmetic in GF(2^255 − 19), the field Curve25519 lives in.
///
/// This exists for exactly one job: converting other people's public keys
/// between the Montgomery form X25519 uses and the Edwards form Ed25519 uses,
/// because CryptoKit offers both curves but no bridge between them, and OMEMO
/// needs the bridge to verify a signed prekey.
///
/// It is therefore never given a secret. Every value that passes through here
/// is a public key someone else published. That is why this is plain,
/// readable schoolbook arithmetic with data-dependent branches, and not a
/// constant-time implementation: there is nothing here for a timing channel
/// to leak. Our own private keys never leave CryptoKit.
///
/// Correctness is checked against CryptoKit itself in the tests — the same
/// scalar produces a point in both forms, and the conversion has to map one to
/// the other exactly — plus the base point, whose coordinates in both forms
/// are published constants.
struct FieldElement: Equatable {
    /// Four little-endian 64-bit limbs. Always fully reduced: value < p.
    private(set) var limbs: [UInt64]

    /// p = 2^255 − 19.
    static let p: [UInt64] = [
        0xFFFF_FFFF_FFFF_FFED, 0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF,
    ]

    static let zero = FieldElement(reduced: [0, 0, 0, 0])
    static let one = FieldElement(reduced: [1, 0, 0, 0])

    private init(reduced: [UInt64]) {
        limbs = reduced
    }

    /// From 32 little-endian bytes. The top bit is ignored, as RFC 7748 §5
    /// requires for Montgomery u-coordinates and as the Edwards encoding uses
    /// it for the sign of x rather than as part of y.
    init(bytes: Data) {
        precondition(bytes.count == 32)
        var l = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 {
            var limb: UInt64 = 0
            for j in 0..<8 {
                limb |= UInt64(bytes[bytes.startIndex + i * 8 + j]) << (8 * j)
            }
            l[i] = limb
        }
        l[3] &= 0x7FFF_FFFF_FFFF_FFFF
        limbs = Self.reduceOnce(Self.reduceOnce(l))
    }

    init(_ small: UInt64) {
        limbs = [small, 0, 0, 0]
    }

    var bytes: Data {
        var out = Data(count: 32)
        for i in 0..<4 {
            for j in 0..<8 {
                out[i * 8 + j] = UInt8((limbs[i] >> (8 * j)) & 0xFF)
            }
        }
        return out
    }

    var isZero: Bool { limbs == [0, 0, 0, 0] }

    // MARK: limb helpers

    private static func add256(_ a: [UInt64], _ b: [UInt64]) -> (sum: [UInt64], carry: Bool) {
        var out = [UInt64](repeating: 0, count: 4)
        var carry = false
        for i in 0..<4 {
            let (s1, c1) = a[i].addingReportingOverflow(b[i])
            let (s2, c2) = s1.addingReportingOverflow(carry ? 1 : 0)
            out[i] = s2
            carry = c1 || c2
        }
        return (out, carry)
    }

    private static func sub256(_ a: [UInt64], _ b: [UInt64]) -> (diff: [UInt64], borrow: Bool) {
        var out = [UInt64](repeating: 0, count: 4)
        var borrow = false
        for i in 0..<4 {
            let (d1, b1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, b2) = d1.subtractingReportingOverflow(borrow ? 1 : 0)
            out[i] = d2
            borrow = b1 || b2
        }
        return (out, borrow)
    }

    /// One conditional subtraction of p. Two of these take any value below
    /// 2^256 down into [0, p), since 2^256 = 2p + 38.
    private static func reduceOnce(_ a: [UInt64]) -> [UInt64] {
        let (d, borrow) = sub256(a, p)
        return borrow ? a : d
    }

    // MARK: field operations

    static func + (a: FieldElement, b: FieldElement) -> FieldElement {
        // a, b < p so a + b < 2p < 2^256: the addition itself cannot carry.
        let (s, _) = add256(a.limbs, b.limbs)
        return FieldElement(reduced: reduceOnce(s))
    }

    static func - (a: FieldElement, b: FieldElement) -> FieldElement {
        let (d, borrow) = sub256(a.limbs, b.limbs)
        guard borrow else { return FieldElement(reduced: d) }
        // Wrapped below zero: the true value is d + p, and the carry out of
        // the addition is exactly the 2^256 the wrap borrowed.
        let (r, _) = add256(d, p)
        return FieldElement(reduced: r)
    }

    static func * (a: FieldElement, b: FieldElement) -> FieldElement {
        // Schoolbook 4×4 → 8 limbs.
        var wide = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (hi, lo) = a.limbs[i].multipliedFullWidth(by: b.limbs[j])
                let (s1, c1) = wide[i + j].addingReportingOverflow(lo)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                wide[i + j] = s2
                carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            wide[i + 4] = carry
        }
        return FieldElement(reduced: reduce512(wide))
    }

    /// 2^256 ≡ 38 (mod p), so the high half folds in as 38·H. Twice, because
    /// the first fold can leave a small excess above 2^256.
    private static func reduce512(_ w: [UInt64]) -> [UInt64] {
        let low = Array(w[0..<4])
        let high = Array(w[4..<8])

        // 38·H, five limbs.
        var folded = [UInt64](repeating: 0, count: 5)
        var carry: UInt64 = 0
        for i in 0..<4 {
            let (hi, lo) = high[i].multipliedFullWidth(by: 38)
            let (s, c) = lo.addingReportingOverflow(carry)
            folded[i] = s
            carry = hi &+ (c ? 1 : 0)
        }
        folded[4] = carry

        // + L.
        var (sum, c) = add256(Array(folded[0..<4]), low)
        var top = folded[4] &+ (c ? 1 : 0)

        // Fold the small top limb the same way; it is at most a few hundred.
        (sum, c) = add256(sum, [top &* 38, 0, 0, 0])
        top = c ? 1 : 0
        if top != 0 {
            (sum, _) = add256(sum, [38, 0, 0, 0])
        }
        return reduceOnce(reduceOnce(sum))
    }

    /// a^(p−2), which is a^(−1) by Fermat. Square-and-multiply over the
    /// exponent's 255 bits; slow and obviously correct, and only ever run on a
    /// public key at conversion time.
    func inverse() -> FieldElement {
        let exponent: [UInt64] = [
            0xFFFF_FFFF_FFFF_FFEB, 0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF,
        ]
        var result = FieldElement.one
        for bit in stride(from: 254, through: 0, by: -1) {
            result = result * result
            if (exponent[bit / 64] >> UInt64(bit % 64)) & 1 == 1 {
                result = result * self
            }
        }
        return result
    }
}
