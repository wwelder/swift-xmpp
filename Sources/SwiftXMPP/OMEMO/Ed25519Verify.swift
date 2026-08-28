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

/// Ed25519 signature verification, RFC 8032, done here rather than through
/// CryptoKit.
///
/// CryptoKit's `Curve25519.Signing.PublicKey.isValidSignature` rejects a subset
/// of the XEdDSA signatures that OMEMO clients actually produce — libsodium and
/// pyca/cryptography accept the very same signature, and so must a client that
/// wants to verify a signed prekey from Conversations, Dino or Gajim. This is
/// the standard verification equation, with the cofactored check RFC 8032 §5.1.7
/// permits and which XEdDSA relies on:
///
///     [8]R  ==  [8](s·B − k·A)
///
/// It runs only on other people's public keys and signatures, never on a
/// secret, so like the field arithmetic it is plain and not constant-time.
///
/// Correctness is pinned two ways: against CryptoKit for the signatures
/// CryptoKit does accept (they must agree), and against a real signature from
/// the python-omemo stack that CryptoKit rejects (we must accept it, as
/// libsodium does).
enum Ed25519Verify {
    /// Verify `signature` (64 bytes: R‖S) over `message` under the compressed
    /// Edwards public key `publicKey` (32 bytes).
    static func isValid(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 32 else { return false }

        let rBytes = Data(signature.prefix(32))
        let sBytes = Data(signature.suffix(32))

        guard let a = Point(compressed: publicKey) else { return false }
        guard let rPoint = Point(compressed: rBytes) else { return false }
        guard let s = Scalar(canonical: sBytes) else { return false }

        // k = SHA-512(R ‖ A ‖ M) mod L
        var hashInput = rBytes
        hashInput.append(publicKey)
        hashInput.append(message)
        let k = Scalar(reducing: Data(SHA512.hash(data: hashInput)))

        // Check [8](s·B) == [8](R + k·A), i.e. s·B == R + k·A up to cofactor.
        let sB = Point.base.scalarMul(s)
        let kA = a.scalarMul(k)
        let rPlusKA = rPoint.add(kA)

        return sB.mul8().equals(rPlusKA.mul8())
    }

    // MARK: scalar mod L

    /// A scalar mod L = 2^252 + 27742317777372353535851937790883648493.
    private struct Scalar {
        /// 32 little-endian bytes, reduced mod L.
        let bytes: [UInt8]

        /// Group order L, little-endian.
        static let L: [UInt8] = [
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]

        /// Reject a non-canonical S (S >= L), which RFC 8032 §5.1.7 requires.
        init?(canonical data: Data) {
            let b = [UInt8](data)
            guard b.count == 32 else { return nil }
            guard Scalar.less(b, Scalar.L) else { return nil }
            bytes = b
        }

        /// Reduce a 64-byte hash mod L (Barrett-free: schoolbook long division
        /// is more than fast enough at verify time).
        init(reducing data: Data) {
            bytes = Scalar.reduceWide([UInt8](data))
        }

        private static func less(_ a: [UInt8], _ b: [UInt8]) -> Bool {
            for i in stride(from: 31, through: 0, by: -1) {
                if a[i] != b[i] { return a[i] < b[i] }
            }
            return false // equal is not less
        }

        /// 64-byte little-endian value mod L, by repeated subtraction of shifted
        /// L. Correct and obvious; used once per verification.
        private static func reduceWide(_ wide: [UInt8]) -> [UInt8] {
            // Work in a big integer as [UInt8] little-endian of length 64.
            var x = wide
            // L is 253 bits and wide is 512, so shifts up to 512−253 = 259 are
            // needed; starting lower leaves the result unreduced and every
            // signature then fails verification.
            for shift in stride(from: 512 - 253, through: 0, by: -1) {
                let shifted = shiftLeft(L, bits: shift, width: 64)
                if !lessWide(x, shifted) {
                    x = subWide(x, shifted)
                }
            }
            return Array(x.prefix(32))
        }

        private static func shiftLeft(_ v: [UInt8], bits: Int, width: Int) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: width)
            let byteShift = bits / 8, bitShift = bits % 8
            for i in 0..<v.count {
                let lo = i + byteShift
                if lo < width {
                    out[lo] |= UInt8((UInt16(v[i]) << bitShift) & 0xFF)
                }
                if bitShift != 0, lo + 1 < width {
                    out[lo + 1] |= UInt8(UInt16(v[i]) >> (8 - bitShift))
                }
            }
            return out
        }

        private static func lessWide(_ a: [UInt8], _ b: [UInt8]) -> Bool {
            for i in stride(from: a.count - 1, through: 0, by: -1) {
                if a[i] != b[i] { return a[i] < b[i] }
            }
            return false
        }

        private static func subWide(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: a.count)
            var borrow = 0
            for i in 0..<a.count {
                let d = Int(a[i]) - Int(b[i]) - borrow
                if d < 0 { out[i] = UInt8(d + 256); borrow = 1 } else { out[i] = UInt8(d); borrow = 0 }
            }
            return out
        }

        /// The bit at position `i`, for the double-and-add ladder.
        func bit(_ i: Int) -> Bool { (bytes[i / 8] >> (i % 8)) & 1 == 1 }
    }

    // MARK: Edwards points

    /// A point on the twisted Edwards curve, in extended coordinates
    /// (X:Y:Z:T) with x = X/Z, y = Y/Z, xy = T/Z.
    private struct Point {
        var x, y, z, t: FieldElement

        /// d = −121665/121666.
        static let d: FieldElement = {
            let num = FieldElement.zero - FieldElement(121_665)
            return num * FieldElement(121_666).inverse()
        }()

        /// The base point B.
        static let base: Point = {
            // y = 4/5, x recovered with the positive (even) sign.
            let y = FieldElement(4) * FieldElement(5).inverse()
            let x = recoverX(y: y, sign: 0)!
            return Point(x: x, y: y, z: .one, t: x * y)
        }()

        static let identity = Point(x: .zero, y: .one, z: .one, t: .zero)

        /// Decompress a 32-byte encoding: low 255 bits are y, top bit is the
        /// sign of x.
        init?(compressed: Data) {
            let bytes = [UInt8](compressed)
            guard bytes.count == 32 else { return nil }
            let sign = Int(bytes[31] >> 7)
            var yBytes = bytes
            yBytes[31] &= 0x7F
            let y = FieldElement(bytes: Data(yBytes))
            guard let x = Point.recoverX(y: y, sign: sign) else { return nil }
            self.x = x; self.y = y; z = .one; t = x * y
        }

        private init(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) {
            self.x = x; self.y = y; self.z = z; self.t = t
        }

        /// Solve x from the curve equation −x² + y² = 1 + d·x²·y², choosing the
        /// root whose low bit matches `sign`.
        static func recoverX(y: FieldElement, sign: Int) -> FieldElement? {
            let y2 = y * y
            let u = y2 - .one
            let v = (d * y2) + .one
            // x = u/v · (u/v)^((p-5)/8) corrected; compute via candidate = u·v³·(u·v⁷)^((p-5)/8).
            let v3 = v * v * v
            let v7 = v3 * v3 * v
            let candidate0 = (u * v3) * powP58(u * v7)
            var x = candidate0
            let vx2 = v * x * x
            if vx2 == u {
                // ok
            } else if vx2 == (.zero - u) {
                x = x * sqrtM1
            } else {
                return nil // not a square: invalid point
            }
            var xBytes = x.bytes
            let low = Int(xBytes[0] & 1)
            if low != sign {
                x = FieldElement.zero - x
                xBytes = x.bytes
                if x.isZero, sign == 1 { return nil }
            }
            return x
        }

        /// a^((p-5)/8), the exponent used in the square-root formula.
        private static func powP58(_ a: FieldElement) -> FieldElement {
            // (p-5)/8, little-endian bits.
            let exp: [UInt8] = [
                0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
            ]
            var result = FieldElement.one
            for i in stride(from: 254, through: 0, by: -1) {
                result = result * result
                if (exp[i / 8] >> (i % 8)) & 1 == 1 { result = result * a }
            }
            return result
        }

        /// √(−1) mod p = 2^((p-1)/4) = 2^(2^253−5).
        static let sqrtM1: FieldElement = {
            let exp: [UInt8] = [
                0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F,
            ]
            var result = FieldElement.one
            let two = FieldElement(2)
            for i in stride(from: 254, through: 0, by: -1) {
                result = result * result
                if (exp[i / 8] >> (i % 8)) & 1 == 1 { result = result * two }
            }
            return result
        }()

        func add(_ q: Point) -> Point {
            // Unified addition for extended twisted Edwards coordinates (a = −1).
            let a = (y - x) * (q.y - q.x)
            let b = (y + x) * (q.y + q.x)
            let c = t * Point.d * FieldElement(2) * q.t
            let dd = z * FieldElement(2) * q.z
            let e = b - a
            let f = dd - c
            let g = dd + c
            let h = b + a
            return Point(x: e * f, y: g * h, z: f * g, t: e * h)
        }

        func double() -> Point { add(self) }

        func mul8() -> Point { double().double().double() }

        func scalarMul(_ s: Scalar) -> Point {
            var result = Point.identity
            var addend = self
            for i in 0..<253 {
                if s.bit(i) { result = result.add(addend) }
                addend = addend.double()
            }
            return result
        }

        /// Projective equality: X1·Z2 == X2·Z1 and Y1·Z2 == Y2·Z1.
        func equals(_ q: Point) -> Bool {
            (x * q.z == q.x * z) && (y * q.z == q.y * z)
        }
    }
}
