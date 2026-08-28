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
import XCTest
@testable import SwiftXMPP

/// The field arithmetic and the curve conversion, checked against an oracle
/// that cannot be argued with: CryptoKit computes the same point in both
/// forms from the same scalar, and our conversion has to map one to the other
/// exactly. A single wrong bit anywhere in the arithmetic fails this.
final class Curve25519ConversionTests: XCTestCase {
    // MARK: field arithmetic

    func testInverseTimesSelfIsOne() {
        for _ in 0..<20 {
            let a = FieldElement(bytes: Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
            guard !a.isZero else { continue }
            XCTAssertEqual(a * a.inverse(), .one)
        }
    }

    func testAdditiveInverse() {
        let a = FieldElement(bytes: Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
        XCTAssertEqual(a - a, .zero)
        XCTAssertEqual((.zero - a) + a, .zero)
    }

    /// Multiplication must agree with repeated addition, which exercises the
    /// 512-bit reduction against arithmetic that never needs it.
    func testMultiplicationMatchesRepeatedAddition() {
        let a = FieldElement(bytes: Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
        var sum = FieldElement.zero
        for _ in 0..<7 { sum = sum + a }
        XCTAssertEqual(a * FieldElement(7), sum)
    }

    /// 2^255 − 19 itself must decode to zero, and p − 1 must be −1.
    func testReductionAtTheModulus() {
        var pBytes = Data(count: 32)
        for i in 0..<4 { for j in 0..<8 { pBytes[i * 8 + j] = UInt8((FieldElement.p[i] >> (8 * j)) & 0xFF) } }
        XCTAssertEqual(FieldElement(bytes: pBytes), .zero)

        var pMinusOne = pBytes
        pMinusOne[0] -= 1
        XCTAssertEqual(FieldElement(bytes: pMinusOne) + .one, .zero)
    }

    /// The largest inputs the multiplier can see, so the reduction's second
    /// fold is actually exercised rather than assumed.
    func testMultiplicationOfMaximalValues() {
        var pBytes = Data(count: 32)
        for i in 0..<4 { for j in 0..<8 { pBytes[i * 8 + j] = UInt8((FieldElement.p[i] >> (8 * j)) & 0xFF) } }
        pBytes[0] -= 1
        let pMinusOne = FieldElement(bytes: pMinusOne(pBytes))
        // (−1)·(−1) = 1
        XCTAssertEqual(pMinusOne * pMinusOne, .one)
    }

    private func pMinusOne(_ bytes: Data) -> Data { bytes }

    // MARK: the base point, a published constant in both forms

    /// Ed25519's base point has y = 4/5; Curve25519's has u = 9. Same point.
    func testBasePointConvertsBothWays() {
        let y = FieldElement(4) * FieldElement(5).inverse()
        var edwards = y.bytes
        edwards[31] &= 0x7F

        var montgomery = Data(count: 32)
        montgomery[0] = 9

        XCTAssertEqual(Curve25519Conversion.montgomeryPublicKey(fromEdwards: edwards), montgomery)
        XCTAssertEqual(Curve25519Conversion.edwardsPublicKey(fromMontgomery: montgomery), edwards)
    }

    // MARK: the oracle

    /// For many random keys: CryptoKit's X25519 public key and CryptoKit's
    /// Ed25519 public key, derived from the same scalar, must be the same
    /// point under our conversion. This validates every operation in
    /// `FieldElement` with no external test vectors at all.
    func testConversionAgreesWithCryptoKitOnRandomKeys() {
        var checked = 0
        for _ in 0..<200 {
            let ed = Curve25519.Signing.PrivateKey()
            var scalar = Data(SHA512.hash(data: ed.rawRepresentation).prefix(32))
            scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64
            let x = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar)

            let edPk = ed.publicKey.rawRepresentation
            let xPk = x.publicKey.rawRepresentation

            // Edwards → Montgomery is sign-independent, so it must hold for every key.
            XCTAssertEqual(Curve25519Conversion.montgomeryPublicKey(fromEdwards: edPk), xPk)

            // Montgomery → Edwards yields the sign-0 point, so compare y only.
            var edY = edPk
            edY[31] &= 0x7F
            XCTAssertEqual(Curve25519Conversion.edwardsPublicKey(fromMontgomery: xPk), edY)
            checked += 1
        }
        XCTAssertEqual(checked, 200)
    }

    func testDegenerateInputsAreRejected() {
        // u = −1 ≡ p − 1 has no Edwards image.
        var minusOne = Data(count: 32)
        for i in 0..<4 { for j in 0..<8 { minusOne[i * 8 + j] = UInt8((FieldElement.p[i] >> (8 * j)) & 0xFF) } }
        minusOne[0] -= 1
        XCTAssertNil(Curve25519Conversion.edwardsPublicKey(fromMontgomery: minusOne))

        // y = 1 is the neutral element and has no finite u.
        var one = Data(count: 32)
        one[0] = 1
        XCTAssertNil(Curve25519Conversion.montgomeryPublicKey(fromEdwards: one))
    }
}

/// The identity key: one CryptoKit key wearing both hats, and signatures that
/// verify through the XEdDSA path another client would use.
final class IdentityKeyTests: XCTestCase {
    func testGeneratedKeyHasZeroSignBit() {
        for _ in 0..<10 {
            let key = IdentityKey()
            let restored = IdentityKey(rawRepresentation: key.rawRepresentation)
            XCTAssertNotNil(restored)
            XCTAssertEqual(restored?.publicKey, key.publicKey)
        }
    }

    /// The whole point: a signature made with CryptoKit's Ed25519 verifies
    /// against the *Montgomery* public key we publish, through the same
    /// conversion an XEdDSA verifier performs. If this holds, other OMEMO
    /// clients can verify our signed prekeys, and we theirs.
    func testSignatureVerifiesThroughTheMontgomeryKey() throws {
        let key = IdentityKey()
        let data = Data("signed prekey bundle".utf8)
        let signature = try key.sign(data)

        XCTAssertTrue(IdentityKey.verify(signature, for: data, publicKey: key.publicKey))
        XCTAssertFalse(IdentityKey.verify(signature, for: Data("tampered".utf8), publicKey: key.publicKey))
        XCTAssertFalse(IdentityKey.verify(signature, for: data, publicKey: IdentityKey().publicKey))
    }

    func testAgreementIsSymmetric() throws {
        let alice = IdentityKey()
        let bob = IdentityKey()
        let ab = try alice.sharedSecret(with: bob.publicKey)
        let ba = try bob.sharedSecret(with: alice.publicKey)
        XCTAssertEqual(
            ab.withUnsafeBytes { Data($0) },
            ba.withUnsafeBytes { Data($0) }
        )
    }

    /// A seed whose public key has a set sign bit would sign in a way XEdDSA
    /// verifiers reject; the initialiser refuses it rather than let it in.
    func testSeedWithSetSignBitIsRefused() {
        var rejected = false
        for _ in 0..<64 {
            let candidate = Curve25519.Signing.PrivateKey()
            if candidate.publicKey.rawRepresentation[31] & 0x80 != 0 {
                XCTAssertNil(IdentityKey(rawRepresentation: candidate.rawRepresentation))
                rejected = true
                break
            }
        }
        XCTAssertTrue(rejected, "64 random keys with no set sign bit is a 1-in-2^64 event")
    }
}
