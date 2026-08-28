import CryptoKit
import XCTest
@testable import SwiftXMPP

/// Ed25519 verification, pinned first to RFC 8032 §7.1 test vectors (which have
/// nothing to do with OMEMO), then to a real XEdDSA signature CryptoKit rejects.
final class Ed25519VerifyTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return d
    }

    /// RFC 8032 §7.1 TEST 2: single-byte message.
    func testRFC8032Vector2() {
        let pub = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        let msg = hex("72")
        let sig = hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        XCTAssertTrue(Ed25519Verify.isValid(signature: sig, message: msg, publicKey: pub))
    }

    /// RFC 8032 §7.1 TEST 3: two-byte message.
    func testRFC8032Vector3() {
        let pub = hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        let msg = hex("af82")
        let sig = hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
        XCTAssertTrue(Ed25519Verify.isValid(signature: sig, message: msg, publicKey: pub))
    }

    /// A tampered message must fail against a genuine vector.
    func testRFC8032VectorRejectsTamper() {
        let pub = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        let sig = hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        XCTAssertFalse(Ed25519Verify.isValid(signature: sig, message: hex("73"), publicKey: pub))
    }

    /// The real XEdDSA signature from python-omemo (Gajim stack) that CryptoKit
    /// rejects. Our verifier must accept it, as libsodium and pyca do.
    func testAcceptsRealXEdDSASignatureCryptoKitRejects() {
        let mont = hex("35bac84b47db36b1b6859ca291a0d35b2ac5b355275f827b59168ddfa0c3b826")
        let spk = hex("05bb0ff5b7cea9c8b34ca9449fa9a5072bde37b7e72f53673d882d8db3e4241e26")
        let sig = hex("779a5785dd294450eff589610c2d4da60cd806b34c47481d99076969466a351965199c9200a1584135cdd3c1160d23107f8b0ecab25848ace91694e9c83f1288")
        XCTAssertTrue(IdentityKey.verify(sig, for: spk, publicKey: mont))
    }

    /// Must still accept everything CryptoKit accepts — our own signatures.
    func testAcceptsOurOwnSignatures() throws {
        for _ in 0..<20 {
            let key = IdentityKey()
            let msg = Data((0..<40).map { _ in UInt8.random(in: 0...255) })
            let sig = try key.sign(msg)
            XCTAssertTrue(IdentityKey.verify(sig, for: msg, publicKey: key.publicKey))
        }
    }

    func testRejectsWrongKeyAndNonCanonicalScalar() throws {
        let key = IdentityKey()
        let msg = Data("m".utf8)
        let sig = try key.sign(msg)
        XCTAssertFalse(IdentityKey.verify(sig, for: msg, publicKey: IdentityKey().publicKey))
        var bad = sig; for i in 32..<64 { bad[i] = 0xFF }
        XCTAssertFalse(IdentityKey.verify(bad, for: msg, publicKey: key.publicKey))
    }
}

extension Ed25519VerifyTests {
    /// Isolate the two halves of the XEdDSA path for the failing key.
    func testConversionAndVerifySeparately() {
        let mont = hex("35bac84b47db36b1b6859ca291a0d35b2ac5b355275f827b59168ddfa0c3b826")
        let spk = hex("05bb0ff5b7cea9c8b34ca9449fa9a5072bde37b7e72f53673d882d8db3e4241e26")
        let sig = hex("779a5785dd294450eff589610c2d4da60cd806b34c47481d99076969466a351965199c9200a1584135cdd3c1160d23107f8b0ecab25848ace91694e9c83f1288")
        _ = sig
        let ours = Curve25519Conversion.edwardsPublicKey(fromMontgomery: mont)!.map { String(format: "%02x", $0) }.joined()
        // Our conversion must reproduce xeddsa's curve25519_pub_to_ed25519_pub
        // (sign bit 0) for this key, byte for byte.
        XCTAssertEqual(ours, "3305addbea57c553b1da4cd0e9366becaeb1b2dde3dc1560c629ba231baddf13")
    }
}
