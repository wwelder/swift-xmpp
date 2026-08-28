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

/// X3DH and the Double Ratchet, exercised as two peers actually talking. None
/// of these failures throw at the point of the mistake: a wrong DH order gives
/// two peers who each derive a different secret and go silent, a reused message
/// key voids the guarantee without any symptom, and a skipped-key bug loses a
/// late message rather than erroring. So they are tested by making messages
/// cross and checking they arrive.
final class OMEMOSessionTests: XCTestCase {
    /// A full X3DH handshake into two ratchets, returned ready to talk.
    private func establishedPair() throws -> (initiator: DoubleRatchet, responder: DoubleRatchet) {
        let aliceIdentity = IdentityKey()
        let bobIdentity = IdentityKey()
        let bobSignedPreKey = Curve25519.KeyAgreement.PrivateKey()
        let signature = try bobIdentity.sign(SignalWire.serialize(publicKey: bobSignedPreKey.publicKey.rawRepresentation))
        let bobOneTime = Curve25519.KeyAgreement.PrivateKey()

        let bundle = X3DH.Bundle(
            identityKey: bobIdentity.publicKey,
            signedPreKey: SignalWire.serialize(publicKey: bobSignedPreKey.publicKey.rawRepresentation),
            signedPreKeySignature: signature,
            oneTimePreKey: bobOneTime.publicKey.rawRepresentation
        )

        let aliceResult = try X3DH.initiate(ourIdentity: aliceIdentity, theirBundle: bundle)
        let bobSecret = try X3DH.respond(
            ourIdentity: bobIdentity,
            ourSignedPreKey: bobSignedPreKey,
            ourOneTimePreKey: bobOneTime,
            theirIdentityPublicKey: aliceResult.identityPublicKey,
            theirEphemeralPublicKey: aliceResult.ephemeralPublicKey
        )

        // Both sides must have agreed on the same secret, or nothing else works.
        XCTAssertEqual(
            aliceResult.sharedSecret.withUnsafeBytes { Data($0) },
            bobSecret.withUnsafeBytes { Data($0) }
        )

        let alice = try DoubleRatchet.initiating(
            sharedSecret: aliceResult.sharedSecret,
            remoteRatchetKey: bobSignedPreKey.publicKey.rawRepresentation,
            selfIdentity: aliceIdentity.publicKey, remoteIdentity: bobIdentity.publicKey
        )
        let bob = DoubleRatchet.responding(
            sharedSecret: bobSecret, ourRatchetPrivate: bobSignedPreKey,
            selfIdentity: bobIdentity.publicKey, remoteIdentity: aliceIdentity.publicKey
        )
        return (alice, bob)
    }

    func testX3DHRejectsAnUnsignedPreKey() throws {
        let alice = IdentityKey()
        let bob = IdentityKey()
        let spk = Curve25519.KeyAgreement.PrivateKey()
        // Signed by a different identity than the bundle claims.
        let imposter = IdentityKey()
        let badSig = try imposter.sign(spk.publicKey.rawRepresentation)

        let bundle = X3DH.Bundle(
            identityKey: bob.publicKey,
            signedPreKey: SignalWire.serialize(publicKey: spk.publicKey.rawRepresentation),
            signedPreKeySignature: badSig,
            oneTimePreKey: nil
        )
        XCTAssertThrowsError(try X3DH.initiate(ourIdentity: alice, theirBundle: bundle)) {
            XCTAssertEqual($0 as? OMEMOError, .untrustedSignedPreKey)
        }
    }

    func testSingleMessage() throws {
        var (alice, bob) = try establishedPair()
        let message = try alice.encrypt(Data("hello bob".utf8))
        XCTAssertEqual(try bob.decrypt(message), Data("hello bob".utf8))
    }

    func testConversationBackAndForth() throws {
        var (alice, bob) = try establishedPair()

        let a1 = try alice.encrypt(Data("one".utf8))
        XCTAssertEqual(try bob.decrypt(a1), Data("one".utf8))

        // Bob replies, which steps the DH ratchet in the other direction.
        let b1 = try bob.encrypt(Data("two".utf8))
        XCTAssertEqual(try alice.decrypt(b1), Data("two".utf8))

        let a2 = try alice.encrypt(Data("three".utf8))
        XCTAssertEqual(try bob.decrypt(a2), Data("three".utf8))
    }

    /// The property that a reused key would break: every ciphertext must be
    /// distinct even for identical plaintext, because every message key is.
    func testEachMessageUsesADistinctKey() throws {
        var (alice, bob) = try establishedPair()
        let c1 = try alice.encrypt(Data("same".utf8))
        let c2 = try alice.encrypt(Data("same".utf8))
        XCTAssertNotEqual(c1.ciphertext, c2.ciphertext)
        XCTAssertEqual(try bob.decrypt(c1), Data("same".utf8))
        XCTAssertEqual(try bob.decrypt(c2), Data("same".utf8))
    }

    /// Out of order within one chain: message 2 arrives before message 1, and
    /// both must still decrypt. This is the skipped-key path.
    func testOutOfOrderDelivery() throws {
        var (alice, bob) = try establishedPair()
        let a1 = try alice.encrypt(Data("first".utf8))
        let a2 = try alice.encrypt(Data("second".utf8))
        let a3 = try alice.encrypt(Data("third".utf8))

        XCTAssertEqual(try bob.decrypt(a3), Data("third".utf8))
        XCTAssertEqual(try bob.decrypt(a1), Data("first".utf8))
        XCTAssertEqual(try bob.decrypt(a2), Data("second".utf8))
    }

    /// A message lost forever must not stall the ones behind it.
    func testDroppedMessageDoesNotStall() throws {
        var (alice, bob) = try establishedPair()
        _ = try alice.encrypt(Data("dropped".utf8)) // never delivered
        let a2 = try alice.encrypt(Data("delivered".utf8))
        XCTAssertEqual(try bob.decrypt(a2), Data("delivered".utf8))
    }

    /// Skipped keys across a DH ratchet step: Alice sends, Bob replies (new
    /// ratchet), Alice sends again, and an earlier message from before the
    /// step still arrives.
    func testSkippedKeysSurviveARatchetStep() throws {
        var (alice, bob) = try establishedPair()
        let a1 = try alice.encrypt(Data("before reply".utf8))
        let a2 = try alice.encrypt(Data("also before".utf8))

        XCTAssertEqual(try bob.decrypt(a2), Data("also before".utf8))
        let b1 = try bob.encrypt(Data("reply".utf8))
        XCTAssertEqual(try alice.decrypt(b1), Data("reply".utf8))

        // a1 was sent before Bob's ratchet step and arrives only now.
        XCTAssertEqual(try bob.decrypt(a1), Data("before reply".utf8))
    }

    /// A tampered ciphertext is a security event, surfaced as one.
    func testTamperedMessageIsRejected() throws {
        var (alice, bob) = try establishedPair()
        let message = try alice.encrypt(Data("authentic".utf8))
        var corrupted = message.ciphertext
        corrupted[corrupted.count - 1] ^= 0x01
        let tampered = DoubleRatchet.EncryptedMessage(header: message.header, ciphertext: corrupted)

        XCTAssertThrowsError(try bob.decrypt(tampered)) {
            XCTAssertEqual($0 as? OMEMOError, .messageAuthenticationFailed)
        }
    }

    /// X3DH must also work without a one-time prekey, since a server can run
    /// out of them and a session still has to start.
    func testHandshakeWithoutOneTimePreKey() throws {
        let alice = IdentityKey()
        let bob = IdentityKey()
        let spk = Curve25519.KeyAgreement.PrivateKey()
        let sig = try bob.sign(SignalWire.serialize(publicKey: spk.publicKey.rawRepresentation))
        let bundle = X3DH.Bundle(
            identityKey: bob.publicKey,
            signedPreKey: SignalWire.serialize(publicKey: spk.publicKey.rawRepresentation),
            signedPreKeySignature: sig,
            oneTimePreKey: nil
        )
        let result = try X3DH.initiate(ourIdentity: alice, theirBundle: bundle)
        let bobSecret = try X3DH.respond(
            ourIdentity: bob, ourSignedPreKey: spk, ourOneTimePreKey: nil,
            theirIdentityPublicKey: result.identityPublicKey,
            theirEphemeralPublicKey: result.ephemeralPublicKey
        )
        XCTAssertEqual(
            result.sharedSecret.withUnsafeBytes { Data($0) },
            bobSecret.withUnsafeBytes { Data($0) }
        )
    }
}
