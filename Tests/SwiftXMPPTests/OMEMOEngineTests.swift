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

import XCTest
@testable import SwiftXMPP

/// The whole OMEMO stack, exercised as two engines talking through an in-memory
/// stand-in for PEP. This is as close to the real interop test as can run
/// without another client: bundle publish and fetch, X3DH from a fetched
/// bundle, the ratchet, the `<encrypted>` element, and decrypt back to
/// plaintext — every layer, in one path, with no server.
final class OMEMOEngineTests: XCTestCase {
    /// A directory that hands out whatever an engine published. Stands in for
    /// the PEP nodes the real transport would read.
    private actor Directory: OMEMOBundleSource {
        private var bundles: [String: OMEMOBundle] = [:]
        private var devices: [String: [UInt32]] = [:]

        func publish(jid: String, deviceID: UInt32, bundle: OMEMOBundle) {
            bundles["\(jid)/\(deviceID)"] = bundle
            devices[jid, default: []].append(deviceID)
        }

        func bundle(for jid: String, deviceID: UInt32) async throws -> OMEMOBundle {
            guard let b = bundles["\(jid)/\(deviceID)"] else { throw OMEMOError.malformedMessage }
            return b
        }

        func deviceIDs(for jid: String) async throws -> [UInt32] { devices[jid] ?? [] }
    }

    private func pair() async throws -> (alice: OMEMOEngine, bob: OMEMOEngine, dir: Directory) {
        let dir = Directory()
        let alice = OMEMOEngine()
        let bob = OMEMOEngine()
        await alice.setBundleSource(dir)
        await bob.setBundleSource(dir)
        try await dir.publish(jid: "alice@srv", deviceID: alice.deviceID, bundle: alice.bundle())
        try await dir.publish(jid: "bob@srv", deviceID: bob.deviceID, bundle: bob.bundle())
        return (alice, bob, dir)
    }

    func testFirstMessageEstablishesASessionAndDecrypts() async throws {
        let (alice, bob, _) = try await pair()
        let encrypted = try await alice.encrypt(Data("hello bob".utf8), for: "bob@srv")

        // The first message must be a prekey message - it starts the session.
        XCTAssertTrue(encrypted.keys.first { $0.deviceID == bob.deviceID }!.isPreKey)

        let decrypted = try await bob.decrypt(encrypted, from: "alice@srv")
        XCTAssertEqual(decrypted, Data("hello bob".utf8))
    }

    func testConversationContinuesAfterTheHandshake() async throws {
        let (alice, bob, _) = try await pair()

        let m1 = try await alice.encrypt(Data("one".utf8), for: "bob@srv")
        let d1 = try await bob.decrypt(m1, from: "alice@srv")
        XCTAssertEqual(d1, Data("one".utf8))

        // Bob replies; now his messages are ordinary ratchet messages, not prekey.
        let reply = try await bob.encrypt(Data("two".utf8), for: "alice@srv")
        XCTAssertFalse(reply.keys.first { $0.deviceID == alice.deviceID }!.isPreKey)
        let d2 = try await alice.decrypt(reply, from: "bob@srv")
        XCTAssertEqual(d2, Data("two".utf8))

        let m3 = try await alice.encrypt(Data("three".utf8), for: "bob@srv")
        let d3 = try await bob.decrypt(m3, from: "alice@srv")
        XCTAssertEqual(d3, Data("three".utf8))
    }

    /// A message fans out to every device; a device that is not a recipient
    /// gets nil, not an error.
    func testMessageForAnotherDeviceReturnsNil() async throws {
        let (alice, bob, dir) = try await pair()
        // A third device belonging to nobody we decrypt as.
        let stranger = OMEMOEngine()
        await stranger.setBundleSource(dir)

        let encrypted = try await alice.encrypt(Data("for bob".utf8), for: "bob@srv")
        // Stranger was not addressed; decrypt must be a quiet nil.
        let result = try await stranger.decrypt(encrypted, from: "alice@srv")
        XCTAssertNil(result)
    }

    /// Multi-device: Bob has two devices, and one message must reach both.
    func testFanOutToMultipleDevices() async throws {
        let dir = Directory()
        let alice = OMEMOEngine()
        let bobPhone = OMEMOEngine()
        let bobLaptop = OMEMOEngine()
        for e in [alice, bobPhone, bobLaptop] { await e.setBundleSource(dir) }
        try await dir.publish(jid: "alice@srv", deviceID: alice.deviceID, bundle: alice.bundle())
        try await dir.publish(jid: "bob@srv", deviceID: bobPhone.deviceID, bundle: bobPhone.bundle())
        try await dir.publish(jid: "bob@srv", deviceID: bobLaptop.deviceID, bundle: bobLaptop.bundle())

        let encrypted = try await alice.encrypt(Data("to all of bob".utf8), for: "bob@srv")
        XCTAssertEqual(encrypted.keys.count, 2)
        let onPhone = try await bobPhone.decrypt(encrypted, from: "alice@srv")
        let onLaptop = try await bobLaptop.decrypt(encrypted, from: "alice@srv")
        XCTAssertEqual(onPhone, Data("to all of bob".utf8))
        XCTAssertEqual(onLaptop, Data("to all of bob".utf8))
    }

    /// The signed prekey in a fetched bundle is verified before use; a bundle
    /// whose signature does not match its identity is rejected, because that is
    /// an impersonation and encrypting to it would leak the message.
    func testBundleWithABadSignatureIsRejected() async throws {
        let dir = Directory()
        let alice = OMEMOEngine()
        await alice.setBundleSource(dir)

        // Bob's bundle, but signed by someone else.
        let realBob = OMEMOEngine()
        var bobBundle = try await realBob.bundle()
        let imposter = IdentityKey()
        bobBundle = OMEMOBundle(
            signedPreKeyID: bobBundle.signedPreKeyID,
            signedPreKeyPublic: bobBundle.signedPreKeyPublic,
            signedPreKeySignature: try imposter.sign(bobBundle.signedPreKeyPublic),
            identityKey: bobBundle.identityKey,
            preKeys: bobBundle.preKeys
        )
        try await dir.publish(jid: "bob@srv", deviceID: realBob.deviceID, bundle: bobBundle)

        do {
            _ = try await alice.encrypt(Data("x".utf8), for: "bob@srv")
            XCTFail("a forged bundle must not be usable")
        } catch {
            XCTAssertEqual(error as? OMEMOError, .untrustedSignedPreKey)
        }
    }

    /// Interop invariant a self-consistent round trip can't catch: every public
    /// key in a published bundle — one-time prekeys included — must be in
    /// libsignal network format (33 bytes, 0x05 prefix), or real clients
    /// (python-omemo, Dino) reject the whole bundle at parse time.
    func testPublishedBundleKeysAreInNetworkFormat() async throws {
        let bundle = try await OMEMOEngine().bundle()
        XCTAssertEqual(bundle.identityKey.count, 33)
        XCTAssertEqual(bundle.identityKey.first, 0x05)
        XCTAssertEqual(bundle.signedPreKeyPublic.count, 33)
        XCTAssertEqual(bundle.signedPreKeyPublic.first, 0x05)
        XCTAssertFalse(bundle.preKeys.isEmpty)
        for pk in bundle.preKeys {
            XCTAssertEqual(pk.publicKey.count, 33, "prekey \(pk.id) not network format")
            XCTAssertEqual(pk.publicKey.first, 0x05, "prekey \(pk.id) missing 0x05 prefix")
        }
    }
}
