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

/// The OMEMO wire shapes. A field named or encoded wrong here does not throw:
/// it means a real client silently cannot read what we publish, or we cannot
/// read theirs. So every shape is round-tripped, and the round trip is checked
/// against the exact legacy element names Conversations and Dino use.
final class OMEMOWireTests: XCTestCase {
    func testDeviceListRoundTrip() {
        let stanza = OMEMOPublishing.publishDeviceList([111, 222, 333])
        // The published element, wrapped as it comes back from a fetch.
        let list = stanza.child("publish")!.child("item")!.child("list")!
        let items = Stanza("pubsub", children: [Stanza("items", children: [Stanza("item", children: [list])])])
        XCTAssertEqual(OMEMOPublishing.parseDeviceList(items), [111, 222, 333])
    }

    func testBundleRoundTrip() {
        let bundle = OMEMOBundle(
            signedPreKeyID: 7,
            signedPreKeyPublic: Data(repeating: 0xA1, count: 32),
            signedPreKeySignature: Data(repeating: 0xB2, count: 64),
            identityKey: Data(repeating: 0xC3, count: 32),
            preKeys: [(1, Data(repeating: 0x01, count: 32)), (2, Data(repeating: 0x02, count: 32))]
        )
        let published = OMEMOPublishing.publishBundle(bundle, deviceID: 42)
        let item = published.child("publish")!.child("item")!
        let asItems = Stanza("pubsub", children: [Stanza("items", children: [Stanza("item", children: [item.child("bundle")!])])])
        let parsed = OMEMOPublishing.parseBundle(asItems)
        XCTAssertEqual(parsed?.signedPreKeyID, 7)
        XCTAssertEqual(parsed?.signedPreKeyPublic, bundle.signedPreKeyPublic)
        XCTAssertEqual(parsed?.signedPreKeySignature, bundle.signedPreKeySignature)
        XCTAssertEqual(parsed?.identityKey, bundle.identityKey)
        XCTAssertEqual(parsed?.preKeys.map(\.id), [1, 2])
    }

    func testBundleUsesLegacyElementNames() {
        let bundle = OMEMOBundle(
            signedPreKeyID: 1, signedPreKeyPublic: Data(count: 32),
            signedPreKeySignature: Data(count: 64), identityKey: Data(count: 32), preKeys: []
        )
        let element = bundle.element()
        // The names other clients look for, verbatim.
        XCTAssertNotNil(element.child("signedPreKeyPublic")?["signedPreKeyId"])
        XCTAssertNotNil(element.child("signedPreKeySignature"))
        XCTAssertNotNil(element.child("identityKey"))
        XCTAssertEqual(element["xmlns"], "eu.siacs.conversations.axolotl")
    }

    func testEncryptedElementRoundTrip() {
        let message = EncryptedElement.Message(
            senderDeviceID: 5,
            keys: [
                .init(deviceID: 10, data: Data(repeating: 0x11, count: 40), isPreKey: true),
                .init(deviceID: 20, data: Data(repeating: 0x22, count: 40), isPreKey: false),
            ],
            payload: Data(repeating: 0x33, count: 24),
            iv: Data(repeating: 0x44, count: 12)
        )
        let parsed = EncryptedElement.parse(message.element())
        XCTAssertEqual(parsed?.senderDeviceID, 5)
        XCTAssertEqual(parsed?.keys.count, 2)
        XCTAssertEqual(parsed?.keys.first?.deviceID, 10)
        XCTAssertEqual(parsed?.keys.first?.isPreKey, true)
        XCTAssertEqual(parsed?.keys.last?.isPreKey, false)
        XCTAssertEqual(parsed?.payload, message.payload)
        XCTAssertEqual(parsed?.iv, message.iv)
    }

    /// A key-transport message carries keys and no body, used to start or heal
    /// a session without a visible message.
    func testKeyTransportMessageHasNoPayload() {
        let message = EncryptedElement.Message(
            senderDeviceID: 1, keys: [.init(deviceID: 2, data: Data(count: 40), isPreKey: false)],
            payload: nil, iv: nil
        )
        XCTAssertNil(message.element().child("payload"))
        XCTAssertNil(EncryptedElement.parse(message.element())?.payload)
    }

    /// The body cipher: encrypt under a fresh key, and the payload key the
    /// ratchet would transport recovers the body exactly.
    func testBodyEncryptionRoundTrip() throws {
        let plaintext = Data("secret message".utf8)
        let (payload, iv, keyAndTag) = try EncryptedElement.encryptBody(plaintext)
        XCTAssertEqual(keyAndTag.count, 32) // 16-byte key + 16-byte tag
        XCTAssertEqual(iv.count, 12) // 12-byte GCM nonce, carried in <header><iv>
        XCTAssertEqual(try EncryptedElement.decryptBody(payload: payload, iv: iv, keyAndTag: keyAndTag), plaintext)
    }

    func testBodyDecryptionRejectsAWrongKey() throws {
        let (payload, iv, _) = try EncryptedElement.encryptBody(Data("x".utf8))
        XCTAssertThrowsError(
            try EncryptedElement.decryptBody(payload: payload, iv: iv, keyAndTag: Data(repeating: 0, count: 32))
        )
    }

    /// Interop invariant: the oldmemo key exchange leaves field 5 (registrationId,
    /// "unused") unset, and real clients (python-omemo, Dino) omit it. Parsing
    /// must accept its absence rather than treat the message as malformed — we
    /// never read registrationId on the responder side.
    func testPreKeyMessageParsesWithoutRegistrationId() throws {
        // A key exchange with fields 1,2,3,4,6 present and field 5 absent, exactly
        // as python-omemo serializes it.
        var proto = Protobuf.field(1, varint: 42)                                  // pk_id
        proto += Protobuf.field(6, varint: 7)                                      // spk_id
        proto += Protobuf.field(2, bytes: SignalWire.serialize(publicKey: Data(repeating: 0xAB, count: 32))) // ek
        proto += Protobuf.field(3, bytes: SignalWire.serialize(publicKey: Data(repeating: 0xCD, count: 32))) // ik
        proto += Protobuf.field(4, bytes: Data(repeating: 0xEE, count: 10))        // message
        let blob = Data([SignalWire.version]) + proto

        let parsed = try PreKeySignalMessage.parse(blob)
        XCTAssertEqual(parsed.registrationId, 0)      // absent -> defaulted, not an error
        XCTAssertEqual(parsed.preKeyId, 42)
        XCTAssertEqual(parsed.signedPreKeyId, 7)
        XCTAssertEqual(parsed.baseKey, Data(repeating: 0xAB, count: 32))
        XCTAssertEqual(parsed.identityKey, Data(repeating: 0xCD, count: 32))
    }
}
