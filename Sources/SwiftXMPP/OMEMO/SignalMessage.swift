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

import CommonCrypto
import CryptoKit
import Foundation

/// The wire format the Signal protocol puts a ratchet message in, as OMEMO
/// (the widely deployed 0.3 revision) carries it. Every constant here is an
/// interoperability requirement: change one and existing clients cannot read
/// us, and the failure is a MAC mismatch that says nothing about why.
enum SignalWire {
    /// Version 3, in both nibbles: (current << 4) | maximum supported.
    static let version: UInt8 = 0x33
    static let macLength = 8

    /// Curve25519 public keys travel with a type byte in front — 0x05 for
    /// this curve — and the MAC and the signed-prekey signature both cover
    /// that 33-byte form, not the bare 32.
    static func serialize(publicKey: Data) -> Data {
        Data([0x05]) + publicKey
    }

    static func publicKey(from serialized: Data) -> Data? {
        guard serialized.count == 33, serialized.first == 0x05 else { return nil }
        return Data(serialized.dropFirst())
    }

    /// The raw 32-byte curve point, whether the input carries the 0x05 prefix
    /// or not. Peers are inconsistent about which form they publish; this makes
    /// our reading tolerant without our writing becoming ambiguous.
    static func normalize(_ key: Data) -> Data {
        if key.count == 33, key.first == 0x05 { return Data(key.dropFirst()) }
        return key
    }
}

/// A message inside an established session.
struct SignalMessage: Equatable {
    let ratchetKey: Data // 32 bytes, our current ratchet public key
    let counter: UInt32
    let previousCounter: UInt32
    let ciphertext: Data

    enum ParseError: Error {
        case tooShort, unsupportedVersion(UInt8), malformed, badMAC
    }

    /// Serialise and authenticate. The MAC covers both identity keys and the
    /// versioned body, so a message replayed into a different pair of
    /// identities fails to verify.
    func serialize(macKey: SymmetricKey, senderIdentity: Data, receiverIdentity: Data) -> Data {
        let body = Data([SignalWire.version]) + proto
        return body + Self.mac(over: body, key: macKey, sender: senderIdentity, receiver: receiverIdentity)
    }

    private var proto: Data {
        Protobuf.field(1, bytes: SignalWire.serialize(publicKey: ratchetKey))
            + Protobuf.field(2, varint: UInt64(counter))
            + Protobuf.field(3, varint: UInt64(previousCounter))
            + Protobuf.field(4, bytes: ciphertext)
    }

    /// Parse without verifying: the MAC key is only known once the ratchet
    /// has advanced to this message, which needs the header first. `verify`
    /// is the second half and is not optional.
    static func parse(_ data: Data) throws -> (message: SignalMessage, body: Data, mac: Data) {
        guard data.count > 1 + SignalWire.macLength else { throw ParseError.tooShort }
        let version = data[data.startIndex]
        guard version >> 4 == 3 else { throw ParseError.unsupportedVersion(version) }

        let body = Data(data.dropLast(SignalWire.macLength))
        let mac = Data(data.suffix(SignalWire.macLength))
        let fields = try Protobuf.decode(Data(body.dropFirst()))

        guard let serializedKey = fields.bytes(1),
              let ratchetKey = SignalWire.publicKey(from: serializedKey),
              let counter = fields.varint(2),
              let ciphertext = fields.bytes(4) else { throw ParseError.malformed }

        let message = SignalMessage(
            ratchetKey: ratchetKey,
            counter: UInt32(truncatingIfNeeded: counter),
            previousCounter: UInt32(truncatingIfNeeded: fields.varint(3) ?? 0),
            ciphertext: ciphertext
        )
        return (message, body, mac)
    }

    static func verify(body: Data, mac: Data, macKey: SymmetricKey, senderIdentity: Data, receiverIdentity: Data) -> Bool {
        let expected = Self.mac(over: body, key: macKey, sender: senderIdentity, receiver: receiverIdentity)
        // Constant-time: a byte-by-byte early exit leaks how much of the MAC
        // an attacker has right.
        return mac.count == expected.count
            && zip(mac, expected).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    private static func mac(over body: Data, key: SymmetricKey, sender: Data, receiver: Data) -> Data {
        var hmac = HMAC<SHA256>(key: key)
        hmac.update(data: SignalWire.serialize(publicKey: sender))
        hmac.update(data: SignalWire.serialize(publicKey: receiver))
        hmac.update(data: body)
        return Data(hmac.finalize().prefix(SignalWire.macLength))
    }
}

/// The first message of a session: a `SignalMessage` plus everything the
/// recipient needs to run X3DH on their side and arrive at the same keys.
struct PreKeySignalMessage: Equatable {
    let registrationId: UInt32
    let preKeyId: UInt32?
    let signedPreKeyId: UInt32
    let baseKey: Data // the initiator's ephemeral X3DH key, 32 bytes
    let identityKey: Data // the initiator's identity key, 32 bytes
    let message: Data // a serialised, authenticated SignalMessage

    func serialize() -> Data {
        var proto = Protobuf.field(5, varint: UInt64(registrationId))
        if let preKeyId { proto += Protobuf.field(1, varint: UInt64(preKeyId)) }
        proto += Protobuf.field(6, varint: UInt64(signedPreKeyId))
            + Protobuf.field(2, bytes: SignalWire.serialize(publicKey: baseKey))
            + Protobuf.field(3, bytes: SignalWire.serialize(publicKey: identityKey))
            + Protobuf.field(4, bytes: message)
        return Data([SignalWire.version]) + proto
    }

    static func parse(_ data: Data) throws -> PreKeySignalMessage {
        guard let version = data.first else { throw SignalMessage.ParseError.tooShort }
        guard version >> 4 == 3 else { throw SignalMessage.ParseError.unsupportedVersion(version) }
        let fields = try Protobuf.decode(Data(data.dropFirst()))
        // Field 5 (registrationId) is "unused" in the oldmemo key exchange and
        // real clients (python-omemo, Dino) omit it. We never read it on the
        // responder side, so a missing field 5 is not malformed — default it.
        guard let signedPreKeyId = fields.varint(6),
              let baseKey = fields.bytes(2).flatMap(SignalWire.publicKey(from:)),
              let identityKey = fields.bytes(3).flatMap(SignalWire.publicKey(from:)),
              let message = fields.bytes(4) else { throw SignalMessage.ParseError.malformed }
        return PreKeySignalMessage(
            registrationId: UInt32(truncatingIfNeeded: fields.varint(5) ?? 0),
            preKeyId: fields.varint(1).map { UInt32(truncatingIfNeeded: $0) },
            signedPreKeyId: UInt32(truncatingIfNeeded: signedPreKeyId),
            baseKey: baseKey,
            identityKey: identityKey,
            message: message
        )
    }
}

/// AES-256-CBC with PKCS#7 padding — what the Signal session cipher uses for
/// the ratchet-encrypted body. CryptoKit has no CBC, so this is CommonCrypto,
/// which is part of the platform rather than a dependency.
enum CBC {
    enum Failure: Error { case cryptor(CCCryptorStatus) }

    static func encrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        try run(CCOperation(kCCEncrypt), plaintext, key: key, iv: iv)
    }

    static func decrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        try run(CCOperation(kCCDecrypt), ciphertext, key: key, iv: iv)
    }

    private static func run(_ op: CCOperation, _ input: Data, key: Data, iv: Data) throws -> Data {
        let capacity = input.count + kCCBlockSizeAES128
        var out = Data(count: capacity)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            input.withUnsafeBytes { inPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                                keyPtr.baseAddress, key.count, ivPtr.baseAddress,
                                inPtr.baseAddress, input.count,
                                outPtr.baseAddress, capacity, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw Failure.cryptor(status) }
        return Data(out.prefix(moved))
    }
}
