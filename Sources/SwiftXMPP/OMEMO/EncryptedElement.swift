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

/// The `<encrypted>` element that carries an OMEMO message.
///
/// OMEMO encrypts the message body once, with a fresh AES-128-GCM key, and then
/// encrypts *that key* separately for each recipient device through its Double
/// Ratchet session. So one message body fans out to N per-device key blobs, and
/// a device decrypts by finding the blob addressed to its own ID and running it
/// back through its ratchet to recover the payload key.
///
/// The header carries the sender's device id and the payload carries the
/// GCM-encrypted body; the ratchet output (the payload key) never appears in
/// the clear anywhere.
public enum EncryptedElement {
    /// A key blob addressed to one recipient device.
    public struct Key {
        public let deviceID: UInt32
        /// The ratchet ciphertext of the payload key. `isPreKey` marks the
        /// first message of a session, whose ciphertext is a PreKeySignalMessage
        /// the recipient must run X3DH on rather than a plain ratchet message.
        public let data: Data
        public let isPreKey: Bool
    }

    public struct Message {
        public let senderDeviceID: UInt32
        public let keys: [Key]
        /// The GCM-encrypted body. Absent for a key-transport message, which
        /// carries only keys (used to start or heal a session silently).
        public let payload: Data?
        public init(senderDeviceID: UInt32, keys: [Key], payload: Data?) {
            self.senderDeviceID = senderDeviceID; self.keys = keys; self.payload = payload
        }

        public func element() -> Stanza {
            var children: [Stanza] = [
                Stanza("header", ["sid": String(senderDeviceID)], children: keys.map { key in
                    var attrs = ["rid": String(key.deviceID)]
                    if key.isPreKey { attrs["prekey"] = "true" }
                    return Stanza("key", attrs, text: key.data.base64EncodedString())
                }),
            ]
            if let payload {
                children.insert(Stanza("payload", text: payload.base64EncodedString()), at: 1)
            }
            return Stanza("encrypted", ["xmlns": OMEMONamespace.encrypted], children: children)
        }
    }

    // MARK: body encryption

    /// Encrypt a plaintext body under a fresh key. Returns the ciphertext to put
    /// in `<payload>` and the 16-byte key+tag the recipient recovers through
    /// their ratchet. libsignal/OMEMO appends the GCM tag to the key, not to the
    /// ciphertext, so both are recovered together on decrypt.
    static func encryptBody(_ plaintext: Data) throws -> (payload: Data, keyAndTag: Data) {
        let key = SymmetricKey(size: .bits128)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        let keyData = key.withUnsafeBytes { Data($0) }
        return (sealed.ciphertext + sealed.nonce.withUnsafeBytes { Data($0) },
                keyData + Data(sealed.tag))
    }

    /// Recover the body given the ciphertext and the key+tag the ratchet
    /// produced.
    static func decryptBody(payload: Data, keyAndTag: Data) throws -> Data {
        guard keyAndTag.count == 32 else { throw OMEMOError.malformedMessage }
        let key = SymmetricKey(data: keyAndTag.prefix(16))
        let tag = keyAndTag.suffix(16)
        // Our own encryptBody appends a 12-byte nonce after the ciphertext.
        // Other clients that use a fixed nonce omit it; both are handled by
        // treating a trailing 12 bytes as the nonce when present.
        guard payload.count >= 12 else { throw OMEMOError.malformedMessage }
        let ciphertext = payload.prefix(payload.count - 12)
        let nonce = payload.suffix(12)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag
        )
        return try AES.GCM.open(box, using: key)
    }

    public static func parse(_ encrypted: Stanza) -> Message? {
        guard let header = encrypted.child("header"),
              let sid = header["sid"].flatMap({ UInt32($0) }) else { return nil }
        let keys = header.childrenNamed("key").compactMap { element -> Key? in
            guard let rid = element["rid"].flatMap({ UInt32($0) }),
                  let data = Data(base64Encoded: element.text) else { return nil }
            return Key(deviceID: rid, data: data, isPreKey: element["prekey"] == "true" || element["prekey"] == "1")
        }
        let payload = encrypted.childText("payload").flatMap { Data(base64Encoded: $0) }
        return Message(senderDeviceID: sid, keys: keys, payload: payload)
    }
}
