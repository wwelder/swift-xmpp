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

/// How OMEMO keys travel over XMPP: PEP (personal pubsub), one node for the
/// list of a user's devices and one node per device for its prekey bundle.
///
/// These are the legacy `eu.siacs.conversations.axolotl` nodes, because that
/// is what Conversations, Dino and Monal publish and read. A client on the
/// modern `urn:xmpp:omemo:2` nodes would not find us and we would not find it;
/// interoperability is the entire reason to implement OMEMO rather than invent
/// encryption, so the node names are not a detail.
enum OMEMONamespace {
    static let devicelist = "eu.siacs.conversations.axolotl.devicelist"
    static let bundles = "eu.siacs.conversations.axolotl.bundles"
    static let encrypted = "eu.siacs.conversations.axolotl"

    static func bundleNode(_ deviceID: UInt32) -> String { "\(bundles):\(deviceID)" }
}

/// A device's public keys, as published and as fetched.
public struct OMEMOBundle {
    public let signedPreKeyID: UInt32
    public let signedPreKeyPublic: Data
    public let signedPreKeySignature: Data
    public let identityKey: Data
    /// (id, public) for each one-time prekey. The publisher advertises many;
    /// a peer takes one and the publisher republishes without it.
    public let preKeys: [(id: UInt32, publicKey: Data)]

    public init(signedPreKeyID: UInt32, signedPreKeyPublic: Data, signedPreKeySignature: Data,
                identityKey: Data, preKeys: [(id: UInt32, publicKey: Data)]) {
        self.signedPreKeyID = signedPreKeyID
        self.signedPreKeyPublic = signedPreKeyPublic
        self.signedPreKeySignature = signedPreKeySignature
        self.identityKey = identityKey
        self.preKeys = preKeys
    }

    /// The `<bundle>` element for the bundle PEP node.
    public func element() -> Stanza {
        Stanza("bundle", ["xmlns": OMEMONamespace.encrypted], children: [
            Stanza("signedPreKeyPublic",
                   ["signedPreKeyId": String(signedPreKeyID)],
                   text: signedPreKeyPublic.base64EncodedString()),
            Stanza("signedPreKeySignature", text: signedPreKeySignature.base64EncodedString()),
            Stanza("identityKey", text: identityKey.base64EncodedString()),
            Stanza("prekeys", children: preKeys.map {
                Stanza("preKeyPublic", ["preKeyId": String($0.id)],
                       text: $0.publicKey.base64EncodedString())
            }),
        ])
    }

    /// Parse a `<bundle>` fetched from a peer. Returns nil on anything
    /// malformed rather than guessing, because a wrong key here is a silent
    /// failure to encrypt to the right person.
    public static func parse(_ bundle: Stanza) -> OMEMOBundle? {
        guard let spk = bundle.child("signedPreKeyPublic"),
              let spkID = spk["signedPreKeyId"].flatMap({ UInt32($0) }),
              let spkPublic = Data(base64Encoded: spk.text),
              let sig = bundle.childText("signedPreKeySignature").flatMap({ Data(base64Encoded: $0) }),
              let ik = bundle.childText("identityKey").flatMap({ Data(base64Encoded: $0) })
        else { return nil }

        let preKeys = (bundle.child("prekeys")?.childrenNamed("preKeyPublic") ?? [])
            .compactMap { element -> (id: UInt32, publicKey: Data)? in
                guard let id = element["preKeyId"].flatMap({ UInt32($0) }),
                      let key = Data(base64Encoded: element.text) else { return nil }
                return (id, key)
            }

        return OMEMOBundle(
            signedPreKeyID: spkID, signedPreKeyPublic: spkPublic,
            signedPreKeySignature: sig, identityKey: ik, preKeys: preKeys
        )
    }
}

/// The stanzas that carry OMEMO over PEP. Pure construction and parsing, kept
/// apart from the session so the wire shape can be tested without a socket.
enum OMEMOPublishing {
    // MARK: devicelist

    static func publishDeviceList(_ ids: [UInt32]) -> Stanza {
        let list = Stanza("list", ["xmlns": OMEMONamespace.encrypted],
                          children: ids.map { Stanza("device", ["id": String($0)]) })
        return pubsubPublish(node: OMEMONamespace.devicelist, itemID: "current", payload: list)
    }

    static func parseDeviceList(_ pubsub: Stanza) -> [UInt32] {
        // pubsub > items > item > list > device. The `items` wrapper is easy to
        // skip and leaves an empty device list that silently encrypts to
        // nobody, so resolve it explicitly.
        let item = pubsub.child("items")?.child("item") ?? pubsub.child("item")
        return (item?.child("list")?.childrenNamed("device") ?? [])
            .compactMap { $0["id"].flatMap { UInt32($0) } }
    }

    // MARK: bundle

    static func publishBundle(_ bundle: OMEMOBundle, deviceID: UInt32) -> Stanza {
        pubsubPublish(
            node: OMEMONamespace.bundleNode(deviceID), itemID: "current", payload: bundle.element()
        )
    }

    static func fetchBundle(deviceID: UInt32) -> Stanza {
        pubsubItems(node: OMEMONamespace.bundleNode(deviceID))
    }

    static func fetchDeviceList() -> Stanza {
        pubsubItems(node: OMEMONamespace.devicelist)
    }

    static func parseBundle(_ pubsub: Stanza) -> OMEMOBundle? {
        let item = pubsub.child("items")?.child("item") ?? pubsub.child("item")
        return item?.child("bundle").flatMap(OMEMOBundle.parse)
    }

    // MARK: pubsub scaffolding

    private static func pubsubPublish(node: String, itemID: String, payload: Stanza) -> Stanza {
        Stanza("pubsub", ["xmlns": "http://jabber.org/protocol/pubsub"], children: [
            Stanza("publish", ["node": node], children: [
                Stanza("item", ["id": itemID], children: [payload]),
            ]),
            // pep#max: keep only the latest item, so a bundle republish replaces
            // rather than piles up.
            Stanza("publish-options", children: [
                Stanza("x", ["xmlns": "jabber:x:data", "type": "submit"], children: [
                    Stanza("field", ["var": "FORM_TYPE", "type": "hidden"], children: [
                        Stanza("value", text: "http://jabber.org/protocol/pubsub#publish-options"),
                    ]),
                    Stanza("field", ["var": "pubsub#persist_items"], children: [Stanza("value", text: "true")]),
                    Stanza("field", ["var": "pubsub#access_model"], children: [Stanza("value", text: "open")]),
                ]),
            ]),
        ])
    }

    private static func pubsubItems(node: String) -> Stanza {
        Stanza("pubsub", ["xmlns": "http://jabber.org/protocol/pubsub"], children: [
            Stanza("items", ["node": node, "max_items": "1"]),
        ])
    }
}
