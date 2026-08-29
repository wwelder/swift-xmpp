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

/// One entry in the roster (RFC 6121 §2).
public struct Contact: Identifiable, Equatable, Sendable {
    /// The bare JID, which is also the identity: a roster has one entry per
    /// contact regardless of how many devices they connect from.
    public let jid: String
    public var name: String?
    public var groups: [String]

    /// The subscription state. This is the part of a roster that surprises
    /// people: seeing someone's presence and them seeing yours are separate
    /// permissions, and a contact can be in the roster with neither.
    public var subscription: Subscription
    /// We have asked them and they have not answered yet.
    public var pendingOut: Bool

    public var id: String { jid }

    /// The name to show. Falls back to the JID's local part rather than the
    /// full JID, because a list of full JIDs is unreadable.
    public var displayName: String {
        if let name, !name.isEmpty { return name }
        return jid.split(separator: "@").first.map(String.init) ?? jid
    }

    public enum Subscription: String, Sendable {
        /// Neither of us sees the other.
        case none
        /// They see us; we do not see them.
        case from
        /// We see them; they do not see us.
        case to
        /// Both.
        case both
        /// The server is telling us to drop this entry.
        case remove
    }

    init?(_ item: Stanza) {
        guard let jid = item["jid"] else { return nil }
        self.jid = jid
        name = item["name"]
        groups = item.childrenNamed("group").map(\.text)
        subscription = Subscription(rawValue: item["subscription"] ?? "none") ?? .none
        pendingOut = item["ask"] == "subscribe"
    }

    /// Build a contact directly — for SwiftUI previews, tests, and demo data
    /// that does not come from a roster stanza.
    public init(jid: String, name: String? = nil, groups: [String] = [],
                subscription: Subscription = .both, pendingOut: Bool = false) {
        self.jid = jid
        self.name = name
        self.groups = groups
        self.subscription = subscription
        self.pendingOut = pendingOut
    }
}

/// Presence of a contact, reduced to what a client actually shows.
public struct ContactPresence: Equatable, Sendable {
    public enum Availability: String, Sendable {
        case offline, online, away, extendedAway = "xa", doNotDisturb = "dnd", chat
    }

    public let jid: String
    public let availability: Availability
    /// The free-text status line, if the contact set one.
    public let status: String?

    init(from stanza: Stanza) {
        jid = (stanza.from ?? "").split(separator: "/").first.map(String.init) ?? (stanza.from ?? "")
        status = stanza.childText("status")
        if stanza.type == "unavailable" {
            availability = .offline
        } else {
            availability = Availability(rawValue: stanza.childText("show") ?? "") ?? .online
        }
    }
}

/// A received or sent message.
public struct Message: Identifiable, Equatable, Sendable {
    public let id: String
    /// Bare JID of the other party, whichever direction this went.
    public let counterpart: String
    public let body: String
    public let isOutgoing: Bool
    public let timestamp: Date

    public init(id: String, counterpart: String, body: String, isOutgoing: Bool, timestamp: Date) {
        self.id = id; self.counterpart = counterpart; self.body = body
        self.isOutgoing = isOutgoing; self.timestamp = timestamp
    }

    init?(from stanza: Stanza, ourBareJID: String) {
        // A message with no body is a real and common thing — chat states,
        // receipts, markers — and is not a message to show.
        guard let body = stanza.childText("body"), !body.isEmpty else { return nil }
        let from = stanza.from ?? ""
        let bareFrom = from.split(separator: "/").first.map(String.init) ?? from
        let to = stanza.to ?? ""
        let bareTo = to.split(separator: "/").first.map(String.init) ?? to

        isOutgoing = bareFrom == ourBareJID
        counterpart = isOutgoing ? bareTo : bareFrom
        self.body = body
        id = stanza.id ?? UUID().uuidString
        // Delayed delivery (XEP-0203) carries the original time; without it the
        // message is arriving now.
        if let stamp = stanza.child("delay")?["stamp"] {
            timestamp = ISO8601DateFormatter().date(from: stamp) ?? Date()
        } else {
            timestamp = Date()
        }
    }
}
