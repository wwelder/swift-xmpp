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

/// What a server told us about itself, and what the app should therefore show.
///
/// This is the whole design in one file. The app never asks "is this Channel?"
/// by looking at a hostname — it asks the server what it supports and believes
/// the answer. A Channel server is just a server that happens to advertise
/// Channel services; any other server gets the plain client, and neither case
/// is special-cased anywhere else in the app.
public struct ServerCapabilities: Equatable {
    /// SASL mechanisms from the stream features, in the order the server listed them.
    let saslMechanisms: [String]
    /// Service JIDs from disco#items on the server domain.
    let services: [String]
    /// Feature vars from disco#info on the server domain.
    let features: [String]

    static let unknown = ServerCapabilities(saslMechanisms: [], services: [], features: [])
}

/// How the user proves who they are. Chosen from what the server offers, never
/// from configuration we shipped.
public enum AuthMethod: Equatable {
    /// The server does password authentication. `mechanism` is the strongest
    /// one it offered that we can actually perform.
    case password(mechanism: String)
    /// The server wants an OAuth access token. The client obtains one and
    /// presents it as the mechanism's credential.
    case oauth(mechanism: String)
    /// Nothing we can do — surfaced to the user rather than retried forever.
    case unsupported(offered: [String])
}

extension ServerCapabilities {
    /// SCRAM in descending strength, then PLAIN. PLAIN is last because it hands
    /// the password to the server verbatim; every SCRAM variant does not.
    private static let scramPreference = [
        "SCRAM-SHA-512-PLUS", "SCRAM-SHA-512",
        "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256",
        "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1",
    ]

    private static let oauthMechanisms = ["OAUTHBEARER", "X-OAUTH2"]

    /// The entire login decision. Note there is no hostname in it.
    var authMethod: AuthMethod {
        if let scram = Self.scramPreference.first(where: { saslMechanisms.contains($0) }) {
            return .password(mechanism: scram)
        }
        if let oauth = Self.oauthMechanisms.first(where: { saslMechanisms.contains($0) }) {
            return .oauth(mechanism: oauth)
        }
        if saslMechanisms.contains("PLAIN") {
            return .password(mechanism: "PLAIN")
        }
        return .unsupported(offered: saslMechanisms)
    }

    /// Whether to reveal the Channel surfaces. Presence of the service in
    /// disco is the signal; when the server grows real `urn:channel:*` feature
    /// vars this reads them instead, and nothing else in the app changes.
    var hasChannelExtensions: Bool {
        features.contains { $0.hasPrefix("urn:channel:") }
            || services.contains { $0.hasPrefix("channel.") }
    }
}

/// The tabs a session shows. Derived, never stored — so a server that gains or
/// loses a capability is reflected on the next connect without migration.
public enum Surface: String, CaseIterable, Identifiable {
    case chats, contacts, feed, create, images

    public var id: String { rawValue }

    var title: String {
        switch self {
        case .chats: "Chats"
        case .contacts: "Contacts"
        case .feed: "Feed"
        case .create: "Create"
        case .images: "Images"
        }
    }

    var systemImage: String {
        switch self {
        case .chats: "bubble.left.and.bubble.right"
        case .contacts: "person.2"
        case .feed: "sparkles.rectangle.stack"
        case .create: "plus.circle"
        case .images: "photo.on.rectangle"
        }
    }

    /// Every server gets these. They are the client.
    static let baseline: [Surface] = [.chats, .contacts]
    /// These arrive with a server that advertises them, and their code is
    /// downloaded on demand rather than shipped to everyone.
    static let channel: [Surface] = [.feed, .create, .images]

    static func available(for capabilities: ServerCapabilities) -> [Surface] {
        capabilities.hasChannelExtensions ? baseline + channel : baseline
    }
}
