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

/// What a server told us about itself.
///
/// A client should decide what it can offer from this, not from a hostname it
/// was built with. A server that advertises an extension supports it; one that
/// does not, does not — and that holds equally for the server the client was
/// written for and for one it has never seen.
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

    /// Whether the server advertises a given extension, by feature var or by
    /// the presence of a service. Callers use this to decide what to show.
    public func advertises(featurePrefix: String? = nil, servicePrefix: String? = nil) -> Bool {
        if let featurePrefix, features.contains(where: { $0.hasPrefix(featurePrefix) }) {
            return true
        }
        if let servicePrefix, services.contains(where: { $0.hasPrefix(servicePrefix) }) {
            return true
        }
        return false
    }
}
