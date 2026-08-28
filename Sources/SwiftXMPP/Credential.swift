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

/// How the client proves who it is.
///
/// Deliberately a closed set rather than a protocol: SASL mechanisms are not
/// pluggable in practice — the server offers a list and the client either
/// speaks one of them or does not. What *is* pluggable is where the credential
/// comes from, and that is the caller's business, not this library's.
///
/// A token here is any bearer credential the server will accept over
/// `OAUTHBEARER` or `X-OAUTH2`: an OAuth access token, or a JWT minted by
/// whatever sits in front of the server. The library does not care which, and
/// deliberately does not know how one is obtained — that is the part that
/// differs per deployment, and baking it in is how a client stops being
/// generic.
public enum Credential: Sendable {
    /// SCRAM. The password never crosses the wire.
    case password(String)

    /// A bearer token, presented through whichever OAuth-family mechanism the
    /// server offers. Unlike a password this *is* sent, so the library refuses
    /// to send one over an unencrypted stream.
    case token(String)

    var isBearerToken: Bool {
        if case .token = self { return true }
        return false
    }
}

/// A SASL mechanism this library can perform, strongest first within its family.
enum Mechanism: String, CaseIterable {
    case scramSHA256 = "SCRAM-SHA-256"
    case scramSHA1 = "SCRAM-SHA-1"
    case oauthBearer = "OAUTHBEARER"
    case xOAuth2 = "X-OAUTH2"
    case plain = "PLAIN"

    var scramVariant: SCRAM.Variant? {
        switch self {
        case .scramSHA256: .sha256
        case .scramSHA1: .sha1
        default: nil
        }
    }

    var carriesSecretVerbatim: Bool {
        switch self {
        case .scramSHA256, .scramSHA1: false
        case .oauthBearer, .xOAuth2, .plain: true
        }
    }

    /// Pick what to use, given the credential we hold and what the server said
    /// it accepts. Order is by strength: a password never falls back to PLAIN
    /// while any SCRAM variant is on the table, because PLAIN hands the
    /// password to the server and SCRAM does not.
    static func choose(for credential: Credential, from offered: [String]) -> Mechanism? {
        let usable = allCases.filter { offered.contains($0.rawValue) }
        switch credential {
        case .password:
            return usable.first { $0.scramVariant != nil } ?? usable.first { $0 == .plain }
        case .token:
            return usable.first { $0 == .oauthBearer } ?? usable.first { $0 == .xOAuth2 }
        }
    }
}
