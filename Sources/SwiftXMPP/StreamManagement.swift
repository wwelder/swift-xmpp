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

/// XEP-0198 Stream Management: the bookkeeping, with no network in it.
///
/// This is what makes a mobile client survive a tunnel, a wifi-to-cellular
/// handover, or a backgrounded app. Without it every network blip is a fresh
/// login and every stanza in flight is simply gone.
///
/// It is also easy to get subtly wrong in a way that only shows up as users
/// reporting lost or duplicated messages weeks later, so the counting lives
/// here, alone, where it can be tested without a socket.
///
/// Two rules do most of the work:
///
/// - `h` counts **stanzas** — message, presence, iq — and nothing else. The
///   `<r/>` and `<a/>` elements of this very protocol are not counted, and
///   counting them desynchronises both sides permanently.
/// - Counters are mod 2^32 (§4). A client that stores them in a signed Int and
///   compares with `>` breaks after four billion stanzas, which sounds like
///   never until a long-lived server connection reaches it.
struct StreamManagement {
    static let namespace = "urn:xmpp:sm:3"

    /// Stanzas we sent that the server has not acknowledged. On resume these
    /// are retransmitted; without the queue "the connection came back" and "the
    /// message arrived" are different things and the user is not told which.
    private(set) var unacknowledged: [(sequence: UInt32, stanza: String)] = []

    /// How many stanzas we have received and handled.
    private(set) var received: UInt32 = 0
    /// How many stanzas we have sent.
    private(set) var sent: UInt32 = 0

    /// The id the server gave us, and the proof we may try to resume.
    private(set) var resumeToken: String?
    private(set) var isEnabled = false

    /// Only these are counted. Everything else on the stream — stream
    /// management's own elements, stream features, SASL — is not a stanza.
    static func isCountable(_ element: Stanza) -> Bool {
        ["message", "presence", "iq"].contains(element.name)
    }

    // MARK: negotiation

    var enableRequest: String {
        // `resume='true'` asks the server to hold the session open briefly after
        // the connection drops, which is the entire point on mobile.
        "<enable xmlns='\(Self.namespace)' resume='true'/>"
    }

    mutating func handleEnabled(_ element: Stanza) {
        isEnabled = true
        received = 0
        sent = 0
        unacknowledged = []
        // A server may support management without supporting resumption.
        resumeToken = element["resume"] == "true" || element["resume"] == "1"
            ? element["id"]
            : nil
    }

    func resumeRequest() -> String? {
        guard let resumeToken else { return nil }
        return "<resume xmlns='\(Self.namespace)' previd='\(resumeToken)' h='\(received)'/>"
    }

    /// The server accepted the resume and told us what it received. Returns the
    /// stanzas to retransmit — those it never got.
    mutating func handleResumed(_ element: Stanza) -> [String] {
        isEnabled = true
        let acknowledgedThrough = UInt32(element["h"] ?? "") ?? 0
        return acknowledge(through: acknowledgedThrough)
    }

    mutating func handleFailed() {
        isEnabled = false
        resumeToken = nil
        unacknowledged = []
        received = 0
        sent = 0
    }

    // MARK: counting

    /// Call for every stanza received. Elements that are not stanzas must not
    /// reach this.
    mutating func countReceived() {
        received &+= 1
    }

    /// Call for every stanza sent, keeping it until the server acknowledges it.
    mutating func countSent(_ serialised: String) {
        sent &+= 1
        unacknowledged.append((sequence: sent, stanza: serialised))
    }

    var ackResponse: String {
        "<a xmlns='\(Self.namespace)' h='\(received)'/>"
    }

    var ackRequest: String {
        "<r xmlns='\(Self.namespace)'/>"
    }

    /// The server says it handled everything up to `h`. Drop those from the
    /// queue and report what is still outstanding.
    @discardableResult
    mutating func acknowledge(through h: UInt32) -> [String] {
        unacknowledged.removeAll { Self.isAtOrBefore($0.sequence, h) }
        return unacknowledged.map(\.stanza)
    }

    /// Is `sequence` at or before `h`, in a counter that wraps at 2^32?
    ///
    /// Plain `<=` is wrong here and the wrongness is invisible until a counter
    /// wraps, at which point every outstanding stanza is either dropped
    /// unacknowledged or retransmitted forever. Wrapping subtraction gives the
    /// distance from `sequence` to `h`; a distance in the near half means `h`
    /// is ahead, and in the far half means it is behind.
    static func isAtOrBefore(_ sequence: UInt32, _ h: UInt32) -> Bool {
        (h &- sequence) < UInt32.max / 2
    }

    /// Everything still in flight, for retransmission after a resume.
    var outstanding: [String] { unacknowledged.map(\.stanza) }
}
