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

final class MechanismChoiceTests: XCTestCase {
    /// The consequence of getting this order wrong is the user's password sent
    /// to the server verbatim, on a server that would have accepted SCRAM.
    func testPasswordNeverFallsBackToPlainWhileScramIsOffered() {
        let mechanism = Mechanism.choose(
            for: .password("pencil"), from: ["PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256"]
        )
        XCTAssertEqual(mechanism, .scramSHA256)
    }

    func testStrongerScramWins() {
        XCTAssertEqual(
            Mechanism.choose(for: .password("p"), from: ["SCRAM-SHA-1", "SCRAM-SHA-256"]),
            .scramSHA256
        )
    }

    /// PLAIN is reachable, but only when there is nothing better.
    func testPlainIsUsedOnlyAsALastResort() {
        XCTAssertEqual(Mechanism.choose(for: .password("p"), from: ["PLAIN"]), .plain)
    }

    /// A token is not a password: it must not be offered to SCRAM, which would
    /// hash it as if it were one and fail in a confusing way.
    func testTokenOnlyUsesOAuthMechanisms() {
        XCTAssertNil(Mechanism.choose(for: .token("jwt"), from: ["SCRAM-SHA-256", "PLAIN"]))
        XCTAssertEqual(
            Mechanism.choose(for: .token("jwt"), from: ["X-OAUTH2", "SCRAM-SHA-256"]), .xOAuth2
        )
        XCTAssertEqual(
            Mechanism.choose(for: .token("jwt"), from: ["OAUTHBEARER", "X-OAUTH2"]), .oauthBearer
        )
    }

    func testNothingUsableIsNotAnAccident() {
        XCTAssertNil(Mechanism.choose(for: .password("p"), from: ["DIGEST-MD5", "EXTERNAL"]))
        XCTAssertNil(Mechanism.choose(for: .password("p"), from: []))
    }

    func testMechanismsKnowWhetherTheyExposeTheSecret() {
        XCTAssertFalse(Mechanism.scramSHA256.carriesSecretVerbatim)
        XCTAssertTrue(Mechanism.plain.carriesSecretVerbatim)
        XCTAssertTrue(Mechanism.oauthBearer.carriesSecretVerbatim)
    }
}

final class StreamParserTests: XCTestCase {
    private func parse(_ chunks: [String]) throws -> [Stanza] {
        var parser = StreamParser()
        var stanzas: [Stanza] = []
        for chunk in chunks {
            for event in try parser.feed(Data(chunk.utf8)) {
                if case let .element(element) = event { stanzas.append(element) }
            }
        }
        return stanzas
    }

    /// The property that matters: a stanza split across TCP reads — which is
    /// normal, not an edge case — must parse as one stanza.
    func testElementSplitAcrossReads() throws {
        let stanzas = try parse([
            "<stream:stream xmlns:stream='x'>",
            "<message to='a@b'><bo",
            "dy>hello</body><",
            "/message>",
        ])
        XCTAssertEqual(stanzas.count, 1)
        XCTAssertEqual(stanzas.first?.childText("body"), "hello")
    }

    func testAttributesWithBothQuoteStyles() throws {
        let stanzas = try parse(["<stream:stream/>", "<iq id=\"1\" type='get'/>"])
        XCTAssertEqual(stanzas.first?["id"], "1")
        XCTAssertEqual(stanzas.first?.type, "get")
    }

    /// A `>` inside an attribute value must not be mistaken for the tag end.
    func testAngleBracketInsideAttributeValue() throws {
        let stanzas = try parse(["<stream:stream/>", "<message body='a &gt; b'/>"])
        XCTAssertEqual(stanzas.first?["body"], "a > b")
    }

    func testNestedElementsAndEntities() throws {
        let stanzas = try parse([
            "<stream:stream/>",
            "<message><body>&lt;tag&gt; &amp; more</body><delay stamp='x'/></message>",
        ])
        XCTAssertEqual(stanzas.first?.childText("body"), "<tag> & more")
        XCTAssertEqual(stanzas.first?.child("delay")?["stamp"], "x")
    }

    /// RFC 6120 §11.1 forbids these outright, so they are errors and not
    /// something to skip past quietly.
    func testRestrictedXMLIsRejected() {
        XCTAssertThrowsError(try parse(["<stream:stream/>", "<!-- hi -->"]))
        XCTAssertThrowsError(try parse(["<stream:stream/>", "<!DOCTYPE foo>"]))
    }

    /// Whitespace between stanzas is the standard keepalive and must not
    /// become stray text on the next element.
    func testWhitespaceKeepaliveIsIgnored() throws {
        let stanzas = try parse(["<stream:stream/>", "\n \n", "<presence/>"])
        XCTAssertEqual(stanzas.count, 1)
        XCTAssertEqual(stanzas.first?.text, "")
    }
}

final class ModelTests: XCTestCase {
    func testMessageDirectionIsFromOurOwnJID() {
        let incoming = Stanza(
            "message", ["from": "them@srv/phone", "to": "us@srv/laptop"],
            children: [Stanza("body", text: "hi")]
        )
        let message = Message(from: incoming, ourBareJID: "us@srv")
        XCTAssertEqual(message?.isOutgoing, false)
        // The counterpart is the bare JID: a conversation is with a person, not
        // with whichever device they happen to be using.
        XCTAssertEqual(message?.counterpart, "them@srv")
    }

    func testCarbonOfOurOwnMessageIsOutgoing() {
        let echoed = Stanza(
            "message", ["from": "us@srv/laptop", "to": "them@srv"],
            children: [Stanza("body", text: "hi")]
        )
        let message = Message(from: echoed, ourBareJID: "us@srv")
        XCTAssertEqual(message?.isOutgoing, true)
        XCTAssertEqual(message?.counterpart, "them@srv")
    }

    /// Chat states, receipts and markers are messages with no body and are not
    /// something to show in a conversation.
    func testBodylessMessageIsNotAMessage() {
        let typing = Stanza(
            "message", ["from": "them@srv"],
            children: [Stanza("composing", ["xmlns": "http://jabber.org/protocol/chatstates"])]
        )
        XCTAssertNil(Message(from: typing, ourBareJID: "us@srv"))
    }

    func testPresenceUnavailableIsOffline() {
        let stanza = Stanza("presence", ["from": "them@srv/phone", "type": "unavailable"])
        XCTAssertEqual(ContactPresence(from: stanza).availability, .offline)
        XCTAssertEqual(ContactPresence(from: stanza).jid, "them@srv")
    }

    func testPresenceShowMapsToAvailability() {
        let stanza = Stanza(
            "presence", ["from": "them@srv/phone"],
            children: [Stanza("show", text: "dnd"), Stanza("status", text: "busy")]
        )
        let presence = ContactPresence(from: stanza)
        XCTAssertEqual(presence.availability, .doNotDisturb)
        XCTAssertEqual(presence.status, "busy")
    }

    func testContactDisplayNameFallsBackToLocalPart() {
        let withName = Contact(Stanza("item", ["jid": "a@b", "name": "Alice"]))
        XCTAssertEqual(withName?.displayName, "Alice")
        let withoutName = Contact(Stanza("item", ["jid": "alice@b"]))
        XCTAssertEqual(withoutName?.displayName, "alice")
    }

    func testPendingSubscriptionIsVisible() {
        let contact = Contact(
            Stanza("item", ["jid": "a@b", "subscription": "none", "ask": "subscribe"])
        )
        XCTAssertEqual(contact?.pendingOut, true)
        XCTAssertEqual(contact?.subscription, Contact.Subscription.none)
    }
}
