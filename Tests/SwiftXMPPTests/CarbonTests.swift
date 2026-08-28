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

/// XEP-0280 §11: a carbon is trusted only because it comes from our own
/// account. Drop that check and anyone can hand the client a message that
/// displays as something we said on another device.
final class CarbonTests: XCTestCase {
    private func carbon(outerFrom: String, kind: String = "received") -> Stanza {
        Stanza("message", ["from": outerFrom, "to": "us@srv/phone"], children: [
            Stanza(kind, ["xmlns": "urn:xmpp:carbons:2"], children: [
                Stanza("forwarded", ["xmlns": "urn:xmpp:forward:0"], children: [
                    Stanza("message", ["from": "them@srv/x", "to": "us@srv/laptop", "type": "chat"],
                           children: [Stanza("body", text: "inner")]),
                ]),
            ]),
        ])
    }

    func testCarbonFromOurOwnAccountIsUnwrapped() {
        let inner = XMPPSession.unwrapCarbon(carbon(outerFrom: "us@srv"), ourBareJID: "us@srv")
        XCTAssertEqual(inner?.childText("body"), "inner")
    }

    func testSentCarbonIsUnwrappedToo() {
        let inner = XMPPSession.unwrapCarbon(carbon(outerFrom: "us@srv", kind: "sent"), ourBareJID: "us@srv")
        XCTAssertEqual(inner?.childText("body"), "inner")
    }

    /// The attack: a stranger wraps a message in carbon markup. It must be
    /// treated as not-a-carbon, not as a carbon from a stranger.
    func testCarbonFromAnyoneElseIsRejected() {
        XCTAssertNil(XMPPSession.unwrapCarbon(carbon(outerFrom: "attacker@evil"), ourBareJID: "us@srv"))
        XCTAssertNil(XMPPSession.unwrapCarbon(carbon(outerFrom: "them@srv"), ourBareJID: "us@srv"))
    }

    /// A full JID of our own account is still our own account.
    func testCarbonFromOurOwnResourceIsAccepted() {
        XCTAssertNotNil(XMPPSession.unwrapCarbon(carbon(outerFrom: "us@srv/laptop"), ourBareJID: "us@srv"))
    }

    func testOrdinaryMessageIsNotACarbon() {
        let plain = Stanza("message", ["from": "us@srv"], children: [Stanza("body", text: "hi")])
        XCTAssertNil(XMPPSession.unwrapCarbon(plain, ourBareJID: "us@srv"))
    }
}
