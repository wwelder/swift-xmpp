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

/// Stream management decides whether a message that was in flight when the
/// network dropped arrives or vanishes. Every failure here is a message the
/// user believes they sent, or one they receive twice, and neither shows up
/// until it happens to a real person on a real train.
final class StreamManagementTests: XCTestCase {
    private func enabled(resume: Bool = true) -> StreamManagement {
        var sm = StreamManagement()
        sm.handleEnabled(
            Stanza("enabled", ["xmlns": StreamManagement.namespace,
                               "id": "token-1", "resume": resume ? "true" : "false"])
        )
        return sm
    }

    // MARK: what counts

    /// The rule that desynchronises both sides permanently when broken: stream
    /// management's own elements are not stanzas.
    func testOnlyStanzasAreCountable() {
        XCTAssertTrue(StreamManagement.isCountable(Stanza("message")))
        XCTAssertTrue(StreamManagement.isCountable(Stanza("presence")))
        XCTAssertTrue(StreamManagement.isCountable(Stanza("iq")))

        XCTAssertFalse(StreamManagement.isCountable(Stanza("r")))
        XCTAssertFalse(StreamManagement.isCountable(Stanza("a")))
        XCTAssertFalse(StreamManagement.isCountable(Stanza("enabled")))
        XCTAssertFalse(StreamManagement.isCountable(Stanza("stream:features")))
    }

    func testReceivedCounterAndAck() {
        var sm = enabled()
        XCTAssertEqual(sm.ackResponse, "<a xmlns='urn:xmpp:sm:3' h='0'/>")
        sm.countReceived()
        sm.countReceived()
        XCTAssertEqual(sm.ackResponse, "<a xmlns='urn:xmpp:sm:3' h='2'/>")
    }

    // MARK: the queue

    func testUnacknowledgedStanzasAreHeld() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        sm.countSent("<message id='2'/>")
        XCTAssertEqual(sm.outstanding.count, 2)
    }

    func testAcknowledgementDropsOnlyWhatTheServerGot() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        sm.countSent("<message id='2'/>")
        sm.countSent("<message id='3'/>")

        let stillOutstanding = sm.acknowledge(through: 2)
        XCTAssertEqual(stillOutstanding, ["<message id='3'/>"])
    }

    func testAcknowledgingNothingKeepsEverything() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        XCTAssertEqual(sm.acknowledge(through: 0).count, 1)
    }

    // MARK: resumption

    func testResumeRequestCarriesTokenAndOurCount() {
        var sm = enabled()
        sm.countReceived()
        sm.countReceived()
        sm.countReceived()
        XCTAssertEqual(
            sm.resumeRequest(),
            "<resume xmlns='urn:xmpp:sm:3' previd='token-1' h='3'/>"
        )
    }

    /// A server may manage the stream without offering resumption, and then
    /// there is nothing to resume with.
    func testNoResumeRequestWithoutAToken() {
        let sm = enabled(resume: false)
        XCTAssertNil(sm.resumeRequest())
    }

    /// The point of the whole feature: after a drop, the stanzas the server
    /// never saw are handed back to be sent again.
    func testResumeReturnsExactlyTheStanzasTheServerMissed() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        sm.countSent("<message id='2'/>")
        sm.countSent("<message id='3'/>")

        let toRetransmit = sm.handleResumed(
            Stanza("resumed", ["xmlns": StreamManagement.namespace, "h": "1"])
        )
        XCTAssertEqual(toRetransmit, ["<message id='2'/>", "<message id='3'/>"])
    }

    /// A refused resume is a new session. Replaying a queue into it would
    /// deliver stanzas the server already handled in the old one.
    func testFailedResumeDiscardsEverything() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        sm.countReceived()
        sm.handleFailed()

        XCTAssertTrue(sm.outstanding.isEmpty)
        XCTAssertNil(sm.resumeRequest())
        XCTAssertFalse(sm.isEnabled)
        XCTAssertEqual(sm.ackResponse, "<a xmlns='urn:xmpp:sm:3' h='0'/>")
    }

    // MARK: the counter wrap

    /// Counters are mod 2^32 (§4). `<=` looks right and is wrong, and stays
    /// invisible until a long-lived connection reaches four billion stanzas.
    func testComparisonSurvivesTheWrap() {
        XCTAssertTrue(StreamManagement.isAtOrBefore(5, 5))
        XCTAssertTrue(StreamManagement.isAtOrBefore(4, 5))
        XCTAssertFalse(StreamManagement.isAtOrBefore(6, 5))

        // h has wrapped past sequence: sequence is still acknowledged.
        XCTAssertTrue(StreamManagement.isAtOrBefore(UInt32.max - 1, 2))
        XCTAssertTrue(StreamManagement.isAtOrBefore(UInt32.max, 0))
        // sequence is genuinely ahead of h, wrap or no wrap.
        XCTAssertFalse(StreamManagement.isAtOrBefore(3, UInt32.max - 1))
    }

    func testSentCounterWrapsRatherThanTrapping() {
        var sm = enabled()
        for _ in 0..<3 { sm.countSent("<message/>") }
        XCTAssertEqual(sm.sent, 3)
        // The counters are UInt32 and use wrapping arithmetic, so reaching the
        // top is an ordinary event rather than a crash.
        XCTAssertNoThrow(sm.acknowledge(through: UInt32.max))
    }

    /// Enabling starts a fresh session; anything held from a previous one
    /// belongs to a stream the server has forgotten.
    func testEnablingResetsState() {
        var sm = enabled()
        sm.countSent("<message id='1'/>")
        sm.countReceived()

        sm.handleEnabled(
            Stanza("enabled", ["xmlns": StreamManagement.namespace, "id": "token-2", "resume": "true"])
        )
        XCTAssertTrue(sm.outstanding.isEmpty)
        XCTAssertEqual(sm.received, 0)
        XCTAssertEqual(sm.sent, 0)
        XCTAssertEqual(sm.resumeRequest(), "<resume xmlns='urn:xmpp:sm:3' previd='token-2' h='0'/>")
    }
}
