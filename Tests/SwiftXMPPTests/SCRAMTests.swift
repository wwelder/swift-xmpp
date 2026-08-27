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

/// The published test vectors. A SCRAM implementation that does not reproduce
/// these byte for byte is wrong in a way that no amount of "it logs in against
/// my server" will reveal — a server will happily accept a client that skips
/// the checks that protect the client.
final class SCRAMTests: XCTestCase {
    /// RFC 5802 §5.
    func testSHA1Vector() throws {
        var scram = SCRAM(
            variant: .sha1, username: "user", password: "pencil",
            nonce: "fyko+d2lbbFgONRv9qkxdawL"
        )

        XCTAssertEqual(scram.clientFirstMessage(), "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")

        let serverFirst = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        XCTAssertEqual(
            try scram.handle(challenge: serverFirst),
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        )

        XCTAssertNoThrow(try scram.handle(finalMessage: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="))
    }

    /// RFC 7677 §3.
    func testSHA256Vector() throws {
        var scram = SCRAM(
            variant: .sha256, username: "user", password: "pencil",
            nonce: "rOprNGfwEbeRWgbNEkqO"
        )

        XCTAssertEqual(scram.clientFirstMessage(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")

        let serverFirst =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
        XCTAssertEqual(
            try scram.handle(challenge: serverFirst),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                + "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        )

        XCTAssertNoThrow(
            try scram.handle(finalMessage: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
        )
    }

    /// The check that turns SCRAM from one-way into mutual authentication. A
    /// peer that cannot produce the right signature does not know the password
    /// and is therefore not the server.
    func testWrongServerSignatureIsRejected() throws {
        var scram = SCRAM(
            variant: .sha1, username: "user", password: "pencil",
            nonce: "fyko+d2lbbFgONRv9qkxdawL"
        )
        _ = scram.clientFirstMessage()
        _ = try scram.handle(
            challenge: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        )

        XCTAssertThrowsError(
            try scram.handle(finalMessage: "v=AAAApqV8S7suAoZWja4dJRkFsKQ=")
        ) { error in
            XCTAssertEqual(error as? SCRAM.Failure, .serverSignatureMismatch)
        }
    }

    /// A server that does not echo our nonce cannot be distinguished from a
    /// replay, so the exchange must not continue.
    func testUnechoedNonceIsRejected() throws {
        var scram = SCRAM(variant: .sha1, username: "user", password: "pencil", nonce: "ours")
        _ = scram.clientFirstMessage()
        XCTAssertThrowsError(
            try scram.handle(challenge: "r=theirs,s=QSXCR+Q6sek8bf92,i=4096")
        )
    }

    /// An absurd iteration count is a denial of service against our own CPU.
    func testOutOfRangeIterationCountIsRejected() throws {
        var scram = SCRAM(variant: .sha1, username: "user", password: "pencil", nonce: "n")
        _ = scram.clientFirstMessage()
        XCTAssertThrowsError(try scram.handle(challenge: "r=n1,s=QSXCR+Q6sek8bf92,i=100"))
        XCTAssertThrowsError(try scram.handle(challenge: "r=n1,s=QSXCR+Q6sek8bf92,i=99999999"))
    }

    /// `=` and `,` separate SCRAM attributes, so a username containing them
    /// must be escaped or it can forge attributes (RFC 5802 §5.1).
    func testUsernameEscaping() {
        XCTAssertEqual(SCRAM.saslPrep("a=b,c"), "a=3Db=2Cc")
    }
}

extension SCRAM.Failure: Equatable {
    public static func == (lhs: SCRAM.Failure, rhs: SCRAM.Failure) -> Bool {
        String(describing: lhs) == String(describing: rhs)
    }
}
