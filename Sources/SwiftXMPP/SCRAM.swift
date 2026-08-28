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

import CryptoKit
import Foundation

/// SCRAM, from RFC 5802 (and RFC 7677 for the SHA-256 family).
///
/// Implemented from the RFC rather than adapted from any existing library. The
/// point of SCRAM over PLAIN is that the password never crosses the wire and
/// the client also authenticates the *server*: a server that cannot produce the
/// right signature is rejected in `handle(finalMessage:)`. Skipping that last
/// check is the classic SCRAM implementation bug — it turns mutual
/// authentication back into one-way.
public struct SCRAM {
    public enum Variant: String {
        case sha1 = "SCRAM-SHA-1"
        case sha256 = "SCRAM-SHA-256"

        public var digestLength: Int {
            switch self {
            case .sha1: Insecure.SHA1.byteCount
            case .sha256: SHA256.byteCount
            }
        }
    }

    enum Failure: Error, LocalizedError {
        case malformedChallenge(String)
        case unsupportedIteration(Int)
        case serverSignatureMismatch

        public var errorDescription: String? {
            switch self {
            case let .malformedChallenge(detail):
                "The server's SCRAM challenge was malformed: \(detail)."
            case let .unsupportedIteration(count):
                "The server asked for \(count) PBKDF2 iterations, which is out of range."
            case .serverSignatureMismatch:
                // Worth its own message: this means the peer could not prove it
                // knows the password, i.e. it is not the server it claims to be.
                "The server failed to prove its identity."
            }
        }
    }

    public let variant: Variant
    private let username: String
    private let password: String
    private let clientNonce: String
    private var clientFirstBare = ""
    private var expectedServerSignature = Data()

    public init(variant: Variant, username: String, password: String, nonce: String? = nil) {
        self.variant = variant
        self.username = username
        self.password = password
        // 24 bytes of randomness; the RFC only requires that it not repeat.
        self.clientNonce = nonce ?? Data((0..<24).map { _ in UInt8.random(in: 0...255) })
            .base64EncodedString()
    }

    /// The `client-first-message`. `n,,` is the GS2 header for "no channel
    /// binding, no authzid".
    public mutating func clientFirstMessage() -> String {
        clientFirstBare = "n=\(Self.saslPrep(username)),r=\(clientNonce)"
        return "n,," + clientFirstBare
    }

    /// Consumes `server-first-message` and produces `client-final-message`.
    public mutating func handle(challenge: String) throws -> String {
        let parts = Self.attributes(of: challenge)
        guard let combinedNonce = parts["r"], combinedNonce.hasPrefix(clientNonce) else {
            // A server that does not echo our nonce cannot be replayed against.
            throw Failure.malformedChallenge("the nonce was not echoed back")
        }
        guard let saltBase64 = parts["s"], let salt = Data(base64Encoded: saltBase64) else {
            throw Failure.malformedChallenge("no usable salt")
        }
        guard let iterationText = parts["i"], let iterations = Int(iterationText) else {
            throw Failure.malformedChallenge("no iteration count")
        }
        // The RFC floor is 4096. The ceiling is ours: an absurd count from a
        // hostile server is a denial of service against our own CPU.
        guard iterations >= 4096, iterations <= 500_000 else {
            throw Failure.unsupportedIteration(iterations)
        }

        let clientFinalBare = "c=biws,r=\(combinedNonce)"
        let authMessage = "\(clientFirstBare),\(challenge),\(clientFinalBare)"

        let saltedPassword = pbkdf2(
            password: Data(Self.saslPrep(password).utf8), salt: salt, iterations: iterations
        )
        let clientKey = hmac(key: saltedPassword, data: Data("Client Key".utf8))
        let storedKey = hash(clientKey)
        let clientSignature = hmac(key: storedKey, data: Data(authMessage.utf8))
        let clientProof = Data(zip(clientKey, clientSignature).map { $0 ^ $1 })

        let serverKey = hmac(key: saltedPassword, data: Data("Server Key".utf8))
        expectedServerSignature = hmac(key: serverKey, data: Data(authMessage.utf8))

        return "\(clientFinalBare),p=\(clientProof.base64EncodedString())"
    }

    /// Verifies `server-final-message`. Not optional — see the type comment.
    public func handle(finalMessage: String) throws {
        let parts = Self.attributes(of: finalMessage)
        if let error = parts["e"] {
            throw Failure.malformedChallenge(error)
        }
        guard let signatureBase64 = parts["v"],
              let signature = Data(base64Encoded: signatureBase64) else {
            throw Failure.malformedChallenge("no server signature")
        }
        // Constant-time: a timing oracle here leaks the expected signature.
        guard signature.count == expectedServerSignature.count,
              zip(signature, expectedServerSignature).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0
        else {
            throw Failure.serverSignatureMismatch
        }
    }

    // MARK: primitives

    private func hash(_ data: Data) -> Data {
        switch variant {
        case .sha1: Data(Insecure.SHA1.hash(data: data))
        case .sha256: Data(SHA256.hash(data: data))
        }
    }

    private func hmac(key: Data, data: Data) -> Data {
        let key = SymmetricKey(data: key)
        switch variant {
        case .sha1: return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        case .sha256: return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        }
    }

    /// PBKDF2-HMAC, RFC 8018 §5.2. Only one block is ever needed: dkLen equals
    /// the digest length for every SCRAM variant.
    private func pbkdf2(password: Data, salt: Data, iterations: Int) -> Data {
        var previous = hmac(key: password, data: salt + Data([0, 0, 0, 1]))
        var result = previous
        for _ in 1..<iterations {
            previous = hmac(key: password, data: previous)
            result = Data(zip(result, previous).map { $0 ^ $1 })
        }
        return result
    }

    /// `=` and `,` are the attribute separators, so they are escaped in the
    /// username (RFC 5802 §5.1). Full SASLprep normalisation is deliberately
    /// not attempted: getting it half-right is worse than being explicit that
    /// non-ASCII usernames need the real profile.
    public static func saslPrep(_ value: String) -> String {
        value
            .replacingOccurrences(of: "=", with: "=3D")
            .replacingOccurrences(of: ",", with: "=2C")
    }

    public static func attributes(of message: String) -> [String: String] {
        var out: [String: String] = [:]
        for field in message.split(separator: ",") {
            guard let split = field.firstIndex(of: "=") else { continue }
            let key = String(field[field.startIndex..<split])
            let value = String(field[field.index(after: split)...])
            if out[key] == nil { out[key] = value }
        }
        return out
    }
}
