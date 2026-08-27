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

/// Negotiates and holds one XMPP session, per RFC 6120 §4–§7.
///
/// The negotiation is a fixed sequence — open a stream, read features, secure
/// it, authenticate, restart, bind a resource — where each step's result
/// decides the next. Written as a linear async function for that reason: the
/// order is the specification's, and a linear read of this file is a linear
/// read of the RFC.
public actor XMPPSession {
    struct Namespace {
        static let stream = "http://etherx.jabber.org/streams"
        static let tls = "urn:ietf:params:xml:ns:xmpp-tls"
        static let sasl = "urn:ietf:params:xml:ns:xmpp-sasl"
        static let bind = "urn:ietf:params:xml:ns:xmpp-bind"
        static let client = "jabber:client"
        static let discoInfo = "http://jabber.org/protocol/disco#info"
        static let discoItems = "http://jabber.org/protocol/disco#items"
    }

    enum Failure: Error, LocalizedError {
        case noSharedMechanism(offered: [String])
        case authenticationRejected(String)
        case insecureServer
        case unexpected(String)

        var errorDescription: String? {
            switch self {
            case let .noSharedMechanism(offered):
                offered.isEmpty
                    ? "The server offered no way to sign in."
                    : "This app cannot use any of the sign-in methods the server offers (\(offered.joined(separator: ",")))."
            case let .authenticationRejected(condition):
                condition == "not-authorized"
                    ? "Incorrect username or password."
                    : "The server rejected the sign-in (\(condition))."
            case .insecureServer:
                "The server does not support encryption, so the connection was refused."
            case let .unexpected(detail):
                "Unexpected response from the server: \(detail)."
            }
        }
    }

    private let transport = StreamTransport()
    private var parser = StreamParser()

    private var features: Stanza?
    private var isSecure = false

    /// Elements the negotiation is waiting for, and IQ replies by id.
    private var elementWaiters: [(Stanza) -> Bool] = []
    private var elementContinuations: [CheckedContinuation<Stanza, Error>] = []
    private var iqContinuations: [String: CheckedContinuation<Stanza, Error>] = [:]

    private(set) var boundJID: String?

    // MARK: negotiation

    func connect(
        jid: JID, password: String, pinnedCertificateSHA256: String? = nil
    ) async throws -> ServerCapabilities {
        transport.pinnedCertificateSHA256 = pinnedCertificateSHA256
        transport.onBytes = { [weak self] data in
            Task { await self?.ingest(data) }
        }
        transport.onError = { [weak self] error in
            Task { await self?.failAllWaiters(with: error) }
        }

        try await transport.connect(host: jid.domain, port: 5222, directTLS: false)
        try await openStream(to: jid.domain)

        // RFC 6120 §5: if the server offers STARTTLS, take it. We do not
        // continue in the clear when it does not — a password over a plaintext
        // stream is a password given away.
        guard let tls = features?.firstDescendant(xmlns: Namespace.tls) else {
            throw Failure.insecureServer
        }
        _ = tls
        try await negotiateTLS(domain: jid.domain)

        let mechanisms = offeredMechanisms()
        try await authenticate(jid: jid, password: password, mechanisms: mechanisms)
        try await openStream(to: jid.domain) // §6.4.6: restart after SASL success
        try await bindResource()

        return try await discoverCapabilities(domain: jid.domain, mechanisms: mechanisms)
    }

    func disconnect() {
        transport.send("</stream:stream>")
        transport.close()
    }

    private func openStream(to domain: String) async throws {
        parser.reset()
        features = nil
        transport.send(
            "<?xml version='1.0'?><stream:stream to='\(domain)' "
                + "xmlns='\(Namespace.client)' xmlns:stream='\(Namespace.stream)' version='1.0'>"
        )
        let features = try await waitForElement { $0.name.hasSuffix("features") }
        self.features = features
    }

    private func negotiateTLS(domain: String) async throws {
        transport.send("<starttls xmlns='\(Namespace.tls)'/>")
        let response = try await waitForElement { $0.xmlns == Namespace.tls }
        guard response.name == "proceed" else {
            throw Failure.unexpected("STARTTLS was refused")
        }
        transport.startTLS()
        isSecure = true
        try await openStream(to: domain) // §5.4.3.3: the stream restarts
    }

    private func offeredMechanisms() -> [String] {
        features?.firstDescendant(xmlns: Namespace.sasl)?
            .childrenNamed("mechanism").map(\.text) ?? []
    }

    private func authenticate(jid: JID, password: String, mechanisms: [String]) async throws {
        // Strongest first. PLAIN is not in this list: it is only reachable
        // through the OAuth path, where the credential is a bearer token whose
        // exposure is bounded, not a password.
        let preference: [SCRAM.Variant] = [.sha256, .sha1]
        guard let variant = preference.first(where: { mechanisms.contains($0.rawValue) }) else {
            throw Failure.noSharedMechanism(offered: mechanisms)
        }

        var scram = SCRAM(variant: variant, username: jid.local, password: password)
        let first = scram.clientFirstMessage()
        transport.send(
            "<auth xmlns='\(Namespace.sasl)' mechanism='\(variant.rawValue)'>"
                + Data(first.utf8).base64EncodedString() + "</auth>"
        )

        let challenge = try await waitForElement { $0.xmlns == Namespace.sasl }
        guard challenge.name == "challenge",
              let decoded = Data(base64Encoded: challenge.text),
              let text = String(data: decoded, encoding: .utf8) else {
            throw Failure.authenticationRejected(challenge.children.first?.name ?? challenge.name)
        }

        let final = try scram.handle(challenge: text)
        transport.send(
            "<response xmlns='\(Namespace.sasl)'>"
                + Data(final.utf8).base64EncodedString() + "</response>"
        )

        let outcome = try await waitForElement { $0.xmlns == Namespace.sasl }
        guard outcome.name == "success" else {
            throw Failure.authenticationRejected(outcome.children.first?.name ?? "unknown")
        }
        // Prove the server also knew the password. Not optional.
        if let decoded = Data(base64Encoded: outcome.text),
           let text = String(data: decoded, encoding: .utf8), !text.isEmpty {
            try scram.handle(finalMessage: text)
        }
    }

    private func bindResource() async throws {
        let id = UUID().uuidString
        transport.send(
            Stanza("iq", ["type": "set", "id": id], children: [
                Stanza("bind", ["xmlns": Namespace.bind]),
            ]).xml
        )
        let reply = try await waitForIQ(id: id)
        guard let jid = reply.child("bind", xmlns: Namespace.bind)?.childText("jid") else {
            throw Failure.unexpected("the server bound no resource")
        }
        boundJID = jid
    }

    private func discoverCapabilities(
        domain: String, mechanisms: [String]
    ) async throws -> ServerCapabilities {
        // A server that answers neither query is not an error: it simply gets
        // the baseline client, which is the right outcome.
        async let info = try? request(
            to: domain, query: Stanza("query", ["xmlns": Namespace.discoInfo])
        )
        async let items = try? request(
            to: domain, query: Stanza("query", ["xmlns": Namespace.discoItems])
        )

        let features = await info?.child("query")?.childrenNamed("feature")
            .compactMap { $0["var"] } ?? []
        let services = await items?.child("query")?.childrenNamed("item")
            .compactMap { $0["jid"] } ?? []

        return ServerCapabilities(
            saslMechanisms: mechanisms, services: services, features: features
        )
    }

    private func request(to jid: String, query: Stanza) async throws -> Stanza {
        let id = UUID().uuidString
        transport.send(
            Stanza("iq", ["type": "get", "id": id, "to": jid], children: [query]).xml
        )
        return try await waitForIQ(id: id)
    }

    // MARK: stream plumbing

    private func ingest(_ data: Data) {
        do {
            for event in try parser.feed(data) {
                switch event {
                case .streamOpened:
                    break // the header carries nothing we need past features
                case let .element(element):
                    deliver(element)
                case .streamClosed:
                    failAllWaiters(with: StreamTransport.Failure.closedByPeer)
                }
            }
        } catch {
            failAllWaiters(with: error)
        }
    }

    private func deliver(_ element: Stanza) {
        if element.name == "iq", let id = element.id,
           let continuation = iqContinuations.removeValue(forKey: id) {
            if element.type == "error" {
                let condition = element.child("error")?.children.first?.name ?? "error"
                continuation.resume(throwing: Failure.unexpected(condition))
            } else {
                continuation.resume(returning: element)
            }
            return
        }
        for (index, matches) in elementWaiters.enumerated() where matches(element) {
            let continuation = elementContinuations.remove(at: index)
            elementWaiters.remove(at: index)
            continuation.resume(returning: element)
            return
        }
    }

    private func waitForElement(
        _ matches: @escaping (Stanza) -> Bool
    ) async throws -> Stanza {
        try await withCheckedThrowingContinuation { continuation in
            elementWaiters.append(matches)
            elementContinuations.append(continuation)
        }
    }

    private func waitForIQ(id: String) async throws -> Stanza {
        try await withCheckedThrowingContinuation { continuation in
            iqContinuations[id] = continuation
        }
    }

    private func failAllWaiters(with error: Error) {
        let waiting = elementContinuations + Array(iqContinuations.values)
        elementContinuations = []
        elementWaiters = []
        iqContinuations = [:]
        for continuation in waiting { continuation.resume(throwing: error) }
    }
}

/// A bare JID. Resource is assigned by the server during binding.
public struct JID {
    let local: String
    let domain: String

    init?(_ raw: String) {
        let parts = raw.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        local = String(parts[0])
        domain = String(parts[1])
    }
}
