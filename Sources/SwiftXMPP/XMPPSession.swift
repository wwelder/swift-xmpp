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
    public init() {}

    struct Namespace {
        static let stream = "http://etherx.jabber.org/streams"
        static let tls = "urn:ietf:params:xml:ns:xmpp-tls"
        static let sasl = "urn:ietf:params:xml:ns:xmpp-sasl"
        static let bind = "urn:ietf:params:xml:ns:xmpp-bind"
        static let client = "jabber:client"
        static let discoInfo = "http://jabber.org/protocol/disco#info"
        static let discoItems = "http://jabber.org/protocol/disco#items"
        static let streamManagement = StreamManagement.namespace
        static let clientState = "urn:xmpp:csi:0"
        static let carbons = "urn:xmpp:carbons:2"
        static let forward = "urn:xmpp:forward:0"
        static let push = "urn:xmpp:push:0"
        static let dataForms = "jabber:x:data"
        static let omemo = OMEMONamespace.encrypted
    }

    public enum Failure: Error, LocalizedError {
        case noSharedMechanism(offered: [String])
        case authenticationRejected(String)
        case insecureServer
        case unexpected(String)
        case unsupported(String)

        public var errorDescription: String? {
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
            case let .unsupported(feature):
                "This server does not support \(feature)."
            }
        }
    }

    private var transport = StreamTransport()
    private var parser = StreamParser()

    private var features: Stanza?
    private var isSecure = false
    private var management = StreamManagement()

    /// Kept so the session can re-establish itself without asking the caller
    /// to hold credentials and hand them back. A client that makes the user
    /// retype a password because a train went into a tunnel is not finished.
    private var jid: JID?
    private var credential: Credential?
    private var pin: String?
    private var reconnectAttempt = 0
    private var isReconnecting = false
    private var deliberatelyClosed = false

    /// Whether the server will act on client state, and what we last told it.
    private var supportsClientState = false
    private var clientState: ClientState = .active

    /// XEP-0352. What the client is doing, from the server's point of view.
    public enum ClientState: Sendable {
        /// Someone is looking at the screen. Send everything.
        case active
        /// Backgrounded or asleep. The server may hold back or coalesce the
        /// traffic that only matters to a visible UI - presence churn, typing
        /// notifications - and deliver it when we come back.
        case inactive
    }

    /// Whether the server will hold our session open across a dropped
    /// connection. Callers show this: "reconnecting" and "signed out" are very
    /// different things to a user watching a spinner.
    public var canResume: Bool { management.resumeToken != nil }

    /// Elements the negotiation is waiting for, and IQ replies by id.
    private var elementWaiters: [(Stanza) -> Bool] = []
    private var elementContinuations: [CheckedContinuation<Stanza, Error>] = []
    private var iqContinuations: [String: CheckedContinuation<Stanza, Error>] = [:]

    public private(set) var boundJID: String?

    /// Bare JID of this session, used to tell our own messages from others'.
    private var ourBareJID = ""

    /// What happened on the stream, in order.
    ///
    /// One stream rather than a delegate with a dozen methods: a caller that
    /// wants only messages writes one `for await` and ignores the rest, and a
    /// caller that wants everything does not have to implement six callbacks
    /// to get there.
    public enum Event: Sendable {
        case rosterLoaded([Contact])
        case rosterChanged(Contact)
        case presence(ContactPresence)
        case message(Message)
        /// The connection dropped and we are trying to get it back. Distinct
        /// from `disconnected`, because a spinner and a login screen are very
        /// different answers to the same event.
        case reconnecting(attempt: Int)
        /// Back, with the same session: nothing was lost and nothing needs
        /// refetching.
        case resumed
        case disconnected(reason: String)
    }

    private var eventContinuation: AsyncStream<Event>.Continuation?

    public lazy var events: AsyncStream<Event> = {
        AsyncStream { continuation in
            self.eventContinuation = continuation
        }
    }()

    private func emit(_ event: Event) {
        eventContinuation?.yield(event)
    }

    // MARK: negotiation

    public func connect(
        jid: JID, credential: Credential, pinnedCertificateSHA256: String? = nil
    ) async throws -> ServerCapabilities {
        self.jid = jid
        self.credential = credential
        pin = pinnedCertificateSHA256
        deliberatelyClosed = false
        transport.pinnedCertificateSHA256 = pinnedCertificateSHA256
        transport.onBytes = { [weak self] data in
            Task { await self?.ingest(data) }
        }
        transport.onError = { [weak self] error in
            Task { await self?.handleTransportFailure(error) }
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
        try await authenticate(jid: jid, credential: credential, mechanisms: mechanisms)
        try await openStream(to: jid.domain) // §6.4.6: restart after SASL success
        try await bindResource()
        supportsClientState = features?.firstDescendant(xmlns: Namespace.clientState) != nil
        await enableStreamManagement()

        return try await discoverCapabilities(domain: jid.domain, mechanisms: mechanisms)
    }

    public func disconnect() {
        deliberatelyClosed = true
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

    private func authenticate(
        jid: JID, credential: Credential, mechanisms: [String]
    ) async throws {
        guard let mechanism = Mechanism.choose(for: credential, from: mechanisms) else {
            throw Failure.noSharedMechanism(offered: mechanisms)
        }
        // A mechanism that sends the secret as-is is only safe on an encrypted
        // stream. We always have one by here, but the check is cheap and the
        // consequence of getting it wrong is the credential in plaintext.
        guard !mechanism.carriesSecretVerbatim || isSecure else {
            throw Failure.insecureServer
        }

        guard let variant = mechanism.scramVariant else {
            return try await authenticateWithBearerToken(
                jid: jid, credential: credential, mechanism: mechanism
            )
        }

        guard case let .password(password) = credential else {
            throw Failure.noSharedMechanism(offered: mechanisms)
        }
        var scram = SCRAM(variant: variant, username: jid.local, password: password)
        let first = scram.clientFirstMessage()
        transport.send(
            "<auth xmlns='\(Namespace.sasl)' mechanism='\(mechanism.rawValue)'>"
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

    /// The bearer-token path. `X-OAUTH2` carries the same bytes as PLAIN, and
    /// `OAUTHBEARER` (RFC 7628) wraps them in a GS2 header; both hand the token
    /// to the server, which is why the encrypted-stream check above is not
    /// optional. What mints the token is deliberately outside this library.
    private func authenticateWithBearerToken(
        jid: JID, credential: Credential, mechanism: Mechanism
    ) async throws {
        guard case let .token(token) = credential else {
            throw Failure.noSharedMechanism(offered: [mechanism.rawValue])
        }
        let payload: String
        switch mechanism {
        case .oauthBearer:
            payload = "n,a=\(jid.local)@\(jid.domain),\u{01}auth=Bearer \(token)\u{01}\u{01}"
        default:
            payload = "\u{00}\(jid.local)\u{00}\(token)"
        }
        transport.send(
            "<auth xmlns='\(Namespace.sasl)' mechanism='\(mechanism.rawValue)'>"
                + Data(payload.utf8).base64EncodedString() + "</auth>"
        )
        let outcome = try await waitForElement { $0.xmlns == Namespace.sasl }
        guard outcome.name == "success" else {
            throw Failure.authenticationRejected(outcome.children.first?.name ?? "unknown")
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
        ourBareJID = jid.split(separator: "/").first.map(String.init) ?? jid
    }

    /// XEP-0198. Requested after binding, because a managed stream counts
    /// stanzas and there are none before the resource exists.
    ///
    /// A server that does not offer it is not an error: the session simply has
    /// no safety net, which is how every XMPP client worked for a decade.
    private func enableStreamManagement() async {
        guard features?.firstDescendant(xmlns: Namespace.streamManagement) != nil else { return }
        transport.send(management.enableRequest)
        guard let reply = try? await waitForElement({
            $0.xmlns == Namespace.streamManagement
        }), reply.name == "enabled" else { return }
        management.handleEnabled(reply)
    }

    /// Tell the server whether anyone is looking.
    ///
    /// Worth doing on every foreground and background transition. On mobile the
    /// saving is real: presence churn in a busy roster and typing notifications
    /// are most of the traffic a backgrounded client would otherwise wake for,
    /// and none of it changes anything the user can see.
    ///
    /// Silently a no-op when the server does not support it, because a client
    /// that refuses to run against a plain server is not a generic client.
    public func setClientState(_ state: ClientState) {
        clientState = state
        guard supportsClientState else { return }
        let element = state == .active ? "active" : "inactive"
        // Not a stanza, so it is not counted for stream management.
        transport.send("<\(element) xmlns='\(Namespace.clientState)'/>")
    }

    /// XEP-0357. Register this device so the server can wake it through an
    /// app server when a message arrives and the connection is gone.
    ///
    /// `service` is the app server's JID and `node` identifies this device to
    /// it - on Apple platforms, the APNs token. The app server itself is
    /// infrastructure the app's operator runs (a stock ejabberd cannot reach
    /// APNs; only the certificate holder can); this is only the client's half.
    ///
    /// Throws when the server does not support push, because unlike carbons or
    /// client state this is something the user needs to know about: without it
    /// a backgrounded phone receives nothing, and they should be told rather
    /// than left to conclude the app is broken.
    public func enablePush(service: String, node: String, secret: String? = nil) async throws {
        guard supportsPush else { throw Failure.unsupported("push notifications") }
        var options: [Stanza] = [
            Stanza("field", ["var": "FORM_TYPE"],
                   children: [Stanza("value", text: "http://jabber.org/protocol/pubsub#publish-options")]),
        ]
        if let secret {
            options.append(Stanza("field", ["var": "secret"], children: [Stanza("value", text: secret)]))
        }
        let id = UUID().uuidString
        sendCounted(Stanza("iq", ["type": "set", "id": id], children: [
            Stanza("enable", ["xmlns": Namespace.push, "jid": service, "node": node], children: [
                Stanza("x", ["xmlns": Namespace.dataForms, "type": "submit"], children: options),
            ]),
        ]))
        _ = try await waitForIQ(id: id)
    }

    public func disablePush(service: String, node: String? = nil) async throws {
        var attrs = ["xmlns": Namespace.push, "jid": service]
        if let node { attrs["node"] = node }
        let id = UUID().uuidString
        sendCounted(Stanza("iq", ["type": "set", "id": id], children: [Stanza("disable", attrs)]))
        _ = try await waitForIQ(id: id)
    }

    /// Whether the server offered XEP-0357 in disco#info.
    public private(set) var supportsPush = false

    // MARK: OMEMO

    private var omemo: OMEMOEngine?
    public var omemoDeviceID: UInt32? { get async { await omemo?.deviceID } }
    private var omemoStore: OMEMOKeyStore?

    /// Turn on OMEMO for this session: create or restore our identity and
    /// device, publish our bundle, and add our device id to the list, so peers
    /// can start encrypting to us. Idempotent.
    ///
    /// `store` persists the identity across launches; without it every launch
    /// is a new device, which peers see as a new unverified key.
    public func enableOMEMO(store: OMEMOKeyStore) async throws {
        guard omemo == nil else { return }
        omemoStore = store
        let engine: OMEMOEngine
        if let saved = store.loadIdentity() {
            engine = OMEMOEngine(identity: saved.identity, deviceID: saved.deviceID)
        } else {
            engine = OMEMOEngine()
            await store.saveIdentity(seed: engine.identitySeed, deviceID: engine.deviceID)
        }
        await engine.setBundleSource(PEPBundleSource(session: self))
        omemo = engine
        try await publishOMEMOBundle()
        try await addSelfToDeviceList()
    }

    private func publishOMEMOBundle() async throws {
        guard let omemo else { return }
        let bundle = try await omemo.bundle()
        _ = try await sendIQ(type: "set", child: OMEMOPublishing.publishBundle(bundle, deviceID: omemo.deviceID))
    }

    /// Add our device id to the published list without dropping the ids already
    /// there. Overwriting the list makes our other devices vanish for everyone,
    /// which is the classic OMEMO footgun.
    private func addSelfToDeviceList() async throws {
        guard let omemo else { return }
        let existing = (try? await fetchDeviceList(for: ourBareJID)) ?? []
        let ids = existing.contains(omemo.deviceID) ? existing : existing + [omemo.deviceID]
        _ = try await sendIQ(type: "set", child: OMEMOPublishing.publishDeviceList(ids))
    }

    func fetchDeviceList(for jid: String) async throws -> [UInt32] {
        let reply = try await sendIQ(type: "get", to: jid, child: OMEMOPublishing.fetchDeviceList())
        return OMEMOPublishing.parseDeviceList(reply.child("pubsub") ?? reply)
    }

    func fetchBundle(for jid: String, deviceID: UInt32) async throws -> OMEMOBundle {
        let reply = try await sendIQ(type: "get", to: jid, child: OMEMOPublishing.fetchBundle(deviceID: deviceID))
        guard let bundle = OMEMOPublishing.parseBundle(reply.child("pubsub") ?? reply) else {
            throw OMEMOError.malformedMessage
        }
        return bundle
    }

    /// Send an OMEMO-encrypted message. The body never appears in the clear;
    /// the optional plaintext fallback is only a hint for clients that cannot
    /// do OMEMO, and callers who want no fallback pass none.
    @discardableResult
    public func sendEncrypted(_ body: String, to jid: String, plaintextFallback: Bool = false) async throws -> Message {
        guard let omemo else { throw OMEMOError.malformedMessage }
        let encrypted = try await omemo.encrypt(Data(body.utf8), for: jid)
        let id = UUID().uuidString
        var children: [Stanza] = [encrypted.element()]
        if plaintextFallback {
            children.append(Stanza("body", text: "This message is OMEMO-encrypted."))
        }
        // EME (XEP-0380): tell a receiving client what it failed to decrypt.
        children.append(Stanza("encryption", ["xmlns": "urn:xmpp:eme:0", "namespace": Namespace.omemo]))
        sendCounted(Stanza("message", ["to": jid, "type": "chat", "id": id, "from": ourBareJID], children: children))
        requestAcknowledgement()
        return Message(id: id, counterpart: jid, body: body, isOutgoing: true, timestamp: Date())
    }

    private func handleEncryptedMessage(_ element: Stanza, from bareFrom: String) async {
        guard let omemo,
              let encryptedElement = element.child("encrypted", xmlns: Namespace.omemo),
              let encrypted = EncryptedElement.parse(encryptedElement)
        else { return }
        do {
            guard let plaintext = try await omemo.decrypt(encrypted, from: bareFrom) else { return }
            emit(.message(Message(
                id: element.id ?? UUID().uuidString, counterpart: bareFrom,
                body: String(decoding: plaintext, as: UTF8.self), isOutgoing: false, timestamp: Date()
            )))
        } catch {
            emit(.message(Message(
                id: element.id ?? UUID().uuidString, counterpart: bareFrom,
                body: "[could not decrypt this OMEMO message]", isOutgoing: false, timestamp: Date()
            )))
        }
    }


    /// Ask the server to confirm what it has handled. Worth doing before the
    /// app goes to the background: the answer decides whether a message the
    /// user just sent is safe or needs resending.
    public func requestAcknowledgement() {
        guard management.isEnabled else { return }
        transport.send(management.ackRequest)
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

        // XEP-0357 §4: push support is advertised on the *account*, not the
        // server. A client that only asks the domain concludes no server
        // supports push, and that is a wrong answer that looks like a right
        // one on every server it is tested against.
        let account = try? await request(
            to: ourBareJID, query: Stanza("query", ["xmlns": Namespace.discoInfo])
        )
        supportsPush = account?.child("query")?.childrenNamed("feature")
            .contains { $0["var"] == Namespace.push } ?? false
        let services = await items?.child("query")?.childrenNamed("item")
            .compactMap { $0["jid"] } ?? []

        return ServerCapabilities(
            saslMechanisms: mechanisms, services: services, features: features
        )
    }

    // MARK: what a client actually does

    /// Fetch the roster (RFC 6121 §2.1) and announce ourselves.
    ///
    /// Presence is sent after the roster on purpose: the server starts pushing
    /// contact presence the moment we send ours, and receiving presence for a
    /// contact we do not yet know about means dropping it or guessing.
    public func start() async throws {
        let reply = try await request(to: ourBareJID, query: Stanza("query", ["xmlns": "jabber:iq:roster"]))
        let contacts = reply.child("query")?.children.compactMap(Contact.init) ?? []
        emit(.rosterLoaded(contacts))
        await enableCarbons()
        sendCounted(Stanza("presence"))
    }

    /// XEP-0280. Ask the server to copy us on conversations happening on our
    /// other devices, in both directions, so a reply typed on a laptop shows
    /// up in the phone's thread instead of the thread going silent.
    ///
    /// Failure is not an error: a server without carbons is a server where
    /// each device sees only its own half, which is how it worked before and
    /// still works.
    private func enableCarbons() async {
        let id = UUID().uuidString
        sendCounted(Stanza("iq", ["type": "set", "id": id],
                           children: [Stanza("enable", ["xmlns": Namespace.carbons])]))
        _ = try? await waitForIQ(id: id)
    }

    /// Send a chat message. Returns the id it was sent with, so a caller can
    /// match it to a delivery receipt later.
    @discardableResult
    public func send(_ body: String, to jid: String) -> Message? {
        let id = UUID().uuidString
        let stanza = Stanza(
            "message",
            ["to": jid, "type": "chat", "id": id, "from": ourBareJID],
            children: [Stanza("body", text: body)]
        )
        sendCounted(stanza)
        // Ask the server to confirm it. Without this the client knows only that
        // the bytes were written to a socket, which is not the same as the
        // message existing anywhere else — and the difference is exactly what
        // stream management was added to close.
        requestAcknowledgement()
        return Message(from: stanza, ourBareJID: ourBareJID)
    }

    /// Ask to see a contact's presence. They must accept; `pendingOut` on the
    /// roster entry is how a client shows that it is waiting.
    public func requestSubscription(to jid: String) {
        sendCounted(Stanza("presence", ["to": jid, "type": "subscribe"]))
    }

    /// Answer someone else's request.
    public func respondToSubscription(from jid: String, accept: Bool) {
        sendCounted(
            Stanza("presence", ["to": jid, "type": accept ? "subscribed" : "unsubscribed"])
        )
    }

    /// Send a stanza, keeping a copy until the server acknowledges it. Only
    /// stanzas go through here; stream management's own elements must not be
    /// counted or they desynchronise the two sides.
    private func sendCounted(_ stanza: Stanza) {
        let serialised = stanza.xml
        transport.send(serialised)
        if management.isEnabled, StreamManagement.isCountable(stanza) {
            management.countSent(serialised)
        }
    }

    private func request(to jid: String, query: Stanza) async throws -> Stanza {
        try await sendIQ(type: "get", to: jid, child: query)
    }

    /// Send an IQ and await its reply. `to` nil means the server. Used by the
    /// PEP layer, which is how OMEMO publishes and fetches keys.
    func sendIQ(type: String, to jid: String? = nil, child: Stanza) async throws -> Stanza {
        let id = UUID().uuidString
        var attrs = ["type": type, "id": id]
        if let jid { attrs["to"] = jid }
        transport.send(Stanza("iq", attrs, children: [child]).xml)
        return try await waitForIQ(id: id)
    }

    /// Drop the socket the way a lost network does: no stream close, no
    /// warning to the server, which then holds the session open for its resume
    /// window. Exists because resumption is otherwise only testable by
    /// physically interrupting a network, and an untested recovery path is a
    /// recovery path that does not work.
    public func simulateConnectionLoss() {
        transport.close()
        Task { await handleTransportFailure(StreamTransport.Failure.closedByPeer) }
    }

    // MARK: staying connected

    /// The connection went away. Whether that is recoverable is the whole
    /// question, and stream management is what makes the answer "usually yes".
    private func handleTransportFailure(_ error: Error) async {
        // Waiters must fail now: something is awaiting a reply that will never
        // come, and leaving them suspended is a hang rather than an error.
        failAllWaiters(with: error)

        guard !deliberatelyClosed, !isReconnecting else { return }
        guard management.resumeToken != nil, let jid, let credential else {
            emit(.disconnected(reason: error.localizedDescription))
            return
        }

        isReconnecting = true
        defer { isReconnecting = false }

        // Bounded, and it backs off: a client that retries a dead server every
        // second is a client that drains a battery and annoys an operator.
        // The ceiling matches what a server typically holds a session for.
        while reconnectAttempt < 6 {
            reconnectAttempt += 1
            emit(.reconnecting(attempt: reconnectAttempt))
            let delay = min(pow(2.0, Double(reconnectAttempt - 1)), 30)
            try? await Task.sleep(for: .seconds(delay))
            if deliberatelyClosed { return }

            do {
                try await resumeSession(jid: jid, credential: credential)
                reconnectAttempt = 0
                emit(.resumed)
                return
            } catch {
                continue
            }
        }

        emit(.disconnected(reason: "Could not reconnect."))
    }

    /// Reconnect and pick the old session back up.
    ///
    /// The order is the XEP's: TLS and SASL happen again exactly as they did
    /// the first time — resumption replaces resource binding, not
    /// authentication. Getting this wrong produces a client that appears to
    /// resume and is in fact unauthenticated.
    private func resumeSession(jid: JID, credential: Credential) async throws {
        transport.close()
        transport = StreamTransport()
        transport.pinnedCertificateSHA256 = pin
        transport.onBytes = { [weak self] data in
            Task { await self?.ingest(data) }
        }
        transport.onError = { [weak self] error in
            Task { await self?.handleTransportFailure(error) }
        }
        isSecure = false

        try await transport.connect(host: jid.domain, port: 5222, directTLS: false)
        try await openStream(to: jid.domain)
        guard features?.firstDescendant(xmlns: Namespace.tls) != nil else {
            throw Failure.insecureServer
        }
        try await negotiateTLS(domain: jid.domain)
        try await authenticate(
            jid: jid, credential: credential, mechanisms: offeredMechanisms()
        )
        try await openStream(to: jid.domain)

        guard let request = management.resumeRequest() else {
            throw Failure.unexpected("no resumable session")
        }
        transport.send(request)
        let reply = try await waitForElement { $0.xmlns == Namespace.streamManagement }

        guard reply.name == "resumed" else {
            // The server has forgotten us. Everything queued belongs to a
            // stream that no longer exists, so it is dropped rather than
            // replayed into a new one, and the caller starts over.
            management.handleFailed()
            throw Failure.unexpected("the session could not be resumed")
        }

        // Anything the server never saw goes out again. This is the payoff:
        // messages sent into a dying connection are not silently lost.
        for stanza in management.handleResumed(reply) {
            transport.send(stanza)
        }
        // Re-assert client state. A resumed session may or may not have kept
        // it, and a client that assumes "active" wakes for everything while a
        // client that assumes "inactive" goes quiet in the foreground.
        setClientState(clientState)
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
                    emit(.disconnected(reason: "The server closed the connection."))
                    failAllWaiters(with: StreamTransport.Failure.closedByPeer)
                }
            }
        } catch {
            failAllWaiters(with: error)
        }
    }

    private func deliver(_ element: Stanza) {
        // Only the two elements that are pure bookkeeping are handled here and
        // dropped. Everything else in this namespace - `enabled`, `resumed`,
        // `failed` - is part of a negotiation something is waiting for, and
        // swallowing it deadlocks the session.
        if element.xmlns == Namespace.streamManagement,
           element.name == "r" || element.name == "a" {
            if element.name == "r" {
                // The server wants to know where we are. Answering promptly is
                // what keeps its own queue from growing.
                transport.send(management.ackResponse)
            } else {
                management.acknowledge(through: UInt32(element["h"] ?? "") ?? 0)
            }
            return
        }
        // Counted before it is acted on: `h` means "received and handled", and
        // a stanza that throws on the way to a handler was still received.
        if management.isEnabled, StreamManagement.isCountable(element) {
            management.countReceived()
        }
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
        route(element)
    }

    /// A carbon is a message from *our own account* wrapping a copy of a
    /// message one of our other devices sent or received. Returns the inner
    /// message, or nil if this is not a carbon.
    ///
    /// The outer `from` must be our own bare JID (XEP-0280 §11). Without that
    /// check anyone can send a message that *looks* like a carbon and have the
    /// client display it as something we said or received elsewhere - a
    /// forged conversation, complete with our name on it.
    static func unwrapCarbon(_ element: Stanza, ourBareJID: String) -> Stanza? {
        guard let wrapper = element.child("received", xmlns: Namespace.carbons)
                ?? element.child("sent", xmlns: Namespace.carbons) else { return nil }
        let from = element.from ?? ""
        let bareFrom = from.split(separator: "/").first.map(String.init) ?? from
        guard bareFrom == ourBareJID else { return nil }
        return wrapper.child("forwarded", xmlns: Namespace.forward)?.child("message")
    }

    /// Anything nobody was waiting for. This is most of the traffic in a live
    /// session: contacts coming and going, messages arriving, the server
    /// pushing roster changes.
    private func route(_ element: Stanza) {
        switch element.name {
        case "message":
            if element.child("encrypted", xmlns: Namespace.omemo) != nil {
                let from = element.from ?? ""
                let bareFrom = from.split(separator: "/").first.map(String.init) ?? from
                Task { await handleEncryptedMessage(element, from: bareFrom) }
                return
            }
            if let carbon = Self.unwrapCarbon(element, ourBareJID: ourBareJID) {
                if let message = Message(from: carbon, ourBareJID: ourBareJID) {
                    emit(.message(message))
                }
            } else if let message = Message(from: element, ourBareJID: ourBareJID) {
                emit(.message(message))
            }
        case "presence":
            // Subscription handshakes are not availability and must not be
            // shown as a contact coming online.
            guard element.type != "subscribe", element.type != "subscribed",
                  element.type != "unsubscribe", element.type != "unsubscribed" else { return }
            emit(.presence(ContactPresence(from: element)))
        case "iq":
            // A roster push (RFC 6121 §2.1.6). The server sends these when the
            // roster changes anywhere, including from our other devices.
            if let item = element.child("query", xmlns: "jabber:iq:roster")?.child("item"),
               let contact = Contact(item) {
                emit(.rosterChanged(contact))
                if let id = element.id {
                    transport.send(Stanza("iq", ["type": "result", "id": id]).xml)
                }
            }
        default:
            break
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
    public let local: String
    public let domain: String

    public init?(_ raw: String) {
        let parts = raw.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        local = String(parts[0])
        domain = String(parts[1])
    }
}
