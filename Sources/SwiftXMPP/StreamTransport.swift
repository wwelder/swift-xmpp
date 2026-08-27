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

/// The socket underneath an XMPP stream.
///
/// Uses CFStream rather than Network.framework for one reason: STARTTLS.
/// `NWConnection` fixes its security parameters when the connection is created
/// and cannot upgrade an established plaintext connection, but RFC 6120 §5
/// negotiation is exactly that upgrade, and it is what nearly every server
/// offers on 5222. CFStream can enable TLS on a live socket.
///
/// Certificates are validated by the system. A generic client talks to servers
/// run by strangers, so accepting an unverified certificate — as the Channel
/// app's XMPP layer does — would expose the SASL exchange to anyone on the
/// path.
final class StreamTransport: NSObject, StreamDelegate {
    enum Failure: Error, LocalizedError {
        case cannotConnect(host: String, port: Int)
        case tlsFailed
        case closedByPeer

        var errorDescription: String? {
            switch self {
            case let .cannotConnect(host, port): "Could not reach \(host) on port \(port)."
            case .tlsFailed: "The server's TLS certificate could not be verified."
            case .closedByPeer: "The server closed the connection."
            }
        }
    }

    /// SHA-256 of a certificate to accept in addition to the system's anchors.
    /// Certificate pinning is a legitimate feature — a self-hosted server with
    /// a private CA is the normal case in XMPP — but it is set here only by the
    /// debug rig, and the UI for a user to review and pin a certificate the way
    /// Conversations and Monal do is still to come.
    var pinnedCertificateSHA256: String?

    private var input: InputStream?
    private var output: OutputStream?
    private var pending = Data()
    private let queue = DispatchQueue(label: "xmpp.transport")
    private var thread: Thread?

    /// Bytes from the server. Called on the transport's own queue.
    var onBytes: ((Data) -> Void)?
    var onError: ((Error) -> Void)?

    private var continuation: CheckedContinuation<Void, Error>?

    func connect(host: String, port: Int, directTLS: Bool) async throws {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let thread = Thread { [weak self] in
                guard let self else { return }
                var readStream: Unmanaged<CFReadStream>?
                var writeStream: Unmanaged<CFWriteStream>?
                CFStreamCreatePairWithSocketToHost(
                    nil, host as CFString, UInt32(port), &readStream, &writeStream
                )
                guard let input = readStream?.takeRetainedValue() as InputStream?,
                      let output = writeStream?.takeRetainedValue() as OutputStream? else {
                    self.finish(.failure(Failure.cannotConnect(host: host, port: port)))
                    return
                }
                self.input = input
                self.output = output
                input.delegate = self
                output.delegate = self
                input.schedule(in: .current, forMode: .default)
                output.schedule(in: .current, forMode: .default)
                if directTLS { self.enableTLS() }
                input.open()
                output.open()
                while !Thread.current.isCancelled,
                      RunLoop.current.run(mode: .default, before: .distantFuture) {}
            }
            thread.name = "xmpp.transport"
            self.thread = thread
            thread.start()
        }
    }

    /// STARTTLS: turn on TLS over the already-open socket. The caller restarts
    /// the XMPP stream afterwards, as RFC 6120 §5.4.3.3 requires.
    func startTLS() {
        enableTLS()
    }

    private var tlsEnabled = false

    private func enableTLS() {
        tlsEnabled = true
        var settings: [String: Any] = [
            kCFStreamSSLLevel as String: kCFStreamSocketSecurityLevelNegotiatedSSL,
        ]
        if pinnedCertificateSHA256 != nil {
            // Take validation into our own hands so the pin can be checked; the
            // system chain check is then performed by `evaluate` below.
            settings[kCFStreamSSLValidatesCertificateChain as String] = false
        }
        input?.setProperty(settings, forKey: .init(rawValue: kCFStreamPropertySSLSettings as String))
        output?.setProperty(settings, forKey: .init(rawValue: kCFStreamPropertySSLSettings as String))
    }

    func send(_ text: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.pending.append(Data(text.utf8))
            self.flush()
        }
    }

    func close() {
        input?.close()
        output?.close()
        thread?.cancel()
        thread = nil
    }

    private func flush() {
        guard let output, output.hasSpaceAvailable, !pending.isEmpty else { return }
        let written = pending.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return output.write(base, maxLength: pending.count)
        }
        if written > 0 { pending.removeFirst(written) }
    }

    private var verifiedPeer = false

    /// With a pin set we disabled the automatic chain check, so the peer must be
    /// checked explicitly: system-trusted, or exactly the pinned certificate.
    private func verifyPeer(on stream: Stream) -> Bool {
        guard let pin = pinnedCertificateSHA256 else {
            verifiedPeer = true
            return true
        }
        guard let trust = stream.property(
            forKey: .init(rawValue: kCFStreamPropertySSLPeerTrust as String)
        ) else {
            return false
        }
        // swiftlint:disable:next force_cast
        let secTrust = trust as! SecTrust
        if SecTrustEvaluateWithError(secTrust, nil) {
            verifiedPeer = true
            return true
        }
        guard let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
              let leaf = chain.first else { return false }
        let der = SecCertificateCopyData(leaf) as Data
        let digest = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        verifiedPeer = digest == pin
        return verifiedPeer
    }

    private func finish(_ result: Result<Void, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(with: result)
    }

    // MARK: StreamDelegate

    func stream(_ stream: Stream, handle event: Stream.Event) {
        switch event {
        case .openCompleted:
            if stream === output { finish(.success(())) }
        case .hasBytesAvailable:
            guard let input, stream === input else { return }
            // Only meaningful once TLS is on: before STARTTLS there is no peer
            // to verify, and the stream features arrive in the clear by design.
            if tlsEnabled, !verifiedPeer, !verifyPeer(on: stream) {
                finish(.failure(Failure.tlsFailed))
                onError?(Failure.tlsFailed)
                close()
                return
            }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let read = input.read(&chunk, maxLength: chunk.count)
            if read > 0 { onBytes?(Data(chunk[0..<read])) }
        case .hasSpaceAvailable:
            queue.async { [weak self] in self?.flush() }
        case .errorOccurred:
            let error = stream.streamError ?? Failure.cannotConnect(host: "", port: 0)
            finish(.failure(error))
            onError?(error)
        case .endEncountered:
            finish(.failure(Failure.closedByPeer))
            onError?(Failure.closedByPeer)
        default:
            break
        }
    }
}
