//
// SwiftXMPP — an XMPP client core written from the specifications.
// Copyright (C) 2026 Baseco. AGPL-3.0.
//
// A command-line harness for driving the stack against a real server and a
// real OMEMO peer. Not part of the shipped library.
//

import Foundation
import SwiftXMPP

/// An in-memory key store: this harness is one run, so nothing needs to persist.
final class MemoryStore: OMEMOKeyStore {
    private var saved: (Data, UInt32)?
    func loadIdentity() -> (identity: IdentityKey, deviceID: UInt32)? {
        guard let (seed, id) = saved, let key = IdentityKey(rawRepresentation: seed) else { return nil }
        return (key, id)
    }
    func saveIdentity(seed: Data, deviceID: UInt32) { saved = (seed, deviceID) }
}

func env(_ key: String) -> String { ProcessInfo.processInfo.environment[key] ?? "" }

let jid = env("XMPP_JID")                 // e.g. alice@localhost
let password = env("XMPP_PASSWORD")
let pin = ProcessInfo.processInfo.environment["XMPP_PIN"]
let sendTo = ProcessInfo.processInfo.environment["OMEMO_SEND_TO"]
let sendBody = ProcessInfo.processInfo.environment["OMEMO_SEND_BODY"]

let session = XMPPSession()
let store = MemoryStore()

guard let parsedJID = JID(jid) else { fatalError("bad JID: \(jid)") }

Task {
    do {
        _ = try await session.connect(jid: parsedJID, credential: .password(password), pinnedCertificateSHA256: pin)
        FileHandle.standardError.write("CONNECTED \(jid)\n".data(using: .utf8)!)
        try await session.start()
        try await session.enableOMEMO(store: store)
        FileHandle.standardError.write("OMEMO_READY device=\(await session.omemoDeviceID ?? 0)\n".data(using: .utf8)!)

        // Print every decrypted message we receive, one JSON line each, so the
        // test can assert on them.
        Task {
            for await event in await session.events {
                if case let .message(m) = event, !m.isOutgoing {
                    let line = "MSG \(m.counterpart) :: \(m.body)\n"
                    FileHandle.standardOutput.write(line.data(using: .utf8)!)
                }
            }
        }

        if let to = sendTo, let body = sendBody {
            // Give the peer a moment to publish its bundle first.
            try await Task.sleep(for: .seconds(3))
            let fallback = ProcessInfo.processInfo.environment["OMEMO_FALLBACK"] == "1"
            _ = try await session.sendEncrypted(body, to: to, plaintextFallback: fallback)
            FileHandle.standardError.write("SENT_ENCRYPTED to=\(to)\n".data(using: .utf8)!)
        }

        // Stay alive to receive.
        try await Task.sleep(for: .seconds(40))
        FileHandle.standardError.write("DONE\n".data(using: .utf8)!)
        exit(0)
    } catch {
        FileHandle.standardError.write("ERROR \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

RunLoop.main.run()
