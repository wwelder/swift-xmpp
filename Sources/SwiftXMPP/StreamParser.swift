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

/// Incremental parser for an XMPP stream.
///
/// An XMPP stream is one XML document whose root element stays open for the
/// life of the connection (RFC 6120 §4.1), so a document-oriented parser is the
/// wrong shape: it would wait forever for the root to close. This feeds on
/// bytes as they arrive and emits each top-level child of the root as soon as
/// it is complete.
///
/// It handles exactly the subset RFC 6120 §11.1 permits. Anything outside that
/// — a DTD, a comment, a processing instruction — is a stream error by the
/// specification, and is reported rather than skipped.
struct StreamParser {
    enum Event {
        /// The opening `<stream:stream ...>` tag, which never "completes".
        case streamOpened(Stanza)
        /// A complete top-level element: an iq, message, presence, features…
        case element(Stanza)
        case streamClosed
    }

    enum ParseError: Error, LocalizedError {
        case notWellFormed(String)
        case restrictedXML(String)

        var errorDescription: String? {
            switch self {
            case let .notWellFormed(detail): "Malformed XML from the server: \(detail)."
            case let .restrictedXML(what): "The server sent \(what), which XMPP does not allow."
            }
        }
    }

    /// Bytes that arrived but do not yet form a complete token.
    private var buffer = ""
    /// Elements we are currently inside, innermost last. Empty means we are at
    /// the stream root and the next completed element is a stanza.
    private var open: [Stanza] = []
    private var sawStreamOpen = false

    mutating func reset() {
        buffer = ""
        open = []
        sawStreamOpen = false
    }

    /// Feed newly received bytes; returns whatever became complete.
    mutating func feed(_ data: Data) throws -> [Event] {
        guard let chunk = String(data: data, encoding: .utf8) else {
            throw ParseError.notWellFormed("not valid UTF-8")
        }
        buffer += chunk
        return try drain()
    }

    private mutating func drain() throws -> [Event] {
        var events: [Event] = []
        while true {
            guard let markerIndex = buffer.firstIndex(of: "<") else {
                // Only character data so far. Keep it if we are inside an
                // element; discard inter-stanza whitespace at the root.
                try appendText(String(buffer))
                buffer = ""
                return events
            }

            if markerIndex != buffer.startIndex {
                try appendText(String(buffer[buffer.startIndex..<markerIndex]))
                buffer = String(buffer[markerIndex...])
            }

            guard let closeIndex = indexOfTagEnd(from: buffer) else {
                return events // tag is still arriving
            }

            let raw = String(buffer[buffer.index(after: buffer.startIndex)..<closeIndex])
            buffer = String(buffer[buffer.index(after: closeIndex)...])

            if let event = try handle(tag: raw) {
                events.append(event)
            }
        }
    }

    /// Finds the `>` that ends a tag, ignoring any inside quoted attributes.
    private func indexOfTagEnd(from s: String) -> String.Index? {
        var quote: Character?
        var i = s.index(after: s.startIndex)
        while i < s.endIndex {
            let c = s[i]
            if let q = quote {
                if c == q { quote = nil }
            } else if c == "'" || c == "\"" {
                quote = c
            } else if c == ">" {
                return i
            }
            i = s.index(after: i)
        }
        return nil
    }

    private mutating func appendText(_ raw: String) throws {
        guard !open.isEmpty else { return } // whitespace keepalive between stanzas
        open[open.count - 1].text += Stanza.unescape(raw)
    }

    /// `raw` is the tag body without the angle brackets.
    private mutating func handle(tag raw: String) throws -> Event? {
        if raw.hasPrefix("?") {
            // The XML declaration is allowed; a processing instruction is not.
            guard raw.hasPrefix("?xml") else {
                throw ParseError.restrictedXML("a processing instruction")
            }
            return nil
        }
        if raw.hasPrefix("!") {
            throw ParseError.restrictedXML(
                raw.hasPrefix("!--") ? "an XML comment" : "a DTD or CDATA section"
            )
        }

        if raw.hasPrefix("/") {
            let name = String(raw.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines)
            if open.isEmpty {
                guard name.hasSuffix("stream") else {
                    throw ParseError.notWellFormed("unexpected closing tag </\(name)>")
                }
                return .streamClosed
            }
            let finished = open.removeLast()
            guard finished.name == name else {
                throw ParseError.notWellFormed("</\(name)> closes <\(finished.name)>")
            }
            return try close(finished)
        }

        let selfClosing = raw.hasSuffix("/")
        let body = selfClosing ? String(raw.dropLast()) : raw
        var element = try parseOpenTag(body)

        // The stream header stays open for the whole session, so it is an event
        // in its own right rather than something we wait to close.
        if !sawStreamOpen {
            sawStreamOpen = true
            element.attributes["xmlns:stream"] = element.attributes["xmlns:stream"]
            return .streamOpened(element)
        }

        if selfClosing {
            return try close(element)
        }
        open.append(element)
        return nil
    }

    private mutating func close(_ element: Stanza) throws -> Event? {
        if open.isEmpty {
            return .element(element)
        }
        open[open.count - 1].children.append(element)
        return nil
    }

    private func parseOpenTag(_ body: String) throws -> Stanza {
        var name = ""
        var index = body.startIndex
        while index < body.endIndex, !body[index].isWhitespace {
            name.append(body[index])
            index = body.index(after: index)
        }
        guard !name.isEmpty else { throw ParseError.notWellFormed("empty tag name") }

        var attributes: [String: String] = [:]
        while index < body.endIndex {
            while index < body.endIndex, body[index].isWhitespace {
                index = body.index(after: index)
            }
            guard index < body.endIndex else { break }

            var key = ""
            while index < body.endIndex, body[index] != "=", !body[index].isWhitespace {
                key.append(body[index])
                index = body.index(after: index)
            }
            while index < body.endIndex, body[index].isWhitespace {
                index = body.index(after: index)
            }
            guard index < body.endIndex, body[index] == "=" else {
                throw ParseError.notWellFormed("attribute '\(key)' has no value")
            }
            index = body.index(after: index)
            while index < body.endIndex, body[index].isWhitespace {
                index = body.index(after: index)
            }
            guard index < body.endIndex, body[index] == "'" || body[index] == "\"" else {
                throw ParseError.notWellFormed("attribute '\(key)' is not quoted")
            }
            let quote = body[index]
            index = body.index(after: index)

            var value = ""
            while index < body.endIndex, body[index] != quote {
                value.append(body[index])
                index = body.index(after: index)
            }
            guard index < body.endIndex else {
                throw ParseError.notWellFormed("attribute '\(key)' is unterminated")
            }
            index = body.index(after: index)
            attributes[key] = Stanza.unescape(value)
        }

        return Stanza(name, attributes)
    }
}
