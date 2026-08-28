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

/// One XML element from the stream.
///
/// Written against RFC 6120 §11, which restricts XMPP to a small subset of XML:
/// no DTDs, no comments, no processing instructions, and only the five
/// predefined entities. That is why this can be a plain struct and the parser
/// can be a few hundred lines rather than a dependency.
public struct Stanza {
    public var name: String
    public var attributes: [String: String]
    public var children: [Stanza]
    /// Character data directly inside this element.
    public var text: String

    public init(
        _ name: String,
        _ attributes: [String: String] = [:],
        text: String = "",
        children: [Stanza] = []
    ) {
        self.name = name
        self.attributes = attributes
        self.children = children
        self.text = text
    }

    // MARK: reading

    public subscript(attribute: String) -> String? { attributes[attribute] }

    public var id: String? { attributes["id"] }
    public var type: String? { attributes["type"] }
    public var from: String? { attributes["from"] }
    public var to: String? { attributes["to"] }
    /// The element's own namespace, as declared on it.
    public var xmlns: String? { attributes["xmlns"] }

    public func child(_ name: String, xmlns: String? = nil) -> Stanza? {
        children.first { $0.name == name && (xmlns == nil || $0.xmlns == xmlns) }
    }

    public func childrenNamed(_ name: String, xmlns: String? = nil) -> [Stanza] {
        children.filter { $0.name == name && (xmlns == nil || $0.xmlns == xmlns) }
    }

    public func childText(_ name: String) -> String? { child(name)?.text }

    /// Depth-first search for the first descendant in a namespace. Handy for
    /// stream features, where the nesting varies between servers.
    public func firstDescendant(xmlns: String) -> Stanza? {
        for child in children {
            if child.xmlns == xmlns { return child }
            if let found = child.firstDescendant(xmlns: xmlns) { return found }
        }
        return nil
    }

    // MARK: writing

    /// Serialised form, with the five predefined entities escaped per RFC 6120.
    public var xml: String {
        var out = "<" + name
        for key in attributes.keys.sorted() {
            out += " \(key)='\(Self.escape(attributes[key]!, inAttribute: true))'"
        }
        if children.isEmpty, text.isEmpty {
            return out + "/>"
        }
        out += ">"
        out += Self.escape(text, inAttribute: false)
        for child in children { out += child.xml }
        return out + "</\(name)>"
    }

    public static func escape(_ value: String, inAttribute: Bool) -> String {
        var out = value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        if inAttribute {
            out = out
                .replacingOccurrences(of: "'", with: "&apos;")
                .replacingOccurrences(of: "\"", with: "&quot;")
        }
        return out
    }

    public static func unescape(_ value: String) -> String {
        guard value.contains("&") else { return value }
        return value
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&quot;", with: "\"")
            // Ampersand last, so "&amp;lt;" survives as the text "&lt;".
            .replacingOccurrences(of: "&amp;", with: "&")
    }
}
