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

/// Just enough protocol buffers for the two Signal message types OMEMO puts
/// on the wire: varints and length-delimited bytes, written from the encoding
/// specification. The other wire types are skipped when read so an unexpected
/// field cannot derail parsing, and never written.
enum Protobuf {
    enum Field: Equatable {
        case varint(UInt64)
        case bytes(Data)
    }

    enum DecodeError: Error {
        case truncated
        case unsupportedWireType(Int)
    }

    static func varint(_ value: UInt64) -> Data {
        var v = value
        var out = Data()
        while v >= 0x80 {
            out.append(UInt8(v & 0x7F) | 0x80)
            v >>= 7
        }
        out.append(UInt8(v))
        return out
    }

    static func field(_ number: Int, varint value: UInt64) -> Data {
        varint(UInt64(number << 3)) + varint(value)
    }

    static func field(_ number: Int, bytes: Data) -> Data {
        varint(UInt64(number << 3 | 2)) + varint(UInt64(bytes.count)) + bytes
    }

    /// Fields by number. A repeated field keeps its last value, which is the
    /// specified merge behaviour for scalars and is fine for these messages.
    static func decode(_ data: Data) throws -> [Int: Field] {
        var fields: [Int: Field] = [:]
        var index = data.startIndex

        func readVarint() throws -> UInt64 {
            var result: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                guard index < data.endIndex, shift < 64 else { throw DecodeError.truncated }
                let byte = data[index]
                index += 1
                result |= UInt64(byte & 0x7F) << shift
                if byte & 0x80 == 0 { return result }
                shift += 7
            }
        }

        while index < data.endIndex {
            let key = try readVarint()
            let number = Int(key >> 3)
            switch Int(key & 7) {
            case 0:
                fields[number] = .varint(try readVarint())
            case 2:
                let length = Int(try readVarint())
                guard data.distance(from: index, to: data.endIndex) >= length else {
                    throw DecodeError.truncated
                }
                fields[number] = .bytes(Data(data[index..<index + length]))
                index += length
            case 1:
                guard data.distance(from: index, to: data.endIndex) >= 8 else { throw DecodeError.truncated }
                index += 8
            case 5:
                guard data.distance(from: index, to: data.endIndex) >= 4 else { throw DecodeError.truncated }
                index += 4
            case let other:
                throw DecodeError.unsupportedWireType(other)
            }
        }
        return fields
    }
}

extension [Int: Protobuf.Field] {
    func varint(_ number: Int) -> UInt64? {
        if case let .varint(v)? = self[number] { return v }
        return nil
    }

    func bytes(_ number: Int) -> Data? {
        if case let .bytes(d)? = self[number] { return d }
        return nil
    }
}
