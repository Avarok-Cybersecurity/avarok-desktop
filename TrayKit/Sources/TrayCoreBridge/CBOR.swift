// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// The CBOR subset tray-ffi writes (crates/tray-ffi/src/encode.rs): unsigned integers, byte and
/// text strings, arrays, maps with text keys, booleans; definite lengths only. Anything else is a
/// decoding error, never a guess.
public indirect enum CBOR: Equatable {
    case uint(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([String: CBOR])
    case bool(Bool)

    public enum DecodeError: Error, Equatable {
        case truncated
        case unsupported(UInt8)
        case notUTF8
        case nonTextKey
        case trailingBytes
    }

    public static func decode(_ data: Data) throws -> CBOR {
        var reader = Reader(bytes: [UInt8](data))
        let value = try reader.value(depth: 0)
        guard reader.at == reader.bytes.count else { throw DecodeError.trailingBytes }
        return value
    }

    public subscript(key: String) -> CBOR? {
        if case .map(let m) = self { return m[key] }
        return nil
    }

    public var text: String? { if case .text(let s) = self { return s }; return nil }
    public var uint: UInt64? { if case .uint(let n) = self { return n }; return nil }
    public var bytes: Data? { if case .bytes(let d) = self { return d }; return nil }
    public var array: [CBOR]? { if case .array(let a) = self { return a }; return nil }
    public var bool: Bool? { if case .bool(let b) = self { return b }; return nil }
}

private struct Reader {
    let bytes: [UInt8]
    var at = 0
    /// Nesting beyond this is not something tray-ffi writes.
    static let maxDepth = 16

    mutating func byte() throws -> UInt8 {
        guard at < bytes.count else { throw CBOR.DecodeError.truncated }
        defer { at += 1 }
        return bytes[at]
    }

    mutating func argument(_ info: UInt8) throws -> UInt64 {
        let width: Int
        switch info {
        case 0...23: return UInt64(info)
        case 24: width = 1
        case 25: width = 2
        case 26: width = 4
        case 27: width = 8
        default: throw CBOR.DecodeError.unsupported(info)
        }
        var n: UInt64 = 0
        for _ in 0..<width { n = (n << 8) | UInt64(try byte()) }
        return n
    }

    mutating func slice(_ count: UInt64) throws -> [UInt8] {
        guard count <= UInt64(bytes.count - at) else { throw CBOR.DecodeError.truncated }
        let end = at + Int(count)
        defer { at = end }
        return Array(bytes[at..<end])
    }

    mutating func value(depth: Int) throws -> CBOR {
        guard depth < Reader.maxDepth else { throw CBOR.DecodeError.unsupported(0xFF) }
        let head = try byte()
        let major = head >> 5, info = head & 0x1F
        switch major {
        case 0: return .uint(try argument(info))
        case 2: return .bytes(Data(try slice(try argument(info))))
        case 3:
            guard let s = String(bytes: try slice(try argument(info)), encoding: .utf8) else {
                throw CBOR.DecodeError.notUTF8
            }
            return .text(s)
        case 4:
            let count = try argument(info)
            guard count <= UInt64(bytes.count - at) else { throw CBOR.DecodeError.truncated }
            return .array(try (0..<count).map { _ in try value(depth: depth + 1) })
        case 5:
            let count = try argument(info)
            guard count <= UInt64(bytes.count - at) else { throw CBOR.DecodeError.truncated }
            var out: [String: CBOR] = [:]
            for _ in 0..<count {
                guard case .text(let key) = try value(depth: depth + 1) else { throw CBOR.DecodeError.nonTextKey }
                out[key] = try value(depth: depth + 1)
            }
            return .map(out)
        case 7 where info == 20: return .bool(false)
        case 7 where info == 21: return .bool(true)
        default: throw CBOR.DecodeError.unsupported(head)
        }
    }
}
