// SPDX-License-Identifier: MIT OR Apache-2.0
import CTrayCore
import Foundation

/// tray-core, through crates/tray-ffi's C ABI. Verification, discovery and the panel URL are all
/// decided in Rust; this only moves bytes across and decodes the CBOR reply.
public enum TrayCore {
    /// The publishers a host trusts, as the CBOR list tray-ffi reads.
    public struct Publishers: Equatable {
        let cbor: Data
    }

    /// The list a shipped host pins (owner decision D-C), from tray-core's `keys/`.
    public static func avarokPublishers() -> Publishers {
        Publishers(cbor: take(tray_core_avarok_publishers()))
    }

    /// An explicit list, such as the contract's TEST publisher in the test suite.
    public static func publishers(_ list: [(name: String, keyHex: String)]) -> Publishers {
        let pairs = list.map { CBOR.array([.text($0.name), .text($0.keyHex)]) }
        return Publishers(cbor: CBOR.array(pairs).encoded())
    }

    public struct Discovery: Equatable {
        public let tabs: [VerifiedTab]
        public let refused: [RefusedTab]
        /// The right-click menu for these tabs, from tray-core's menu model.
        public let menu: [MenuEntry]
    }

    /// What the menu shows about the host itself.
    public struct Host: Equatable {
        public let name: String
        public let startsAtLogin: Bool
        public init(name: String, startsAtLogin: Bool) {
            self.name = name
            self.startsAtLogin = startsAtLogin
        }
    }

    public enum Failure: Error, Equatable {
        /// tray-core could not read the directory or the publisher list.
        case refused(String)
        case malformedReply(String)
    }

    /// The OS code-signature check: (bundle id, team id) → whether the installed bundle is
    /// signed by that team. Called synchronously, during `tabs`, once per signed manifest.
    public typealias CodeSignatureCheck = (_ bundleID: String, _ teamID: String) -> Bool

    public static func tabs(in directory: URL, trusting publishers: Publishers, host: Host, codeSignature: @escaping CodeSignatureCheck) throws -> Discovery {
        let box = Unmanaged.passRetained(CheckBox(codeSignature))
        defer { box.release() }
        let path = Array(directory.path.utf8), name = Array(host.name.utf8)
        let pinned = [UInt8](publishers.cbor)
        let reply = take(path.withUnsafeBufferPointer { dir in
            pinned.withUnsafeBufferPointer { pin in
                name.withUnsafeBufferPointer { hn in
                    tray_core_tabs(dir.baseAddress, dir.count, pin.baseAddress, pin.count, host.startsAtLogin,
                                   hn.baseAddress, hn.count, { ctx, b, bl, t, tl in
                        guard let ctx, let bundle = utf8(b, bl), let team = utf8(t, tl) else { return false }
                        return Unmanaged<CheckBox>.fromOpaque(ctx).takeUnretainedValue().check(bundle, team)
                    }, box.toOpaque())
                }
            }
        })
        let root: CBOR
        do { root = try CBOR.decode(reply) } catch { throw Failure.malformedReply("\(error)") }
        if let why = root["error"]?.text { throw Failure.refused(why) }
        do {
            let tabs = try (root["tabs"]?.array ?? []).map(VerifiedTab.init(cbor:))
            let refused = (root["refused"]?.array ?? []).compactMap { r -> RefusedTab? in
                guard let file = r["file"]?.text, let reason = r["reason"]?.text else { return nil }
                return RefusedTab(file: file, reason: reason)
            }
            guard root["tabs"]?.array != nil, root["refused"]?.array != nil, let menu = root["menu"]?.array else {
                throw Failure.malformedReply("no tabs, refused or menu list")
            }
            return Discovery(tabs: tabs, refused: refused, menu: try menu.map(MenuEntry.init(cbor:)))
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.malformedReply("\(error)")
        }
    }

    /// The web panel URL from one stdout line of the agent this host launched, or nil when the
    /// line carries no token.
    public static func panelURL(port: UInt16, path: String, line: String) -> URL? {
        let p = Array(path.utf8), l = Array(line.utf8)
        let bytes = take(p.withUnsafeBufferPointer { pp in
            l.withUnsafeBufferPointer { lp in tray_core_panel_url(port, pp.baseAddress, pp.count, lp.baseAddress, lp.count) }
        })
        guard !bytes.isEmpty, let text = String(data: bytes, encoding: .utf8) else { return nil }
        return URL(string: text)
    }

    private static func take(_ buffer: TrayBuffer) -> Data {
        defer { tray_core_buffer_free(buffer) }
        guard let ptr = buffer.ptr, buffer.len > 0 else { return Data() }
        return Data(bytes: ptr, count: buffer.len)
    }
}

private final class CheckBox {
    let check: TrayCore.CodeSignatureCheck
    init(_ check: @escaping TrayCore.CodeSignatureCheck) { self.check = check }
}

private func utf8(_ ptr: UnsafePointer<UInt8>?, _ len: Int) -> String? {
    guard let ptr else { return len == 0 ? "" : nil }
    return String(bytes: UnsafeBufferPointer(start: ptr, count: len), encoding: .utf8)
}

extension CBOR {
    /// Encodes the text-and-array subset the publisher list needs.
    func encoded() -> Data {
        var out = [UInt8]()
        func head(_ major: UInt8, _ n: Int) {
            let n = UInt64(n)
            switch n {
            case 0...23: out.append(major << 5 | UInt8(n))
            case 24...0xFF: out += [major << 5 | 24, UInt8(n)]
            case 0x100...0xFFFF: out += [major << 5 | 25, UInt8(n >> 8), UInt8(n & 0xFF)]
            default: out += [major << 5 | 26] + (0..<4).reversed().map { UInt8((n >> ($0 * 8)) & 0xFF) }
            }
        }
        func write(_ v: CBOR) {
            switch v {
            case .text(let s): head(3, s.utf8.count); out += Array(s.utf8)
            case .array(let a): head(4, a.count); a.forEach(write)
            default: preconditionFailure("only text and arrays are encoded")
            }
        }
        write(self)
        return Data(out)
    }
}
