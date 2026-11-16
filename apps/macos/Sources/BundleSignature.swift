// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import Security

/// The macOS half of the tab trust chain (§5.4 (2)): the app installed for a bundle id must
/// satisfy `anchor apple generic and certificate leaf[subject.OU] = <team>` (a Developer ID or
/// App Store signature by that team) and carry that identifier.
enum BundleSignature {
    /// The bundle's location when it passes, nil otherwise. tray-core has already checked both
    /// strings (`[A-Za-z0-9-.]` and `[A-Z0-9]{10}`), so neither can change the requirement text.
    static func installed(bundleID: String, teamID: String) -> URL? {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return nil }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        let text = "identifier \"\(bundleID)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { return nil }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess ? url : nil
    }
}
