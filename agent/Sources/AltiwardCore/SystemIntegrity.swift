import CryptoKit
import Foundation
import Security

/// One tamper check. The raw values are the wire names in `agent.tamper` and in
/// `agent.health`'s `integrity`.
public enum IntegrityCheck: String, Sendable, CaseIterable, Comparable {
    case launchDaemon = "launch_daemon"
    case codeSignature = "code_signature"
    case settingsManaged = "settings_managed"
    case privilegesTamperProtection = "privileges_tamper_protection"
    case privilegesHook = "privileges_hook"
    /// Someone holding Privileges rights stopped Privileges' agent, which runs their timer.
    /// Checked by the heartbeat, which knows the open sessions.
    case privilegesTimer = "privileges_timer"
    /// Not a standing check: a downgrade is reported once, as `detected`.
    case agentVersion = "agent_version"
    /// Not a standing check: each attempt Privileges' system extension blocked is reported
    /// once, as `detected` (``PrivilegesAuditRecord``).
    case privilegesBlocked = "privileges_blocked"

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

public struct IntegrityResult: Sendable, Equatable {
    public var ok: Bool
    /// What is wrong, for the event and the log. Nil when ok.
    public var problem: String?

    public static let ok = IntegrityResult(ok: true, problem: nil)
    public static func failed(_ problem: String) -> IntegrityResult { IntegrityResult(ok: false, problem: problem) }
}

/// Runs the checks that look at the installed system. Each applies only where it means
/// something: install and signature checks need the daemon running from its bundle, the
/// Privileges checks need Privileges installed. A check that doesn't apply is left out.
/// Paths and lookups are injectable for tests.
public struct SystemIntegrity: Sendable {
    /// Policy keys a local admin could change to their advantage. Each must come from an MDM
    /// profile (forced), not from /Library/Preferences.
    public static let policyKeys = [
        "PermanentAdmins", "ExpiryEnforcement", "ExpiryGraceMinutes", "HookCodeRequirement", "ServerURL",
        "OutOfBandEnforcement", "OutOfBandGraceMinutes",
    ]

    /// Altiward.app, or nil when the daemon isn't running from its bundle (development).
    public var bundleURL: URL?
    public var launchDaemonsDirectory = URL(fileURLWithPath: "/Library/LaunchDaemons")
    /// Whether `com.altiward.agent` has a value for the key, and whether MDM forces it.
    public var hasValue: @Sendable (String) -> Bool
    public var isForced: @Sendable (String) -> Bool
    public var privileges: @Sendable () -> PrivilegesSettings
    public var privilegesInstalled: @Sendable () -> Bool

    public init(
        bundleURL: URL?, hasValue: @escaping @Sendable (String) -> Bool, isForced: @escaping @Sendable (String) -> Bool,
        privileges: @escaping @Sendable () -> PrivilegesSettings, privilegesInstalled: @escaping @Sendable () -> Bool
    ) {
        self.bundleURL = bundleURL
        self.hasValue = hasValue
        self.isForced = isForced
        self.privileges = privileges
        self.privilegesInstalled = privilegesInstalled
    }

    public static func live() -> SystemIntegrity {
        let domain = AgentConfiguration.domain
        let main = Bundle.main
        return SystemIntegrity(
            bundleURL: main.bundleIdentifier == "com.altiward.agent" ? main.bundleURL : nil,
            hasValue: { CFPreferencesCopyAppValue($0 as CFString, domain as CFString) != nil },
            isForced: { CFPreferencesAppValueIsForced($0 as CFString, domain as CFString) },
            privileges: { PrivilegesSettings.current() },
            privilegesInstalled: { DeviceIdentity.current().privilegesVersion != nil })
    }

    public func run() -> [IntegrityCheck: IntegrityResult] {
        var results: [IntegrityCheck: IntegrityResult] = [:]
        results[.settingsManaged] = settingsManaged()
        if let bundleURL {
            let resources = bundleURL.appendingPathComponent("Contents/Resources")
            results[.launchDaemon] = sameFile(
                installed: launchDaemonsDirectory.appendingPathComponent("com.altiward.agent.plist"),
                shipped: resources.appendingPathComponent("com.altiward.agent.plist"))
            results[.codeSignature] = Self.signature(of: bundleURL)
        }
        if privilegesInstalled() {
            let settings = privileges()
            results[.privilegesTamperProtection] =
                settings.systemExtensionEnabled == true
                ? .ok : .failed("Privileges' tamper protection (EnableSystemExtension) is off")
            if let bundleURL {
                // The altiward-hook product, installed as "Altiward": Privileges shows the file's
                // name next to "Run after privilege change".
                let hook = bundleURL.appendingPathComponent("Contents/MacOS/Altiward").path
                results[.privilegesHook] =
                    settings.postChangeExecutablePath == hook
                    ? Self.checksum(settings.postChangeExecutableChecksum, matches: hook)
                    : .failed(
                        "PostChangeExecutablePath is \(settings.postChangeExecutablePath ?? "not set"), not Altiward's hook")
            }
        }
        return results
    }

    /// Privileges runs the hook only when its SHA-256 matches `PostChangeExecutableChecksum`
    /// (compared ignoring case), and otherwise skips it silently. A profile left on an older
    /// agent build's checksum stops every report, so it fails this check.
    static func checksum(_ expected: String?, matches hook: String) -> IntegrityResult {
        guard let expected else { return .ok }
        guard let data = FileManager.default.contents(atPath: hook) else {
            return .failed("cannot read \(hook) to compare it with PostChangeExecutableChecksum")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return actual.caseInsensitiveCompare(expected) == .orderedSame
            ? .ok
            : .failed(
                "PostChangeExecutableChecksum doesn't match Altiward's hook, so Privileges won't run it: "
                    + "use the corp.sap.privileges.plist from this agent's release")
    }

    func settingsManaged() -> IntegrityResult {
        let local = Self.policyKeys.filter { hasValue($0) && !isForced($0) }
        return local.isEmpty ? .ok : .failed("set outside MDM: \(local.joined(separator: ", "))")
    }

    func sameFile(installed: URL, shipped: URL) -> IntegrityResult {
        guard let mine = FileManager.default.contents(atPath: installed.path) else {
            return .failed("\(installed.path) is missing")
        }
        guard let reference = FileManager.default.contents(atPath: shipped.path) else {
            return .failed("\(shipped.path) is missing from the bundle")
        }
        return mine == reference ? .ok : .failed("\(installed.path) differs from the one Altiward installed")
    }

    /// A strict check of the whole bundle, nested code and every architecture included: any
    /// replaced or edited file fails it.
    static func signature(of bundle: URL) -> IntegrityResult {
        var code: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(bundle as CFURL, [], &code)
        guard created == errSecSuccess, let code else {
            return .failed("cannot read the signature of \(bundle.path) (OSStatus \(created))")
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate)
        let status = SecStaticCodeCheckValidity(code, flags, nil)
        guard status == errSecSuccess else {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return .failed("\(bundle.lastPathComponent) fails its code signature check: \(message)")
        }
        return .ok
    }
}

extension AgentVersion {
    /// Compares dotted versions numerically: "0.10.0" is newer than "0.9.1".
    static func isOlder(_ a: String, than b: String) -> Bool {
        let parts = { (v: String) in v.split(separator: ".").map { Int($0) ?? 0 } }
        let (x, y) = (parts(a), parts(b))
        for i in 0..<max(x.count, y.count) {
            let (p, q) = (i < x.count ? x[i] : 0, i < y.count ? y[i] : 0)
            if p != q { return p < q }
        }
        return false
    }
}
