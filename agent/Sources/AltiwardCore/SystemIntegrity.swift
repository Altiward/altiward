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
    /// Enforcement can't confirm Privileges grants against Privileges' own log: the log is
    /// missing, or the system extension stopped recording grants. Checked by the heartbeat,
    /// which knows the enforcement settings and what grants have confirmed.
    case grantConfirmation = "grant_confirmation"
    /// MDM doesn't cap how long a Privileges grant lasts, so a user can choose "Never" and
    /// expiry enforcement has nothing to enforce.
    case privilegesExpiryCap = "privileges_expiry_cap"
    /// Privileges lets rights be renewed while `ExpiryEnforcement` is `enforce`. A renewal
    /// doesn't reach Altiward, so enforcement removes renewed rights at the old expiry.
    case privilegesRenewal = "privileges_renewal"
    /// MDM doesn't force `PostChangeActionOnGrantOnly` off, so Privileges can skip the hook
    /// when rights are given back.
    case privilegesGiveBackHook = "privileges_give_back_hook"
    /// Privileges revokes rights at sign-in or after a clock change, and its exclusion list
    /// leaves out an account in `PermanentAdmins`, which then loses its rights.
    case privilegesRevokeExclusions = "privileges_revoke_exclusions"
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
    /// What is wrong with Privileges' running system extension, or nil when SAP's extension is
    /// running (``PrivilegesExtensionProcess/problem()``). The setting alone isn't protection:
    /// an extension never approved, or killed, leaves it on.
    public var privilegesExtensionProblem: @Sendable () -> String?
    /// From the agent's settings, for the checks that depend on them.
    public var expiryEnforcement: ExpiryEnforcement = .alert
    public var permanentAdmins: Set<String> = []

    public init(
        bundleURL: URL?, hasValue: @escaping @Sendable (String) -> Bool, isForced: @escaping @Sendable (String) -> Bool,
        privileges: @escaping @Sendable () -> PrivilegesSettings, privilegesInstalled: @escaping @Sendable () -> Bool,
        privilegesExtensionProblem: @escaping @Sendable () -> String?
    ) {
        self.bundleURL = bundleURL
        self.hasValue = hasValue
        self.isForced = isForced
        self.privileges = privileges
        self.privilegesInstalled = privilegesInstalled
        self.privilegesExtensionProblem = privilegesExtensionProblem
    }

    public static func live(config: AgentConfiguration) -> SystemIntegrity {
        let domain = AgentConfiguration.domain
        let main = Bundle.main
        var system = SystemIntegrity(
            bundleURL: main.bundleIdentifier == "com.altiward.agent" ? main.bundleURL : nil,
            hasValue: { CFPreferencesCopyAppValue($0 as CFString, domain as CFString) != nil },
            isForced: { CFPreferencesAppValueIsForced($0 as CFString, domain as CFString) },
            privileges: { PrivilegesSettings.current() },
            privilegesInstalled: { DeviceIdentity.current().privilegesVersion != nil },
            privilegesExtensionProblem: { PrivilegesExtensionProcess.problem() })
        system.expiryEnforcement = config.expiryEnforcement
        system.permanentAdmins = config.permanentAdmins
        return system
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
                settings.systemExtensionEnabled != true
                ? .failed("Privileges' tamper protection (EnableSystemExtension) is off")
                : privilegesExtensionProblem().map {
                    .failed("Privileges' tamper protection is on, but its system extension \($0)")
                } ?? .ok
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
            let recommended = Self.settingsChecks(
                settings, expiryEnforcement: expiryEnforcement, permanentAdmins: permanentAdmins)
            results.merge(recommended) { $1 }
        }
        return results
    }

    /// The Privileges settings Altiward relies on and recommends in `corp.sap.privileges.plist`
    /// (#92). Privileges lets the user change any setting its profile doesn't force, so the
    /// expiry cap, renewals and the give-back hook count only when MDM sets them.
    /// `privileges_renewal` applies only while `ExpiryEnforcement` is `enforce`.
    static func settingsChecks(
        _ settings: PrivilegesSettings, expiryEnforcement: ExpiryEnforcement, permanentAdmins: Set<String>
    ) -> [IntegrityCheck: IntegrityResult] {
        var results: [IntegrityCheck: IntegrityResult] = [:]
        results[.privilegesExpiryCap] =
            settings.expiryCapped
            ? .ok
            : .failed(
                "MDM doesn't cap how long a Privileges grant lasts (ExpirationIntervalMax or ExpirationInterval), "
                    + "so a user can choose to keep admin rights with no expiry")
        if expiryEnforcement == .enforce {
            results[.privilegesRenewal] =
                settings.autoRenewalConfigured
                ? .failed(
                    "AutoRenewalProcessPaths renews admin rights, and Altiward sees a renewal only in a log line "
                        + "a user's process writes, so ExpiryEnforcement may remove renewed rights at the original expiry")
                : settings.allowPrivilegeRenewal == false
                    ? .ok
                    : .failed(
                        "MDM doesn't set AllowPrivilegeRenewal to false, and Altiward sees a renewal only in a log line "
                            + "a user's process writes, so ExpiryEnforcement may remove renewed rights at the original expiry")
        }
        results[.privilegesGiveBackHook] =
            switch settings.postChangeActionOnGrantOnly {
            case false: .ok
            case true:
                .failed("PostChangeActionOnGrantOnly is true, so Privileges doesn't run Altiward's hook on a give-back")
            case nil:
                .failed(
                    "MDM doesn't set PostChangeActionOnGrantOnly to false, so a user can stop Privileges "
                        + "running Altiward's hook on a give-back")
            }
        let missing = [
            ("RevokeAtLoginExcludedUsers", "at sign-in", settings.revokeAtLogin, settings.revokeAtLoginExcludedUsers),
            (
                "RevokeAfterTimeChangeExcludedUsers", "after a clock change", settings.revokeAfterTimeChange,
                settings.revokeAfterTimeChangeExcludedUsers
            ),
        ]
        .compactMap { key, when, on, excluded -> String? in
            guard on == true else { return nil }
            let left = permanentAdmins.subtracting(excluded ?? []).sorted()
            guard !left.isEmpty else { return nil }
            return "\(key) leaves out \(left.joined(separator: ", ")), so Privileges removes their admin rights \(when)"
        }
        results[.privilegesRevokeExclusions] =
            missing.isEmpty
            ? .ok : .failed("PermanentAdmins accounts aren't excluded: " + missing.joined(separator: "; "))
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
