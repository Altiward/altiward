import Foundation

/// Snapshot of the SAP Privileges settings Altiward cares about, read from the
/// `corp.sap.privileges` preference domain (normally delivered by MDM profile).
public struct PrivilegesSettings: Sendable, Equatable {
    public var postChangeExecutablePath: String?
    /// The SHA-256 Privileges requires of the hook before it runs it, as Privileges reads it:
    /// only when MDM forces both this key and `PostChangeExecutablePath`. Nil means
    /// Privileges runs the hook without checking it.
    public var postChangeExecutableChecksum: String?
    public var passReasonToExecutable: Bool
    public var expirationIntervalMinutes: Int?
    public var expirationIntervalMaxMinutes: Int?
    public var enforcePrivileges: String?
    public var systemExtensionEnabled: Bool?
    /// `AdminBudget` (Privileges 2.7+): the most minutes a day a user may hold admin rights.
    /// Reported only; Privileges enforces it before a grant.
    public var adminBudgetMinutes: Int?

    public init(
        postChangeExecutablePath: String? = nil,
        postChangeExecutableChecksum: String? = nil,
        passReasonToExecutable: Bool = false,
        expirationIntervalMinutes: Int? = nil,
        expirationIntervalMaxMinutes: Int? = nil,
        enforcePrivileges: String? = nil,
        systemExtensionEnabled: Bool? = nil,
        adminBudgetMinutes: Int? = nil
    ) {
        self.postChangeExecutablePath = postChangeExecutablePath
        self.postChangeExecutableChecksum = postChangeExecutableChecksum
        self.passReasonToExecutable = passReasonToExecutable
        self.expirationIntervalMinutes = expirationIntervalMinutes
        self.expirationIntervalMaxMinutes = expirationIntervalMaxMinutes
        self.enforcePrivileges = enforcePrivileges
        self.systemExtensionEnabled = systemExtensionEnabled
        self.adminBudgetMinutes = adminBudgetMinutes
    }

    public static let domain = "corp.sap.privileges"

    /// Reads managed and system-wide values. Never writes to the domain.
    public static func current() -> PrivilegesSettings {
        settings(from: Preferences(domain: domain))
    }

    static func settings(from p: Preferences) -> PrivilegesSettings {
        let checksumApplies = p.isForced("PostChangeExecutablePath") && p.isForced("PostChangeExecutableChecksum")
        return PrivilegesSettings(
            postChangeExecutablePath: p.string("PostChangeExecutablePath"),
            postChangeExecutableChecksum: checksumApplies
                ? p.string("PostChangeExecutableChecksum").flatMap { $0.isEmpty ? nil : $0 } : nil,
            passReasonToExecutable: p.bool("PassReasonToExecutable") ?? false,
            expirationIntervalMinutes: p.int("ExpirationInterval"),
            expirationIntervalMaxMinutes: p.int("ExpirationIntervalMax"),
            enforcePrivileges: p.string("EnforcePrivileges"),
            systemExtensionEnabled: p.bool("EnableSystemExtension"),
            adminBudgetMinutes: p.int("AdminBudget").flatMap { $0 > 0 ? $0 : nil })
    }

    /// The expiry Privileges will apply to a grant made at `grantedAt`, and where it came from.
    /// `ExpirationInterval` wins when both are set, matching Privileges. 0 means no expiry.
    /// Otherwise the duration the user picked, Privileges' `timer` (``PrivilegesTimer``),
    /// counts when it is later than the grant, capped by `ExpirationIntervalMax`.
    public func expiry(grantedAt: Date, timer: Date? = nil) -> (date: Date, basis: String)? {
        if let m = expirationIntervalMinutes {
            return m > 0 ? (grantedAt.addingTimeInterval(TimeInterval(m * 60)), "ExpirationInterval") : nil
        }
        var cap: Date?
        if let m = expirationIntervalMaxMinutes, m > 0 {
            cap = grantedAt.addingTimeInterval(TimeInterval(m * 60))
        }
        if let timer, timer > grantedAt, cap.map({ timer <= $0 }) ?? true {
            return (timer, "PrivilegesTimer")
        }
        return cap.map { ($0, "ExpirationIntervalMax") }
    }

    var healthDetail: JSONValue {
        [
            "post_change_hook_configured": .bool(postChangeExecutablePath != nil),
            "pass_reason_to_executable": .bool(passReasonToExecutable),
            "expiration_interval_minutes": expirationIntervalMinutes.map { .number(Double($0)) } ?? .null,
            "expiration_interval_max_minutes": expirationIntervalMaxMinutes.map { .number(Double($0)) } ?? .null,
            "enforce_privileges": .optional(enforcePrivileges),
            "system_extension_enabled": systemExtensionEnabled.map(JSONValue.bool) ?? .null,
            "admin_budget_minutes": adminBudgetMinutes.map { .number(Double($0)) } ?? .null,
        ]
    }
}

/// What the daemon does when admin rights outlive their expiry plus the grace period.
public enum ExpiryEnforcement: String, Sendable, Equatable {
    /// Ignore expiry.
    case off
    /// Report `elevation.overdue` once per session; leave the rights in place.
    case alert
    /// Remove the user from `admin` and report `elevation.expired_enforced`.
    case enforce
}

/// What the daemon does about admin rights nobody granted (`admin.out_of_band`) once they
/// have lasted the grace period.
public enum OutOfBandEnforcement: String, Sendable, Equatable {
    /// Report them; leave the rights in place.
    case alert
    /// Remove the user from `admin` and report `admin.out_of_band_removed`, unless that
    /// would leave the Mac without an admin.
    case enforce
}

/// Agent settings from the `com.altiward.agent` domain (MDM profile), with
/// `ALTIWARD_*` environment overrides for local development.
public struct AgentConfiguration: Sendable, Equatable {
    public var serverURL: URL?
    public var enrollmentToken: String?
    public var dataDirectory: URL
    public var heartbeatInterval: TimeInterval
    public var flushInterval: TimeInterval
    /// Accounts expected to hold standing admin rights (IT, break-glass); never reported out-of-band.
    public var permanentAdmins: Set<String>
    /// Short name → corporate UPN. Typically filled from an MDM variable.
    public var userPrincipalNames: [String: String]
    /// Designated-requirement string the hook helper must satisfy to talk to the daemon.
    public var hookCodeRequirement: String?
    public var expiryEnforcement: ExpiryEnforcement
    /// How long past expiry rights may persist before expiry enforcement acts.
    public var expiryGracePeriod: TimeInterval
    public var outOfBandEnforcement: OutOfBandEnforcement
    /// How long rights nobody granted may last, from when they were raised, before
    /// out-of-band enforcement acts.
    public var outOfBandGracePeriod: TimeInterval
    /// Seconds between polls for remote commands.
    public var commandPollInterval: TimeInterval

    public static let domain = "com.altiward.agent"
    public static let defaultDataDirectory = URL(fileURLWithPath: "/Library/Application Support/Altiward")

    public init(
        serverURL: URL? = nil,
        enrollmentToken: String? = nil,
        dataDirectory: URL = defaultDataDirectory,
        heartbeatInterval: TimeInterval = 300,
        flushInterval: TimeInterval = 60,
        permanentAdmins: Set<String> = [],
        userPrincipalNames: [String: String] = [:],
        hookCodeRequirement: String? = nil,
        expiryEnforcement: ExpiryEnforcement = .alert,
        expiryGracePeriod: TimeInterval = 300,
        outOfBandEnforcement: OutOfBandEnforcement = .alert,
        outOfBandGracePeriod: TimeInterval = 300,
        commandPollInterval: TimeInterval = 60
    ) {
        self.serverURL = serverURL
        self.enrollmentToken = enrollmentToken
        self.dataDirectory = dataDirectory
        self.heartbeatInterval = heartbeatInterval
        self.flushInterval = flushInterval
        self.permanentAdmins = permanentAdmins
        self.userPrincipalNames = userPrincipalNames
        self.hookCodeRequirement = hookCodeRequirement
        self.expiryEnforcement = expiryEnforcement
        self.expiryGracePeriod = expiryGracePeriod
        self.outOfBandEnforcement = outOfBandEnforcement
        self.outOfBandGracePeriod = outOfBandGracePeriod
        self.commandPollInterval = commandPollInterval
    }

    /// The settings that differ from `other`, by their profile key, sorted. Names only: a
    /// value such as `EnrollmentToken` is a secret, so it never reaches the log.
    public func changedSettings(_ other: AgentConfiguration) -> [String] {
        let differs: [(String, Bool)] = [
            ("ServerURL", serverURL != other.serverURL),
            ("EnrollmentToken", enrollmentToken != other.enrollmentToken),
            ("ALTIWARD_DATA_DIR", dataDirectory != other.dataDirectory),
            ("HeartbeatInterval", heartbeatInterval != other.heartbeatInterval),
            ("FlushInterval", flushInterval != other.flushInterval),
            ("PermanentAdmins", permanentAdmins != other.permanentAdmins),
            ("UserPrincipalNames", userPrincipalNames != other.userPrincipalNames),
            ("HookCodeRequirement", hookCodeRequirement != other.hookCodeRequirement),
            ("ExpiryEnforcement", expiryEnforcement != other.expiryEnforcement),
            ("ExpiryGraceMinutes", expiryGracePeriod != other.expiryGracePeriod),
            ("OutOfBandEnforcement", outOfBandEnforcement != other.outOfBandEnforcement),
            ("OutOfBandGraceMinutes", outOfBandGracePeriod != other.outOfBandGracePeriod),
            ("CommandPollInterval", commandPollInterval != other.commandPollInterval),
        ]
        return differs.filter(\.1).map(\.0).sorted()
    }

    public static func load(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        preferences p: Preferences = Preferences(domain: domain)
    ) -> AgentConfiguration {
        var c = AgentConfiguration()
        c.serverURL = (environment["ALTIWARD_SERVER_URL"] ?? p.string("ServerURL")).flatMap(URL.init(string:))
        c.enrollmentToken = environment["ALTIWARD_TOKEN"] ?? p.string("EnrollmentToken")
        if let dir = environment["ALTIWARD_DATA_DIR"] {
            // Say it is a folder: without that the URL gains a trailing slash once the folder exists,
            // and the daemon would read its own new data directory as a changed setting.
            c.dataDirectory = URL(fileURLWithPath: dir, isDirectory: true)
        }
        if let s = environment["ALTIWARD_HEARTBEAT_SECONDS"].flatMap(TimeInterval.init) ?? p.int("HeartbeatInterval").map(TimeInterval.init) {
            c.heartbeatInterval = max(30, s)
        }
        if let s = p.int("FlushInterval") {
            c.flushInterval = max(10, TimeInterval(s))
        }
        c.permanentAdmins = Set(p.strings("PermanentAdmins") ?? [])
        c.userPrincipalNames = p.stringMap("UserPrincipalNames") ?? [:]
        c.hookCodeRequirement = p.string("HookCodeRequirement")
        // An unrecognised value keeps the default rather than silently turning expiry enforcement off.
        if let mode = p.string("ExpiryEnforcement").flatMap(ExpiryEnforcement.init(rawValue:)) {
            c.expiryEnforcement = mode
        }
        if let s = p.int("CommandPollInterval") {
            c.commandPollInterval = max(15, TimeInterval(s))
        }
        if let m = p.int("ExpiryGraceMinutes") {
            c.expiryGracePeriod = TimeInterval(max(0, m)) * 60
        }
        // An unrecognised value keeps the default, alert, rather than removing anyone's rights
        // on a setting nobody meant.
        if let mode = p.string("OutOfBandEnforcement").flatMap(OutOfBandEnforcement.init(rawValue:)) {
            c.outOfBandEnforcement = mode
        }
        // At least a minute, so a grant whose hook is still on its way isn't removed.
        if let m = p.int("OutOfBandGraceMinutes") {
            c.outOfBandGracePeriod = TimeInterval(max(1, m)) * 60
        }
        return c
    }

    public func upn(for user: String) -> String? {
        userPrincipalNames[user]
    }
}

/// Thin typed reader over CFPreferences. `CFPreferencesCopyAppValue` returns managed
/// (MDM-forced) values first, then /Library/Preferences, which is what the daemon wants.
/// Tests build one from a dictionary.
public struct Preferences: Sendable {
    private let lookup: @Sendable (String) -> Any?
    private let forced: @Sendable (String) -> Bool

    public init(domain: String) {
        lookup = { CFPreferencesCopyAppValue($0 as CFString, domain as CFString) }
        forced = { CFPreferencesAppValueIsForced($0 as CFString, domain as CFString) }
    }

    public init(values: [String: Any], forced: Set<String> = []) {
        nonisolated(unsafe) let values = values
        lookup = { values[$0] }
        self.forced = { forced.contains($0) }
    }

    /// Whether an MDM profile sets the key.
    func isForced(_ key: String) -> Bool { forced(key) }

    func string(_ key: String) -> String? { lookup(key) as? String }
    func bool(_ key: String) -> Bool? { lookup(key) as? Bool }
    func int(_ key: String) -> Int? { (lookup(key) as? NSNumber)?.intValue }
    func strings(_ key: String) -> [String]? { lookup(key) as? [String] }
    func stringMap(_ key: String) -> [String: String]? { lookup(key) as? [String: String] }
}
