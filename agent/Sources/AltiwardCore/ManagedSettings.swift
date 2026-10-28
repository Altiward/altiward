import Foundation
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "settings")

/// The payloads MDM installed for the domains Altiward compares, as read at one time.
public struct MDMPayloadSet: Sendable, Equatable {
    /// In a fixed order (domain, then payload UUID), so two reads of the same profiles are equal.
    public private(set) var payloads: [MDMPayload]
    public var readAt: Date

    public init(_ payloads: [MDMPayload], readAt: Date) {
        self.payloads = payloads.sorted { ($0.domain, $0.payloadUUID) < ($1.domain, $1.payloadUUID) }
        self.readAt = readAt
    }

    /// Whether the two hold the same payloads, whenever they were read.
    public func sameSettings(as other: MDMPayloadSet?) -> Bool { payloads == other?.payloads }

    public func payloads(for domain: String) -> [MDMPayload] { payloads.filter { $0.domain == domain } }

    /// Whether any payload sets Altiward's own settings.
    public var setsAgent: Bool { !payloads(for: AgentConfiguration.domain).isEmpty }

    /// A domain's settings, merged across its payloads. Where two payloads set one key
    /// differently, the first in the set's order wins.
    public func settings(for domain: String) -> [String: PlistValue] {
        var merged: [String: PlistValue] = [:]
        for p in payloads(for: domain) {
            merged.merge(p.settings) { first, _ in first }
        }
        return merged
    }

    /// A domain's settings as ``Preferences``, every one of them forced, as MDM sets it.
    public func preferences(for domain: String) -> Preferences {
        let settings = settings(for: domain)
        return Preferences(values: settings.mapValues(\.propertyList), forced: Set(settings.keys))
    }
}

/// What the agent knows of MDM's payloads after its latest read of the installed profiles.
public struct ManagedSettingsState: Sendable, Equatable {
    /// The payloads in use: the latest clean read, or the stored set from an earlier one.
    public var payloads: MDMPayloadSet?
    /// Why the latest read failed; nil when it worked.
    public var readError: ProfilesReadError?
    /// The latest read worked and showed no MDM enrolment.
    public var notEnrolled = false
    /// The latest read worked and no MDM profile set Altiward's settings, so the earlier set
    /// that did is still in use.
    public var agentPayloadMissing = false
    /// When the payloads in use last changed from one read to the next; nil when they haven't
    /// changed since the agent started.
    public var changedAt: Date?
    /// The latest two reads both worked and gave these payloads.
    public var stable = false

    public init(
        payloads: MDMPayloadSet? = nil, readError: ProfilesReadError? = nil, notEnrolled: Bool = false,
        agentPayloadMissing: Bool = false, changedAt: Date? = nil, stable: Bool = false
    ) {
        self.payloads = payloads
        self.readError = readError
        self.notEnrolled = notEnrolled
        self.agentPayloadMissing = agentPayloadMissing
        self.changedAt = changedAt
        self.stable = stable
    }

    /// Nothing to take the agent's settings from that an admin couldn't have written: no payloads
    /// read now or stored, and the profiles can't be read. The installed agent waits.
    public var mustWait: Bool { payloads == nil && !notEnrolled }

    /// No MDM enrolment and no payloads ever read: the agent's settings come from the
    /// preferences, and the settings check fails.
    public var unmanaged: Bool { payloads == nil && notEnrolled }
}

/// The installed agent's view of MDM's payloads for `com.altiward.agent` and
/// `corp.sap.privileges`, shared by everything that needs them so `profiles` runs only on
/// ``refresh()``: on the heartbeat and when a managed preferences file changes. The last
/// clean read is kept in the store, so a `profiles` that stops working doesn't hand the agent
/// back to settings an admin can write.
public final class ManagedSettings: Sendable {
    let store: AgentStore
    let readDevice: @Sendable () -> Result<ProfilesReading, ProfilesReadError>
    let now: @Sendable () -> Date
    /// One read at a time.
    private let reading = NSLock()
    private let state: OSAllocatedUnfairLock<ManagedSettingsState>
    /// The latest read's payloads when it worked, for ``ManagedSettingsState/stable``.
    private let lastRead = OSAllocatedUnfairLock<MDMPayloadSet?>(initialState: nil)

    public init(
        store: AgentStore,
        readDevice: @escaping @Sendable () -> Result<ProfilesReading, ProfilesReadError> = InstalledProfiles.readDevice,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.store = store
        self.readDevice = readDevice
        self.now = now
        var stored: MDMPayloadSet?
        do {
            stored = try store.mdmPayloads()
        } catch {
            log.error("can't read the stored MDM settings: \(String(describing: error), privacy: .public)")
        }
        state = OSAllocatedUnfairLock(
            initialState: ManagedSettingsState(
                payloads: stored, readError: .malformed("the installed profiles haven't been read yet")))
    }

    /// The state after the latest ``refresh()``, without reading the profiles.
    public var latest: ManagedSettingsState { state.withLock { $0 } }

    /// Reads the installed profiles, once more if the first read fails, and updates the state.
    /// A clean read is stored. A clean read without Altiward's payload, while the set in use
    /// has one, isn't: the agent keeps its settings and the check fails.
    @discardableResult
    public func refresh() -> ManagedSettingsState {
        reading.lock()
        defer { reading.unlock() }
        var result = readDevice()
        if case .failure = result { result = readDevice() }
        let now = now()

        var next = state.withLock { $0 }
        next.readError = nil
        next.notEnrolled = false
        next.agentPayloadMissing = false
        switch result {
        case .failure(let error):
            next.readError = error
            next.stable = false
            lastRead.withLock { $0 = nil }
        case .success(.notEnrolled):
            next.notEnrolled = true
            next.stable = false
            lastRead.withLock { $0 = nil }
        case .success(.enrolled(let payloads)):
            let set = MDMPayloadSet(payloads, readAt: now)
            let previous = lastRead.withLock { last in
                defer { last = set }
                return last
            }
            if !set.setsAgent, next.payloads?.setsAgent == true {
                next.agentPayloadMissing = true
                next.stable = false
            } else {
                if !set.sameSettings(as: next.payloads) { next.changedAt = now }
                next.stable = set.sameSettings(as: previous)
                next.payloads = set
                do {
                    try store.saveMDMPayloads(set)
                } catch {
                    log.error("can't store the MDM settings: \(String(describing: error), privacy: .public)")
                }
            }
        }
        let settled = next
        state.withLock { $0 = settled }
        return settled
    }

    /// The agent's settings from the state: from MDM's payloads, or, on a Mac with no MDM
    /// enrolment and no payloads ever read, from the preferences. Nil while it must wait.
    /// `ALTIWARD_*` overrides never apply.
    public static func configuration(_ state: ManagedSettingsState) -> AgentConfiguration? {
        if let payloads = state.payloads {
            return AgentConfiguration.load(environment: [:], preferences: payloads.preferences(for: AgentConfiguration.domain))
        }
        return state.unmanaged ? AgentConfiguration.load(environment: [:]) : nil
    }

    /// The settings to restart with: only once two reads in a row agree, so one odd read
    /// doesn't restart the agent. Never runs `profiles`.
    public func settledConfiguration() -> AgentConfiguration? {
        let s = latest
        guard s.stable || s.unmanaged else { return nil }
        return Self.configuration(s)
    }

    /// The Privileges settings the agent's own logic uses: from MDM's payloads, or the
    /// preferences when there are none.
    public func privilegesSettings() -> PrivilegesSettings {
        guard let payloads = latest.payloads else { return PrivilegesSettings.current() }
        return PrivilegesSettings.settings(from: payloads.preferences(for: PrivilegesSettings.domain))
    }
}

// MARK: The managed preferences files

/// Reads the files macOS answers managed preferences from: `/Library/Managed Preferences/
/// <domain>.plist` for the device, and a user folder's copy of it and that folder's
/// `complete.plist`, which ManagedClient writes for each user who signs in. Root can write
/// all of them, which is why they are compared with MDM's payloads.
public struct ManagedPreferenceFiles: Sendable {
    public enum Read: Sendable, Equatable {
        case missing
        case unreadable
        case settings([String: PlistValue])
    }

    public var root: URL

    public init(root: URL = URL(fileURLWithPath: "/Library/Managed Preferences")) {
        self.root = root
    }

    public func devicePath(_ domain: String) -> String { root.appendingPathComponent("\(domain).plist").path }
    public func userPath(_ user: String, _ domain: String) -> String {
        root.appendingPathComponent(user).appendingPathComponent("\(domain).plist").path
    }
    public func completePath(_ user: String) -> String {
        root.appendingPathComponent(user).appendingPathComponent("complete.plist").path
    }

    func file(_ path: String) -> Read {
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        guard let data = FileManager.default.contents(atPath: path),
            let object = try? PropertyListSerialization.propertyList(from: data, format: nil),
            let settings = PlistValue.dictionary(object)
        else { return .unreadable }
        return .settings(settings)
    }

    /// A domain's entries in `complete.plist`, which holds `domain => key => {…, value}`.
    func complete(_ path: String, domain: String) -> Read {
        let read = file(path)
        guard case .settings(let all) = read else { return read }
        guard let entry = all[domain] else { return .missing }
        guard case .dictionary(let keys) = entry else { return .unreadable }
        var settings: [String: PlistValue] = [:]
        for (key, item) in keys {
            guard case .dictionary(let fields) = item, let value = fields["value"] else { return .unreadable }
            settings[key] = value
        }
        return .settings(settings)
    }
}

/// A setting that differs between a managed preferences file and MDM's payloads. Names only:
/// values such as `EnrollmentToken` are secrets.
public struct SettingsMismatch: Sendable, Equatable, Comparable {
    public enum Kind: String, Sendable {
        /// MDM sets the key to another value.
        case changed
        /// MDM sets the key; the file doesn't have it.
        case removed
        /// The file has a key no MDM payload sets.
        case added
        /// The file can't be read as settings.
        case unreadable
    }

    public var path: String
    public var domain: String
    /// Nil when the whole file is unreadable.
    public var key: String?
    public var kind: Kind

    public static func < (a: Self, b: Self) -> Bool {
        (a.path, a.domain, a.key ?? "", a.kind.rawValue) < (b.path, b.domain, b.key ?? "", b.kind.rawValue)
    }

    /// Compares a file's settings for `domain` with the payloads MDM installed for it, both
    /// ways: every key a payload sets must be in the file with a value equal to one payload's,
    /// and every key in the file must be one a payload sets. `Payload*` keys are left out on
    /// both sides, but the file's `PayloadUUID` must be one of the payloads'.
    static func compare(_ file: ManagedPreferenceFiles.Read, path: String, domain: String, payloads: [MDMPayload])
        -> [SettingsMismatch]
    {
        let settings: [String: PlistValue]
        switch file {
        case .missing: settings = [:]
        case .unreadable: return [SettingsMismatch(path: path, domain: domain, key: nil, kind: .unreadable)]
        case .settings(let s): settings = s
        }
        var found: [SettingsMismatch] = []
        let expected = payloads.reduce(into: [String: [PlistValue]]()) { all, p in
            for (key, value) in p.settings { all[key, default: []].append(value) }
        }
        for (key, values) in expected {
            guard let value = settings[key] else {
                found.append(SettingsMismatch(path: path, domain: domain, key: key, kind: .removed))
                continue
            }
            if !values.contains(value) {
                found.append(SettingsMismatch(path: path, domain: domain, key: key, kind: .changed))
            }
        }
        for key in settings.keys where !key.hasPrefix("Payload") && expected[key] == nil {
            found.append(SettingsMismatch(path: path, domain: domain, key: key, kind: .added))
        }
        if let uuid = settings["PayloadUUID"] {
            let known = Set(payloads.map(\.payloadUUID))
            guard case .string(let s) = uuid, known.contains(s.uppercased()) else {
                found.append(
                    SettingsMismatch(
                        path: path, domain: domain, key: "PayloadUUID", kind: payloads.isEmpty ? .added : .changed))
                return found.sorted()
            }
        }
        return found.sorted()
    }
}

/// The `settings_managed` comparison in the installed agent: the device's managed preferences
/// files always, and the copies in the folders of users signed in at the login window (after
/// ``signInGrace``, while ManagedClient writes them). Other users' folders are left alone: a
/// folder keeps the settings of its user's last sign-in, and takes the current ones at the next.
public struct ManagedSettingsCheck: Sendable {
    /// How long after a sign-in its folder is left alone.
    public static let signInGrace: TimeInterval = 120
    /// How long after MDM's payloads change differences are held, while macOS rewrites the files.
    public static let profileChangeGrace: TimeInterval = 300

    public var files: ManagedPreferenceFiles
    /// Users signed in at the login window now, with when they signed in.
    public var signedIn: @Sendable () -> [String: Date]
    /// MDM payloads installed for one user (user channel), read only when a user's folder
    /// differs from the device's payloads.
    public var userPayloads: @Sendable (String) -> Result<[MDMPayload], ProfilesReadError>
    public var now: @Sendable () -> Date

    public init(
        files: ManagedPreferenceFiles = ManagedPreferenceFiles(),
        signedIn: @escaping @Sendable () -> [String: Date],
        userPayloads: @escaping @Sendable (String) -> Result<[MDMPayload], ProfilesReadError> = InstalledProfiles.readUser,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.files = files
        self.signedIn = signedIn
        self.userPayloads = userPayloads
        self.now = now
    }

    public static let domains = [AgentConfiguration.domain, PrivilegesSettings.domain]

    public func result(_ state: ManagedSettingsState) -> IntegrityResult {
        guard let payloads = state.payloads else {
            if state.notEnrolled {
                return IntegrityResult(
                    ok: false, problem: "this Mac isn't enrolled in MDM, so no MDM profile sets Altiward's settings",
                    findings: ["not enrolled in MDM"])
            }
            return IntegrityResult(
                ok: false,
                problem: "can't read the installed profiles (\(state.readError?.description ?? "not read")), "
                    + "and no MDM settings are stored",
                findings: ["profiles unreadable"])
        }

        var notes: [String] = []
        var findings: Set<String> = []
        let stored = "the MDM settings read \(AltiwardJSON.format(payloads.readAt))"
        if let error = state.readError {
            notes.append("can't read the installed profiles (\(error)), so compared with \(stored)")
            findings.insert("profiles unreadable")
        } else if state.notEnrolled {
            notes.append("the installed profiles show no MDM enrolment now, so compared with \(stored)")
            findings.insert("not enrolled in MDM")
        } else if state.agentPayloadMissing {
            notes.append("no MDM profile sets com.altiward.agent now, so the agent keeps \(stored)")
            findings.insert("no com.altiward.agent payload")
        }
        if !payloads.setsAgent {
            notes.append("no MDM profile sets com.altiward.agent")
            findings.insert("no com.altiward.agent payload")
        }

        let mismatches = self.mismatches(payloads)
        findings.formUnion(mismatches.map { "\($0.domain) \($0.key ?? "(file)")" })
        if !mismatches.isEmpty {
            notes.append("managed settings differ from MDM's profiles: " + Self.describe(mismatches))
        }
        guard !notes.isEmpty else { return .ok }
        // Only differences, just after MDM changed its payloads: macOS may still be rewriting the files.
        if notes.count == 1, !mismatches.isEmpty, let changed = state.changedAt,
            now().timeIntervalSince(changed) < Self.profileChangeGrace
        {
            return IntegrityResult(ok: true, problem: nil, held: true)
        }
        return IntegrityResult(ok: false, problem: notes.joined(separator: "; "), findings: findings.sorted())
    }

    func mismatches(_ payloads: MDMPayloadSet) -> [SettingsMismatch] {
        var found: [SettingsMismatch] = []
        for domain in Self.domains {
            found += SettingsMismatch.compare(
                files.file(files.devicePath(domain)), path: files.devicePath(domain), domain: domain,
                payloads: payloads.payloads(for: domain))
        }
        let now = now()
        for (user, since) in signedIn().sorted(by: { $0.key < $1.key })
        where now.timeIntervalSince(since) >= Self.signInGrace && Self.plainName(user) {
            var forUser = userMismatches(user, payloads.payloads)
            if !forUser.isEmpty, case .success(let own) = userPayloads(user), !own.isEmpty {
                forUser = userMismatches(user, payloads.payloads + own)
            }
            found += forUser
        }
        return found
    }

    private func userMismatches(_ user: String, _ payloads: [MDMPayload]) -> [SettingsMismatch] {
        Self.domains.flatMap { domain in
            let mine = payloads.filter { $0.domain == domain }
            return SettingsMismatch.compare(
                files.file(files.userPath(user, domain)), path: files.userPath(user, domain), domain: domain,
                payloads: mine)
                + SettingsMismatch.compare(
                    files.complete(files.completePath(user), domain: domain), path: files.completePath(user),
                    domain: domain, payloads: mine)
        }
    }

    /// A short name that is safe as a folder name.
    static func plainName(_ user: String) -> Bool {
        !user.isEmpty && user != "." && user != ".." && !user.contains("/")
    }

    /// "com.altiward.agent ServerURL (changed), corp.sap.privileges EnableSystemExtension
    /// (removed) in /Library/Managed Preferences; … in /Library/Managed Preferences/jdoe/complete.plist"
    static func describe(_ mismatches: [SettingsMismatch]) -> String {
        var byPath: [(String, [SettingsMismatch])] = []
        for m in mismatches.sorted() {
            let folder = (m.path as NSString).lastPathComponent == "complete.plist"
                ? m.path : (m.path as NSString).deletingLastPathComponent
            if let i = byPath.firstIndex(where: { $0.0 == folder }) {
                byPath[i].1.append(m)
            } else {
                byPath.append((folder, [m]))
            }
        }
        return byPath.map { folder, items in
            items.map { "\($0.domain) \($0.key ?? "file") (\($0.kind.rawValue))" }.joined(separator: ", ")
                + " in \(folder)"
        }.joined(separator: "; ")
    }
}
