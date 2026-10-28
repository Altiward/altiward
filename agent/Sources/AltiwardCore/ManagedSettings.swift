import CryptoKit
import Foundation
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "settings")

/// The preference domains whose MDM payloads the agent reads and compares.
public enum ManagedDomains {
    public static let all = [AgentConfiguration.domain, PrivilegesSettings.domain]
}

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

/// What this Mac enrolled with: the server of each key record, and a digest of the enrolment
/// token, for checking stored settings against at start.
public struct EnrolmentRecord: Sendable, Equatable {
    public var serverURLs: Set<String>
    /// SHA-256 of the token, hex; nil for an enrolment from before the agent kept it.
    public var tokenDigest: String?

    public init(serverURLs: Set<String>, tokenDigest: String?) {
        self.serverURLs = serverURLs
        self.tokenDigest = tokenDigest
    }

    public static func digest(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Why stored settings can't be used with this enrolment; nil when they can. A stored set
    /// is used only while the profiles can't be read, so it must lead to the server and token
    /// this Mac enrolled with.
    public func refusal(of stored: MDMPayloadSet) -> String? {
        guard !serverURLs.isEmpty else { return nil }
        let c = AgentConfiguration.load(environment: [:], preferences: stored.preferences(for: AgentConfiguration.domain))
        guard let url = c.serverURL?.absoluteString, serverURLs.contains(url) else {
            return "the stored ServerURL isn't the server this Mac enrolled with"
        }
        if let tokenDigest, let token = c.enrollmentToken, Self.digest(token) != tokenDigest {
            return "the stored EnrollmentToken isn't the one this Mac enrolled with"
        }
        return nil
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
    /// When this agent last saw MDM's payloads change between two of its own clean reads; nil
    /// when it hasn't. A difference from the stored set doesn't count.
    public var changedAt: Date?
    /// The payloads before that change, for telling files macOS hasn't rewritten yet from new
    /// content.
    public var previous: MDMPayloadSet?
    /// The latest two reads both worked and gave these payloads.
    public var stable = false
    /// Why the stored set wasn't used at start.
    public var storedRefused: String?

    public init(
        payloads: MDMPayloadSet? = nil, readError: ProfilesReadError? = nil, notEnrolled: Bool = false,
        agentPayloadMissing: Bool = false, changedAt: Date? = nil, previous: MDMPayloadSet? = nil,
        stable: Bool = false, storedRefused: String? = nil
    ) {
        self.payloads = payloads
        self.readError = readError
        self.notEnrolled = notEnrolled
        self.agentPayloadMissing = agentPayloadMissing
        self.changedAt = changedAt
        self.previous = previous
        self.stable = stable
        self.storedRefused = storedRefused
    }

    /// Nothing to take the agent's settings from that an admin couldn't have written: no payloads
    /// read now or usable from the store, and the profiles can't be read. The installed agent waits.
    public var mustWait: Bool { payloads == nil && !notEnrolled }

    /// No MDM enrolment and no payloads ever read: the agent's settings come from the
    /// preferences, and the settings check fails.
    public var unmanaged: Bool { payloads == nil && notEnrolled }

    /// Whether MDM's payloads just changed, so differences in the files may be macOS still
    /// rewriting them.
    public func inProfileChange(at now: Date) -> Bool {
        guard let changedAt, previous != nil else { return false }
        return now.timeIntervalSince(changedAt) < ManagedSettingsCheck.profileChangeGrace
    }

    /// Whether to read the profiles again soon, while the payloads settle: a clean read that
    /// isn't confirmed by a second yet, or differences held after a profile change. Never with
    /// a read that failed, showed no enrolment or lost Altiward's payload (the heartbeat looks
    /// again), and never longer than ``ManagedSettingsCheck/profileChangeGrace`` after
    /// `since`, when the rechecks began.
    public static func needsRecheck(_ s: ManagedSettingsState, since: Date, now: Date) -> Bool {
        guard s.readError == nil, !s.notEnrolled, !s.agentPayloadMissing, s.payloads != nil,
            now.timeIntervalSince(since) < ManagedSettingsCheck.profileChangeGrace
        else { return false }
        return !s.stable || s.inProfileChange(at: now)
    }

    /// Where the agent's settings come from, for `altiward-agent status`. Nil `state`:
    /// development.
    public static func sourceDescription(_ state: ManagedSettingsState?) -> String {
        guard let state else { return "com.altiward.agent preferences (development)" }
        if state.unmanaged { return "com.altiward.agent preferences: this Mac isn't enrolled in MDM" }
        guard let payloads = state.payloads else {
            return "none: the installed profiles can't be read"
                + (state.storedRefused.map { ", and \($0)" } ?? ", and none are stored")
        }
        let read = AltiwardJSON.format(payloads.readAt)
        if let error = state.readError { return "MDM's profiles as read \(read); they can't be read now (\(error))" }
        if state.notEnrolled { return "MDM's profiles as read \(read); no MDM enrolment shows now" }
        if state.agentPayloadMissing { return "MDM's profiles as read \(read); no MDM profile sets them now" }
        return "MDM's profiles, read \(read)"
    }
}

/// The installed agent's view of MDM's payloads for `com.altiward.agent` and
/// `corp.sap.privileges`, shared by everything that needs them so `profiles` runs only on
/// ``refresh()``: on the heartbeat and after a managed preferences file changes. The last
/// clean read is kept in the store, so a `profiles` that stops working doesn't hand the agent
/// back to settings an admin can write. It also keeps what the settings check found between
/// reads (``ManagedSettingsCheck``).
public final class ManagedSettings: Sendable {
    let store: AgentStore
    let readDevice: @Sendable () -> Result<ProfilesReading, ProfilesReadError>
    let now: @Sendable () -> Date
    /// One read at a time.
    private let reading = NSLock()
    private let state: OSAllocatedUnfairLock<ManagedSettingsState>
    /// The latest read's payloads when it worked, for ``ManagedSettingsState/stable``.
    private let lastRead = OSAllocatedUnfairLock<MDMPayloadSet?>(initialState: nil)
    /// The latest clean read in this process, failed reads or not since.
    private let lastClean = OSAllocatedUnfairLock<MDMPayloadSet?>(initialState: nil)

    struct Memo: Sendable {
        /// Managed preferences that differed from the payloads when a file changed, to judge
        /// at the next read of the profiles. At most ``maxCaptures``.
        var captures: [ManagedFilesSnapshot] = []
        /// When a signed-in user's folder is due to be compared.
        var followUp: Date?
        /// Each user's own MDM payloads (user channel), as last read.
        var userPayloads: [String: [MDMPayload]] = [:]
    }

    static let maxCaptures = 5
    let memo = OSAllocatedUnfairLock(initialState: Memo())

    /// `enrolment`: what this Mac enrolled with. A stored set that doesn't match it isn't used.
    public init(
        store: AgentStore,
        readDevice: @escaping @Sendable () -> Result<ProfilesReading, ProfilesReadError> = InstalledProfiles.readDevice,
        now: @escaping @Sendable () -> Date = { Date() },
        enrolment: EnrolmentRecord? = nil
    ) {
        self.store = store
        self.readDevice = readDevice
        self.now = now
        var initial = ManagedSettingsState(readError: .malformed("the installed profiles haven't been read yet"))
        do {
            if let stored = try store.mdmPayloads() {
                if let refusal = enrolment?.refusal(of: stored) {
                    initial.storedRefused = refusal
                    log.error("not using the stored MDM settings: \(refusal, privacy: .public)")
                } else {
                    initial.payloads = stored
                }
            }
        } catch {
            initial.storedRefused = "the stored MDM settings can't be read"
            log.error("can't read the stored MDM settings: \(String(describing: error), privacy: .public)")
        }
        state = OSAllocatedUnfairLock(initialState: initial)
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
            let clean = lastClean.withLock { last in
                defer { last = set }
                return last
            }
            // Only a change this agent saw between two of its own reads opens the grace for
            // files macOS hasn't rewritten yet: not a difference from the stored set, which
            // anyone with root could have edited.
            if let clean, !set.sameSettings(as: clean) {
                next.changedAt = now
                next.previous = clean
            }
            if !set.setsAgent, next.payloads?.setsAgent == true {
                next.agentPayloadMissing = true
                next.stable = false
            } else {
                next.stable = set.sameSettings(as: previous)
                next.payloads = set
                next.storedRefused = nil
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

    /// The settings that differ from those the daemon runs with, by profile key: in the
    /// installed agent (`settled` given, or nil while reads don't agree) MDM's settled payloads,
    /// otherwise the preferences.
    public static func restartChanges(
        running: AgentConfiguration, installed: Bool, settled: AgentConfiguration?,
        preferences: () -> AgentConfiguration
    ) -> [String] {
        if installed {
            guard let settled else { return [] }
            return running.changedSettings(settled)
        }
        return running.changedSettings(preferences())
    }

    /// The Privileges settings the agent's own logic uses: from MDM's payloads, or the
    /// preferences when there are none.
    public func privilegesSettings() -> PrivilegesSettings {
        guard let payloads = latest.payloads else { return PrivilegesSettings.current() }
        return PrivilegesSettings.settings(from: payloads.preferences(for: PrivilegesSettings.domain))
    }

    /// Reads the profiles until there is something to take settings from. Only the daemon
    /// (`mayWait`) waits, reading again every `retry` seconds; a command throws instead.
    ///
    /// Synchronous on purpose: the daemon calls it before `Daemon.run()`, which calls
    /// `dispatchMain()`. An `await` on that path would resume the rest of `main.swift` in a
    /// block on the main queue, where `dispatchMain()` traps.
    public static func startupState(
        _ settings: ManagedSettings, mayWait: Bool, retry: TimeInterval = 30,
        sleep: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) },
        log: (String) -> Void
    ) throws -> ManagedSettingsState {
        var state = settings.refresh()
        while state.mustWait {
            guard mayWait else { throw SettingsUnavailable(state: state) }
            log("\(SettingsUnavailable(state: state).description); trying again in \(Int(retry)) s")
            sleep(retry)
            state = settings.refresh()
        }
        return state
    }

    // MARK: Between reads

    func capture(_ snapshot: ManagedFilesSnapshot) {
        memo.withLock { m in
            m.captures.append(snapshot)
            if m.captures.count > Self.maxCaptures { m.captures.removeFirst(m.captures.count - Self.maxCaptures) }
        }
    }

    func takeCaptures() -> [ManagedFilesSnapshot] {
        memo.withLock { m in
            defer { m.captures = [] }
            return m.captures
        }
    }

    func noteFollowUp(_ date: Date) {
        memo.withLock { $0.followUp = min($0.followUp ?? date, date) }
    }

    /// When a signed-in user's folder is next due to be compared, once.
    public func takeFollowUp() -> Date? {
        memo.withLock { m in
            defer { m.followUp = nil }
            return m.followUp
        }
    }
}

/// The installed agent can't read the installed profiles and has no usable MDM settings stored.
public struct SettingsUnavailable: Error, CustomStringConvertible {
    public let state: ManagedSettingsState
    public var description: String {
        "can't read MDM's settings from the installed profiles (\(state.readError?.description ?? "not read")), "
            + (state.storedRefused.map { "and \($0)" } ?? "and none are stored")
    }
}
