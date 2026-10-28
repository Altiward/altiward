import CoreFoundation
import Foundation

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

    public func read(_ path: String) -> Read {
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        guard let data = FileManager.default.contents(atPath: path),
            let object = try? PropertyListSerialization.propertyList(from: data, format: nil),
            let settings = PlistValue.dictionary(object)
        else { return .unreadable }
        return .settings(settings)
    }

    /// A domain's entries in a `complete.plist`, which holds `domain => key => {mcxdomain,
    /// source, value}`. An entry that isn't `mcxdomain` `always` (forced) keeps its whole
    /// entry as its value, so it never equals what MDM sets and is reported.
    static func complete(_ file: Read, domain: String) -> Read {
        guard case .settings(let all) = file else { return file }
        guard let entry = all[domain] else { return .missing }
        guard case .dictionary(let keys) = entry else { return .unreadable }
        var settings: [String: PlistValue] = [:]
        for (key, item) in keys {
            guard case .dictionary(let fields) = item, let value = fields["value"] else { return .unreadable }
            settings[key] = fields["mcxdomain"] == .string("always") ? value : item
        }
        return .settings(settings)
    }
}

/// A setting that differs between the managed preferences and MDM's payloads. Names only:
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
    /// Just after MDM's payloads changed, the file still holds what the payloads before set:
    /// macOS hasn't rewritten it yet.
    public var lagging = false

    public static func < (a: Self, b: Self) -> Bool {
        (a.path, a.domain, a.key ?? "", a.kind.rawValue) < (b.path, b.domain, b.key ?? "", b.kind.rawValue)
    }

    /// The finding it stands for, for ``IntegrityResult/findings``.
    var finding: String { "\(domain) \(key.map(ManagedSettingsCheck.quoted) ?? "file")" }

    /// Compares a file's settings for `domain` with the payloads MDM installed for it, both
    /// ways: every key a payload sets must be in the file with a value equal to one payload's,
    /// and every key in the file must be one a payload sets. `Payload*` keys are left out on
    /// both sides, but the file's `PayloadUUID` must be one of the payloads'. With `previous`,
    /// the payloads before a change, a difference the old payloads explain is marked lagging.
    static func compare(
        _ file: ManagedPreferenceFiles.Read, path: String, domain: String, payloads: [MDMPayload],
        previous: [MDMPayload]? = nil
    ) -> [SettingsMismatch] {
        let settings: [String: PlistValue]
        switch file {
        case .missing: settings = [:]
        case .unreadable: return [SettingsMismatch(path: path, domain: domain, key: nil, kind: .unreadable)]
        case .settings(let s): settings = s
        }
        let expected = values(payloads)
        let before = previous.map(values)
        var found: [SettingsMismatch] = []
        func add(_ key: String, _ kind: Kind, lagging: Bool) {
            found.append(SettingsMismatch(path: path, domain: domain, key: key, kind: kind, lagging: lagging))
        }
        for (key, values) in expected {
            guard let value = settings[key] else {
                add(key, .removed, lagging: before.map { $0[key] == nil } ?? false)
                continue
            }
            if !values.contains(value) { add(key, .changed, lagging: before?[key]?.contains(value) ?? false) }
        }
        for (key, value) in settings where !key.hasPrefix("Payload") && expected[key] == nil {
            add(key, .added, lagging: before?[key]?.contains(value) ?? false)
        }
        if let uuid = settings["PayloadUUID"] {
            let known = Set(payloads.map(\.payloadUUID))
            if case .string(let s) = uuid, known.contains(s.uppercased()) {
            } else {
                let wasKnown = previous.map { old in
                    guard case .string(let s) = uuid else { return false }
                    return old.contains { $0.payloadUUID == s.uppercased() }
                } ?? false
                add("PayloadUUID", payloads.isEmpty ? .added : .changed, lagging: wasKnown)
            }
        }
        return found.sorted()
    }

    /// What CFPreferences serves for each key a payload sets, as root: equal to one payload's
    /// value, or the key is reported. `served` gives nil for a key it has nothing for.
    static func compareServed(
        domain: String, payloads: [MDMPayload], previous: [MDMPayload]?, served: (String) -> PlistValue??
    ) -> [SettingsMismatch] {
        let expected = values(payloads)
        let before = previous.map(values)
        var found: [SettingsMismatch] = []
        for (key, values) in expected.sorted(by: { $0.key < $1.key }) {
            guard case .some(let value) = served(key) else { continue }
            guard let value else {
                found.append(
                    SettingsMismatch(
                        path: ManagedSettingsCheck.servedPath, domain: domain, key: key, kind: .removed,
                        lagging: before.map { $0[key] == nil } ?? false))
                continue
            }
            if !values.contains(value) {
                found.append(
                    SettingsMismatch(
                        path: ManagedSettingsCheck.servedPath, domain: domain, key: key, kind: .changed,
                        lagging: before?[key]?.contains(value) ?? false))
            }
        }
        return found
    }

    private static func values(_ payloads: [MDMPayload]) -> [String: [PlistValue]] {
        payloads.reduce(into: [String: [PlistValue]]()) { all, p in
            for (key, value) in p.settings { all[key, default: []].append(value) }
        }
    }
}

/// The managed preferences as read when a file changed, to judge against MDM's payloads at the
/// next read of the profiles: a value changed and put back before then is still reported.
struct ManagedFilesSnapshot: Sendable {
    var takenAt: Date
    var files: [String: ManagedPreferenceFiles.Read]
    /// What CFPreferences served, by "domain key".
    var served: [String: PlistValue?]
    var signedIn: [String: Date]
}

/// The `settings_managed` comparison in the installed agent: the device's managed preferences
/// files and what CFPreferences serves for them always, and the copies in the folders of users
/// signed in at the login window (after ``signInGrace``, while ManagedClient writes them).
/// Other users' folders are left alone: a folder keeps the settings of its user's last sign-in,
/// and takes the current ones at the next.
public struct ManagedSettingsCheck: Sendable {
    /// How long after a sign-in its folder is left alone.
    public static let signInGrace: TimeInterval = 120
    /// How long after MDM's payloads change a file that still holds the old payloads' value is
    /// left alone, while macOS rewrites the files.
    public static let profileChangeGrace: TimeInterval = 300
    /// Settings named in one problem text; the rest are counted.
    static let listedLimit = 20
    /// Findings kept for telling one failure from the next.
    static let findingsLimit = 100
    /// Characters of a key name shown.
    static let nameLimit = 64
    /// Where a mismatch in what CFPreferences serves is said to be.
    static let servedPath = "(served)"

    public var files: ManagedPreferenceFiles
    /// Users signed in at the login window now, with when they signed in.
    public var signedIn: @Sendable () -> [String: Date]
    /// MDM payloads installed for one user (user channel), read only when a user's folder
    /// differs from the device's payloads.
    public var userPayloads: @Sendable (String) -> Result<[MDMPayload], ProfilesReadError>
    /// What CFPreferences serves root for a key of a domain; nil turns that comparison off.
    public var served: (@Sendable (_ domain: String, _ key: String) -> PlistValue?)?
    public var now: @Sendable () -> Date
    /// Where findings between reads, follow-ups and users' own payloads are kept.
    public var memo: ManagedSettings?

    public init(
        files: ManagedPreferenceFiles = ManagedPreferenceFiles(),
        signedIn: @escaping @Sendable () -> [String: Date],
        userPayloads: @escaping @Sendable (String) -> Result<[MDMPayload], ProfilesReadError> = InstalledProfiles.readUser,
        served: (@Sendable (_ domain: String, _ key: String) -> PlistValue?)? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        memo: ManagedSettings? = nil
    ) {
        self.files = files
        self.signedIn = signedIn
        self.userPayloads = userPayloads
        self.served = served
        self.now = now
        self.memo = memo
    }

    /// The real system, keeping its findings in `managed`.
    public static func live(_ managed: ManagedSettings) -> ManagedSettingsCheck {
        ManagedSettingsCheck(
            signedIn: { LoginRecords.signedInAtLoginWindow() },
            served: { domain, key in
                CFPreferencesAppSynchronize(domain as CFString)
                return CFPreferencesCopyAppValue(key as CFString, domain as CFString).flatMap { PlistValue($0) }
            },
            memo: managed)
    }

    // MARK: Checking

    /// The full check, after a read of the profiles. Also judges what changed files held
    /// since the last one (``quick(_:)``) against the payloads just read.
    public func result(_ state: ManagedSettingsState) -> IntegrityResult {
        let now = now()
        guard let payloads = state.payloads else {
            _ = memo?.takeCaptures()
            if state.notEnrolled {
                return IntegrityResult(
                    ok: false, problem: "this Mac isn't enrolled in MDM, so no MDM profile sets Altiward's settings",
                    findings: ["not enrolled in MDM"], observedAt: now)
            }
            return IntegrityResult(
                ok: false,
                problem: "can't read the installed profiles (\(state.readError?.description ?? "not read")), "
                    + "and no MDM settings are stored",
                findings: ["profiles unreadable"], observedAt: now)
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

        let current = evaluate(payloads, state, sources: liveSources(record: nil), readUsers: true, now: now)
        if let due = current.dueAt { memo?.noteFollowUp(due) }
        let mismatches = current.mismatches
        findings.formUnion(mismatches.map(\.finding))
        if !mismatches.isEmpty {
            notes.append("managed settings differ from MDM's profiles: " + Self.describe(mismatches))
        }

        // What changed files held since the last read, judged against the payloads now.
        var earlier: EarlierFailure?
        if let captures = memo?.takeCaptures(), let first = captures.first {
            let seen = Set(
                captures.flatMap {
                    evaluate(payloads, state, sources: snapshotSources($0), readUsers: false, now: now).mismatches
                }
            ).sorted()
            let seenFindings = Set(seen.map(\.finding))
            if !seen.isEmpty, !seenFindings.isSubset(of: findings) {
                earlier = EarlierFailure(
                    problem: "managed settings differed from MDM's profiles at \(AltiwardJSON.format(first.takenAt)): "
                        + Self.describe(seen),
                    findings: Self.capped(seenFindings.sorted()))
            }
        }

        guard !notes.isEmpty else {
            return IntegrityResult(ok: true, problem: nil, held: current.held, observedAt: now, earlier: earlier)
        }
        return IntegrityResult(
            ok: false, problem: notes.joined(separator: "; "), findings: Self.capped(findings.sorted()),
            observedAt: now, earlier: earlier)
    }

    /// On a change to a managed preferences file: compares the files, and what CFPreferences
    /// serves, with the payloads in use straight away, without reading the profiles. If they
    /// differ, keeps what it read for the next full check, which judges it against the
    /// payloads then: a profile MDM just changed matches them, a forged value doesn't, even
    /// if it was put back in between.
    public func quick(_ state: ManagedSettingsState) {
        guard let memo, let payloads = state.payloads else { return }
        let now = now()
        let recorder = Recorder()
        let found = evaluate(payloads, state, sources: liveSources(record: recorder), readUsers: false, now: now)
        guard !found.mismatches.isEmpty else { return }
        memo.capture(
            ManagedFilesSnapshot(
                takenAt: now, files: recorder.files, served: recorder.served, signedIn: recorder.signedIn))
    }

    // MARK: Comparing

    private final class Recorder {
        var files: [String: ManagedPreferenceFiles.Read] = [:]
        var served: [String: PlistValue?] = [:]
        var signedIn: [String: Date] = [:]
    }

    private struct Sources {
        var file: (String) -> ManagedPreferenceFiles.Read
        /// Nil: not compared. Then per key: nil when unknown, .some(nil) when nothing is served.
        var served: ((String, String) -> PlistValue??)?
        var signedIn: [String: Date]
    }

    private func liveSources(record: Recorder?) -> Sources {
        let users = signedIn()
        record?.signedIn = users
        return Sources(
            file: { path in
                let r = files.read(path)
                record?.files[path] = r
                return r
            },
            served: served.map { serve in
                { domain, key in
                    let v = serve(domain, key)
                    record?.served["\(domain) \(key)"] = .some(v)
                    return .some(v)
                }
            },
            signedIn: users)
    }

    private func snapshotSources(_ s: ManagedFilesSnapshot) -> Sources {
        Sources(
            file: { s.files[$0] ?? .missing },
            served: { domain, key in s.served["\(domain) \(key)"] },
            signedIn: s.signedIn)
    }

    private struct Evaluation {
        /// What fails, leaving out what macOS hasn't rewritten yet after a profile change.
        var mismatches: [SettingsMismatch]
        /// Some differences were left out for that.
        var held: Bool
        /// When a signed-in user's folder, left alone for now, is due.
        var dueAt: Date?
    }

    private func evaluate(
        _ payloads: MDMPayloadSet, _ state: ManagedSettingsState, sources: Sources, readUsers: Bool, now: Date
    ) -> Evaluation {
        let previous = state.inProfileChange(at: now) ? state.previous : nil
        var found: [SettingsMismatch] = []
        for domain in ManagedDomains.all {
            let mine = payloads.payloads(for: domain)
            let before = previous?.payloads(for: domain)
            found += SettingsMismatch.compare(
                sources.file(files.devicePath(domain)), path: files.devicePath(domain), domain: domain, payloads: mine,
                previous: before)
            if let served = sources.served {
                found += SettingsMismatch.compareServed(
                    domain: domain, payloads: mine, previous: before, served: { served(domain, $0) })
            }
        }
        var dueAt: Date?
        for (user, since) in sources.signedIn.sorted(by: { $0.key < $1.key }) where Self.plainName(user) {
            guard now.timeIntervalSince(since) >= Self.signInGrace else {
                let due = since.addingTimeInterval(Self.signInGrace)
                dueAt = min(dueAt ?? due, due)
                continue
            }
            var forUser = userMismatches(user, payloads.payloads, previous?.payloads, sources)
            if !forUser.isEmpty, let own = ownPayloads(user, read: readUsers), !own.isEmpty {
                forUser = userMismatches(user, payloads.payloads + own, previous.map { $0.payloads + own }, sources)
            }
            found += forUser
        }
        return Evaluation(
            mismatches: found.filter { !$0.lagging }, held: found.contains(where: \.lagging), dueAt: dueAt)
    }

    /// A user's own MDM payloads: read now when `read`, else as last read.
    private func ownPayloads(_ user: String, read: Bool) -> [MDMPayload]? {
        if read, case .success(let own) = userPayloads(user) {
            memo?.memo.withLock { $0.userPayloads[user] = own }
            return own
        }
        return memo?.memo.withLock { $0.userPayloads[user] }
    }

    private func userMismatches(
        _ user: String, _ payloads: [MDMPayload], _ previous: [MDMPayload]?, _ sources: Sources
    ) -> [SettingsMismatch] {
        let complete = sources.file(files.completePath(user))
        return ManagedDomains.all.flatMap { domain in
            let mine = payloads.filter { $0.domain == domain }
            let before = previous?.filter { $0.domain == domain }
            return SettingsMismatch.compare(
                sources.file(files.userPath(user, domain)), path: files.userPath(user, domain), domain: domain,
                payloads: mine, previous: before)
                + SettingsMismatch.compare(
                    ManagedPreferenceFiles.complete(complete, domain: domain), path: files.completePath(user),
                    domain: domain, payloads: mine, previous: before)
        }
    }

    // MARK: Wording

    /// A short name that is safe as a folder name.
    static func plainName(_ user: String) -> Bool {
        !user.isEmpty && user != "." && user != ".." && !user.contains("/")
    }

    /// A key name as the problem text shows it: in quotes, at most ``nameLimit`` characters,
    /// with quotes, backslashes and control characters escaped, so a name can't pass for
    /// more of the text.
    static func quoted(_ name: String) -> String {
        let short = name.count > nameLimit ? String(name.prefix(nameLimit)) + "…" : name
        var out = "\""
        for scalar in short.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case _ where scalar.properties.generalCategory == .control || scalar.properties.generalCategory == .format:
                out += String(format: "\\u{%X}", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    static func capped(_ findings: [String]) -> [String] {
        findings.count <= findingsLimit
            ? findings : Array(findings.prefix(findingsLimit)) + ["and \(findings.count - findingsLimit) more"]
    }

    /// `com.altiward.agent "ServerURL" (changed), corp.sap.privileges "EnableSystemExtension"
    /// (removed) in /Library/Managed Preferences; … in /Library/Managed Preferences/jdoe/complete.plist`,
    /// listing at most ``listedLimit``.
    static func describe(_ mismatches: [SettingsMismatch]) -> String {
        let sorted = mismatches.sorted()
        var byPlace: [(String, [SettingsMismatch])] = []
        for m in sorted.prefix(listedLimit) {
            let place =
                m.path == servedPath
                ? "what macOS serves"
                : (m.path as NSString).lastPathComponent == "complete.plist"
                    ? m.path : (m.path as NSString).deletingLastPathComponent
            if let i = byPlace.firstIndex(where: { $0.0 == place }) {
                byPlace[i].1.append(m)
            } else {
                byPlace.append((place, [m]))
            }
        }
        let listed = byPlace.map { place, items in
            items.map { "\($0.domain) \($0.key.map(quoted) ?? "file") (\($0.kind.rawValue))" }.joined(separator: ", ")
                + " in \(place)"
        }.joined(separator: "; ")
        return sorted.count > listedLimit ? listed + "; and \(sorted.count - listedLimit) more" : listed
    }
}

extension SettingsMismatch: Hashable {}
extension SettingsMismatch.Kind: Hashable {}
