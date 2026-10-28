import Foundation

/// One domain's settings from a payload of a profile MDM installed.
public struct MDMPayload: Sendable, Equatable {
    public var domain: String
    public var profileUUID: String
    public var payloadUUID: String
    /// The settings, without the payload's own `Payload*` keys.
    public var settings: [String: PlistValue]

    public init(domain: String, profileUUID: String, payloadUUID: String, settings: [String: PlistValue]) {
        self.domain = domain
        self.profileUUID = profileUUID.uppercased()
        self.payloadUUID = payloadUUID.uppercased()
        self.settings = settings.filter { !$0.key.hasPrefix("Payload") }
    }
}

/// What the installed profiles say about the domains Altiward compares.
public enum ProfilesReading: Sendable, Equatable {
    /// The Mac is enrolled in MDM; these are the settings payloads MDM installed (possibly none).
    case enrolled([MDMPayload])
    /// The Mac isn't enrolled in MDM, so no profile was installed by MDM.
    case notEnrolled
}

/// Why the installed profiles couldn't be read. Never carries what `profiles` printed: its
/// output holds Wi-Fi, VPN and certificate secrets.
public enum ProfilesReadError: Error, Equatable, Sendable, CustomStringConvertible {
    case command(String, CommandFailure)
    case malformed(String)

    public var description: String {
        switch self {
        case .command(let what, let failure): "\(what) \(failure)"
        case .malformed(let what): "the profiles tool's output can't be used: \(what)"
        }
    }
}

/// Reads the configuration profiles installed on this Mac with `/usr/bin/profiles` (on the
/// sealed system volume, so root can't change it), as root. Two outputs are joined:
/// `profiles show -output stdout-xml` has each payload's content, and the text of
/// `profiles list -verbose` is the only one that says whether MDM installed a profile
/// (`installedByMDM`). Both are parsed strictly, and anything unexpected fails the read
/// rather than being skipped: a profile an admin installs by hand can carry text that
/// looks like more lines of the listing.
public enum InstalledProfiles {
    /// The domains whose payloads are kept; everything else is dropped as soon as it is parsed.
    public static let domains: Set<String> = [AgentConfiguration.domain, PrivilegesSettings.domain]
    static let managedClientPreferences = "com.apple.ManagedClient.preferences"
    static let enrolmentPayloadType = "com.apple.mdm"
    static let deviceScope = "_computerlevel"
    static let executable = "/usr/bin/profiles"
    static let timeout: TimeInterval = 10
    static let maxOutput = 16 << 20

    struct ShownPayload: Equatable {
        var type: String
        var uuid: String
        var settings: [(domain: String, settings: [String: PlistValue])]

        static func == (a: Self, b: Self) -> Bool {
            a.type == b.type && a.uuid == b.uuid && a.settings.map(\.domain) == b.settings.map(\.domain)
                && a.settings.map(\.settings) == b.settings.map(\.settings)
        }
    }

    struct ShownProfile: Equatable {
        var uuid: String
        var payloads: [ShownPayload]
    }

    struct ListedProfile: Equatable {
        var installedByMDM: Bool
        var payloadUUIDs: Set<String>
    }

    // MARK: Reading

    /// The device's MDM payloads for ``domains``, read once.
    public static func readDevice() -> Result<ProfilesReading, ProfilesReadError> {
        Result {
            let shown = try self.shown(run(["show", "-output", "stdout-xml"]), user: nil)
            let listed = try self.listed(String(decoding: run(["list", "-verbose"]), as: UTF8.self), user: nil)
            let payloads = try mdmPayloads(shown: shown, listed: listed)
            if hasEnrolmentPayload(shown) { return .enrolled(payloads) }
            // No enrolment profile: either no MDM, or the profiles services answer with nothing.
            let status = String(decoding: try run(["status", "-type", "enrollment"]), as: UTF8.self)
            guard try !enrolled(status: status) else {
                throw ProfilesReadError.malformed("the Mac is enrolled in MDM, but no profile shows the enrolment")
            }
            return .notEnrolled
        }.mapError { $0 as? ProfilesReadError ?? .malformed(String(describing: $0)) }
    }

    /// The MDM payloads for ``domains`` installed for one user (user channel).
    public static func readUser(_ user: String) -> Result<[MDMPayload], ProfilesReadError> {
        Result {
            let shown = try self.shown(run(["show", "-user", user, "-output", "stdout-xml"]), user: user)
            let listed = try self.listed(
                String(decoding: run(["list", "-user", user, "-verbose"]), as: UTF8.self), user: user)
            return try mdmPayloads(shown: shown, listed: listed)
        }.mapError { $0 as? ProfilesReadError ?? .malformed(String(describing: $0)) }
    }

    private static func run(_ arguments: [String]) throws -> Data {
        switch CommandOutput.run(executable, arguments, timeout: timeout, maxBytes: maxOutput) {
        case .success(let data): return data
        case .failure(let failure): throw ProfilesReadError.command("profiles \(arguments[0])", failure)
        }
    }

    // MARK: Parsing

    /// The profiles in `profiles show -output stdout-xml`: the device's (`_computerlevel`), or
    /// with `user` every other scope's.
    static func shown(_ data: Data, user: String?) throws -> [ShownProfile] {
        guard let top = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw ProfilesReadError.malformed("profiles show didn't print a dictionary")
        }
        var profiles: [ShownProfile] = []
        for (scope, value) in top where (scope == deviceScope) == (user == nil) {
            guard let list = value as? [[String: Any]] else {
                throw ProfilesReadError.malformed("profiles show's \(scope) isn't a list of profiles")
            }
            for profile in list {
                guard let uuid = profile["ProfileUUID"] as? String, !uuid.isEmpty else {
                    throw ProfilesReadError.malformed("a profile in profiles show has no ProfileUUID")
                }
                guard let items = (profile["ProfileItems"] ?? [Any]()) as? [[String: Any]] else {
                    throw ProfilesReadError.malformed("profile \(uuid) has ProfileItems that aren't a list")
                }
                profiles.append(ShownProfile(uuid: uuid.uppercased(), payloads: try items.map { try payload($0, in: uuid) }))
            }
        }
        var seen: Set<String> = []
        for uuid in profiles.map(\.uuid) + profiles.flatMap({ $0.payloads.map(\.uuid) }) {
            guard seen.insert(uuid).inserted else {
                throw ProfilesReadError.malformed("UUID \(uuid) appears twice in profiles show")
            }
        }
        return profiles
    }

    /// One payload, keeping only the settings of ``domains``: a payload of the domain's own
    /// type, or `com.apple.ManagedClient.preferences` (every entry of the domain's `Forced`).
    private static func payload(_ item: [String: Any], in profile: String) throws -> ShownPayload {
        guard let type = item["PayloadType"] as? String, let uuid = item["PayloadUUID"] as? String, !uuid.isEmpty
        else {
            throw ProfilesReadError.malformed("a payload of profile \(profile) has no PayloadType or PayloadUUID")
        }
        var found: [(domain: String, settings: [String: PlistValue])] = []
        if domains.contains(type) {
            let content = item["PayloadContent"] ?? [String: Any]()
            guard let settings = PlistValue.dictionary(content) else {
                throw ProfilesReadError.malformed("payload \(uuid) has content that isn't a property-list dictionary")
            }
            found.append((type, settings))
        } else if type == managedClientPreferences {
            guard let content = (item["PayloadContent"] ?? [String: Any]()) as? [String: Any] else {
                throw ProfilesReadError.malformed("payload \(uuid) has content that isn't a dictionary")
            }
            for domain in domains.sorted() {
                guard let entry = content[domain] else { continue }
                guard let entry = entry as? [String: Any],
                    let forced = (entry["Forced"] ?? [Any]()) as? [[String: Any]]
                else {
                    throw ProfilesReadError.malformed("payload \(uuid) has \(domain) settings in an unknown layout")
                }
                for f in forced {
                    guard let settings = f["mcx_preference_settings"].flatMap(PlistValue.dictionary) else {
                        throw ProfilesReadError.malformed("payload \(uuid) has a Forced entry without settings")
                    }
                    found.append((domain, settings))
                }
            }
        }
        return ShownPayload(type: type, uuid: uuid.uppercased(), settings: found)
    }

    /// The profiles in the text of `profiles list -verbose`, by profile UUID: lines such as
    /// `_computerlevel[3] attribute: installedByMDM: TRUE` and
    /// `_computerlevel[3]            payload[1] uuid = …`, grouped by their `[N]`. A profile
    /// with an attribute or payload field twice, or without `profileUUID`, `installedByMDM` or
    /// a payload's `uuid`, a UUID twice, or a count that differs from the closing
    /// "There are N … profiles installed", fails the read.
    static func listed(_ text: String, user: String?) throws -> [String: ListedProfile] {
        struct Group {
            var attributes: [String: String] = [:]
            var payloads: [Int: [String: String]] = [:]
        }
        let line = /^(\S+)\[(\d+)\] +(.*)$/
        let attribute = /^attribute: ([^:]+): ?(.*)$/
        let payloadField = /^payload\[(\d+)\]\s+(\S+)\s*= ?(.*)$/
        // "There are 5 system configuration profiles installed", or "There are no configuration
        // profiles installed for user 'jdoe'".
        let total = /^There are (\d+|no) (?:system )?configuration profiles installed( for user)?/

        var groups: [Int: Group] = [:]
        var stated: Int?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let row = String(raw)
            if let m = row.prefixMatch(of: total), (m.2 != nil) == (user != nil) {
                guard stated == nil else { throw ProfilesReadError.malformed("profiles list states its count twice") }
                stated = m.1 == "no" ? 0 : Int(m.1) ?? -1
                continue
            }
            guard let m = row.wholeMatch(of: line) else { continue }
            let scope = String(m.1)
            guard (scope == deviceScope) == (user == nil), let index = Int(m.2) else { continue }
            let rest = m.3.trimmingCharacters(in: .whitespaces)
            var group = groups[index] ?? Group()
            if let a = rest.wholeMatch(of: attribute) {
                let name = String(a.1)
                guard group.attributes[name] == nil else {
                    throw ProfilesReadError.malformed("profile [\(index)] lists \(name) twice")
                }
                group.attributes[name] = String(a.2).trimmingCharacters(in: .whitespaces)
            } else if let p = rest.wholeMatch(of: payloadField), let n = Int(p.1) {
                let name = String(p.2)
                guard group.payloads[n]?[name] == nil else {
                    throw ProfilesReadError.malformed("profile [\(index)] lists payload [\(n)] \(name) twice")
                }
                group.payloads[n, default: [:]][name] = String(p.3).trimmingCharacters(in: .whitespaces)
            }
            groups[index] = group
        }
        guard let stated else { throw ProfilesReadError.malformed("profiles list has no count of profiles") }
        guard stated == groups.count else {
            throw ProfilesReadError.malformed("profiles list counts \(stated) profiles but lists \(groups.count)")
        }

        var profiles: [String: ListedProfile] = [:]
        var payloadUUIDs: Set<String> = []
        for (index, group) in groups.sorted(by: { $0.key < $1.key }) {
            guard let uuid = group.attributes["profileUUID"]?.uppercased(), !uuid.isEmpty else {
                throw ProfilesReadError.malformed("profile [\(index)] has no profileUUID")
            }
            let mdm: Bool
            switch group.attributes["installedByMDM"] {
            case "TRUE": mdm = true
            case "FALSE": mdm = false
            default: throw ProfilesReadError.malformed("profile [\(index)] has no installedByMDM")
            }
            var uuids: Set<String> = []
            for (n, fields) in group.payloads {
                guard let id = fields["uuid"]?.uppercased(), !id.isEmpty else {
                    throw ProfilesReadError.malformed("profile [\(index)] payload [\(n)] has no uuid")
                }
                guard payloadUUIDs.insert(id).inserted else {
                    throw ProfilesReadError.malformed("payload UUID \(id) appears twice in profiles list")
                }
                uuids.insert(id)
            }
            guard profiles[uuid] == nil, !payloadUUIDs.contains(uuid) else {
                throw ProfilesReadError.malformed("profile UUID \(uuid) appears twice in profiles list")
            }
            profiles[uuid] = ListedProfile(installedByMDM: mdm, payloadUUIDs: uuids)
        }
        return profiles
    }

    /// Joins the two: the settings payloads of profiles MDM installed. Both must list the same
    /// profiles, and each profile the same payloads.
    static func mdmPayloads(shown: [ShownProfile], listed: [String: ListedProfile]) throws -> [MDMPayload] {
        guard Set(shown.map(\.uuid)) == Set(listed.keys), shown.count == listed.count else {
            throw ProfilesReadError.malformed("profiles show and profiles list name different profiles")
        }
        var payloads: [MDMPayload] = []
        for profile in shown {
            let entry = listed[profile.uuid]!
            guard Set(profile.payloads.map(\.uuid)) == entry.payloadUUIDs else {
                throw ProfilesReadError.malformed("profile \(profile.uuid) has different payloads in profiles show and list")
            }
            guard entry.installedByMDM else { continue }
            for p in profile.payloads {
                for (domain, settings) in p.settings {
                    payloads.append(
                        MDMPayload(domain: domain, profileUUID: profile.uuid, payloadUUID: p.uuid, settings: settings))
                }
            }
        }
        return payloads
    }

    /// Whether a profile, MDM's or not, carries MDM's enrolment (`com.apple.mdm`). Intune's own
    /// enrolment profile shows `installedByMDM: FALSE`, so any profile counts.
    static func hasEnrolmentPayload(_ shown: [ShownProfile]) -> Bool {
        shown.contains { $0.payloads.contains { $0.type == enrolmentPayloadType } }
    }

    /// `profiles status -type enrollment`'s "MDM enrollment: Yes (User Approved)" or "No".
    static func enrolled(status: String) throws -> Bool {
        let answers = status.split(separator: "\n").compactMap { line -> Substring? in
            line.hasPrefix("MDM enrollment:") ? line.dropFirst("MDM enrollment:".count) : nil
        }
        guard answers.count == 1 else { throw ProfilesReadError.malformed("profiles status has no single MDM enrollment line") }
        let answer = answers[0].trimmingCharacters(in: .whitespaces)
        if answer.hasPrefix("Yes") { return true }
        if answer.hasPrefix("No") { return false }
        throw ProfilesReadError.malformed("profiles status gives an unknown MDM enrollment answer")
    }
}
