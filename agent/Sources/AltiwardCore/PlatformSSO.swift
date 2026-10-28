import Foundation
import OpenDirectory
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "platform-sso")

/// The account Platform SSO links to a Mac account: macOS records it in the local user
/// record's `AltSecurityIdentities` as `PlatformSSO:<upn>`. Any user can read it; only root
/// and admins can change it, which a Privileges elevation is. So a session keeps the UPN it
/// started with (``OpenSession/upn``), and a link changed while someone is elevated is
/// reported by persistence detection (``PersistenceKind/localAccount``).
public enum PlatformSSO {
    static let attribute = "dsAttrTypeStandard:AltSecurityIdentities"
    static let prefix = "PlatformSSO:"
    /// ASCII only, so homoglyphs, invisible characters and Unicode case folding can't make
    /// one UPN pass for another.
    nonisolated(unsafe) static let shape = /^[A-Za-z0-9._%+'!#^~-]{1,64}@[A-Za-z0-9.-]{1,190}$/

    /// What reading an account's link found.
    public enum Lookup: Sendable, Equatable {
        case linked(String)
        case notLinked
        case noAccount
        case unreadable(String)

        public var upn: String? {
            if case .linked(let upn) = self { return upn }
            return nil
        }
    }

    /// The UPN in an account's `AltSecurityIdentities`: the text after the one value that
    /// starts `PlatformSSO:`. Nil when no value does, when more than one value starts with it
    /// in any case, or when the text isn't a plain ASCII UPN.
    public static func upn(fromAltSecurityIdentities values: [String]) -> String? {
        let candidates = values.filter { $0.lowercased().hasPrefix(prefix.lowercased()) }
        guard candidates.count == 1, let value = candidates.first, value.hasPrefix(prefix) else { return nil }
        let upn = String(value.dropFirst(prefix.count))
        return upn.wholeMatch(of: shape) == nil ? nil : upn
    }

    /// Reads one account's link from the local directory.
    public static func lookup(_ shortName: String) -> Lookup {
        do {
            let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
            let query = try ODQuery(
                node: node, forRecordTypes: kODRecordTypeUsers, attribute: kODAttributeTypeRecordName,
                matchType: ODMatchType(kODMatchEqualTo), queryValues: shortName, returnAttributes: [attribute],
                maximumResults: 2)
            let records = try query.resultsAllowingPartial(false) as? [ODRecord] ?? []
            guard records.count == 1, let record = records.first else {
                return records.isEmpty ? .noAccount : .unreadable("\(records.count) records named \(shortName)")
            }
            return upn(fromAltSecurityIdentities: try values(of: record)).map(Lookup.linked) ?? .notLinked
        } catch {
            return .unreadable(String(describing: error))
        }
    }

    /// Every local account's link, by short name, for the persistence snapshot. Nil when the
    /// directory can't be read.
    public static func allLinks() -> [String: String]? {
        do {
            let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
            let query = try ODQuery(
                node: node, forRecordTypes: kODRecordTypeUsers, attribute: nil, matchType: ODMatchType(kODMatchAny),
                queryValues: nil, returnAttributes: [attribute], maximumResults: 0)
            var links: [String: String] = [:]
            for record in try query.resultsAllowingPartial(false) as? [ODRecord] ?? [] {
                if let name = record.recordName, let upn = upn(fromAltSecurityIdentities: try values(of: record)) {
                    links[name] = upn
                }
            }
            return links
        } catch {
            return nil
        }
    }

    /// The record's `AltSecurityIdentities`, empty when it has none. `recordDetails` leaves out
    /// an attribute the record doesn't have; `values(forAttribute:)` would throw the same
    /// error for that as for a failed read.
    private static func values(of record: ODRecord) throws -> [String] {
        let details = try record.recordDetails(forAttributes: [attribute])
        return details[attribute] as? [String] ?? []
    }
}

extension ElevationTracker {
    /// A person's UPN now (``AgentConfiguration/upn(for:platformSSO:)``). Read live: the local
    /// directory answers in about a millisecond, like the other account reads made inside
    /// transactions.
    func upn(for user: String) -> String? {
        env.config.upn(for: user) { user in
            guard env.config.platformSSOIdentity else { return nil }
            let lookup = env.platformSSO(user)
            if case .unreadable(let why) = lookup {
                log.error("can't read \(user, privacy: .public)'s Platform SSO account: \(why, privacy: .public)")
            }
            return lookup.upn
        }
    }

    /// Who a session's events are about: the UPN the session started with, so a link changed
    /// during it can't move it onto someone else.
    func sessionUser(_ session: OpenSession) -> UserInfo {
        UserInfo(localName: session.user, upn: session.upn ?? upn(for: session.user))
    }
}
