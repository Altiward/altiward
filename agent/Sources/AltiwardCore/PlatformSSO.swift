import Foundation
import OpenDirectory
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "platform-sso")

/// The account Platform SSO links to a Mac account: macOS records it in the local user
/// record's `AltSecurityIdentities` as `PlatformSSO:<upn>`. Any user can read it; only root
/// and admins can change it, which a Privileges elevation is. So the agent never takes a link
/// as it finds it: it keeps its own record of every account's link, reports each change to it
/// as `agent.tamper` (``ElevationTracker/checkPlatformSSOLinks()``), and events take their UPN
/// from that record. A session keeps the UPN it started with (``PinnedUPN``).
public enum PlatformSSO {
    static let attribute = "dsAttrTypeStandard:AltSecurityIdentities"
    static let prefix = "PlatformSSO:"
    /// ASCII only, so homoglyphs, invisible characters and Unicode case folding can't make
    /// one UPN pass for another; a domain of dotted labels, none starting or ending with `-`.
    nonisolated(unsafe) static let shape =
        /^[A-Za-z0-9._%+'!#^~-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
    static let maxLength = 254

    /// The UPN in an account's `AltSecurityIdentities`: the text after the one value that
    /// starts `PlatformSSO:`. Nil when no value does, when more than one value starts with it
    /// in any case, or when the text isn't a plain ASCII UPN.
    public static func upn(fromAltSecurityIdentities values: [String]) -> String? {
        let candidates = values.filter { $0.lowercased().hasPrefix(prefix.lowercased()) }
        guard candidates.count == 1, let value = candidates.first, value.hasPrefix(prefix) else { return nil }
        let upn = String(value.dropFirst(prefix.count))
        return upn.count <= maxLength && upn.wholeMatch(of: shape) != nil ? upn : nil
    }

    /// Every local account's link, by short name; nil when the directory can't be read, as
    /// a whole or for any one account, so a failed read is never taken for links removed.
    public static func allLinks() -> [String: String]? {
        do {
            let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
            let query = try ODQuery(
                node: node, forRecordTypes: kODRecordTypeUsers, attribute: nil, matchType: ODMatchType(kODMatchAny),
                queryValues: nil, returnAttributes: [attribute], maximumResults: 0)
            var links: [String: String] = [:]
            for record in try query.resultsAllowingPartial(false) as? [ODRecord] ?? [] {
                // recordDetails leaves out an attribute the record doesn't have, where
                // values(forAttribute:) would throw the same error as for a failed read.
                let details = try record.recordDetails(forAttributes: [attribute])
                if let name = record.recordName,
                    let upn = upn(fromAltSecurityIdentities: details[attribute] as? [String] ?? [])
                {
                    links[name] = upn
                }
            }
            return links
        } catch {
            log.error("can't read Platform SSO links: \(String(describing: error), privacy: .public)")
            return nil
        }
    }
}

/// The agent's record of every account's Platform SSO link (``ElevationTracker/checkPlatformSSOLinks()``).
struct PlatformSSORecord: Codable, Equatable {
    /// Each account's link, by short name.
    var links: [String: String] = [:]
    /// The link each account last had, for accounts whose link was removed or that are gone,
    /// so linking one again to someone else counts as a change.
    var last: [String: String] = [:]
}

extension ElevationTracker {
    static let platformSSOLinksKey = "platform_sso_links"
    /// A link added or removed: Medium. Registering for Platform SSO adds one, once a user.
    static let platformSSOLinkCheck = "platform_sso_link"
    /// A link that may put an account on someone else's UPN: High. It moved to another
    /// account, or was added after the account had another, while someone held admin rights,
    /// or with an account another Mac account already has.
    static let platformSSOLinkChangedCheck = "platform_sso_link_changed"

    /// Reads every account's Platform SSO link, records it, and reports each change since the
    /// last read as `agent.tamper` (`detected`), whether or not anyone is elevated: so no
    /// account gets another person's UPN unreported. Only the very first read records without
    /// reporting. An account that is gone is dropped from the links, but its last link is
    /// kept. With `PlatformSSOIdentity` off nothing is read and an empty record is kept, so
    /// every link is reported when it is turned on again; so is an unreadable record.
    ///
    /// Runs when the daemon starts, after anything that may have opened or closed a session,
    /// and on the heartbeat.
    @discardableResult
    public func checkPlatformSSOLinks() throws -> [AltiwardEvent] {
        platformSSOLock.lock()
        defer { platformSSOLock.unlock() }
        guard env.config.platformSSOIdentity else {
            if try store.value(forKey: Self.platformSSOLinksKey) != nil { try saveRecord(PlatformSSORecord()) }
            return []
        }
        // Outside the transaction: a directory query. Unreadable, the record stands.
        guard let links = env.platformSSOLinks() else { return [] }
        let now = env.now()
        let device = env.device()

        return try store.transaction {
            guard let stored = try store.value(forKey: Self.platformSSOLinksKey) else {
                try saveRecord(PlatformSSORecord(links: links))
                return []
            }
            let record = (try? JSONDecoder().decode(PlatformSSORecord.self, from: Data(stored.utf8))) ?? PlatformSSORecord()
            let elevated = try !store.openSessions().isEmpty || !store.pendingClaims().isEmpty
            var next = PlatformSSORecord(links: links, last: record.last)
            var events: [AltiwardEvent] = []
            for user in Set(record.links.keys).union(links.keys).sorted() {
                let (before, after) = (record.links[user], links[user])
                guard before != after else { continue }
                guard let after else {
                    next.last[user] = before
                    // A gone account can't sign in or elevate; recreated, it is compared with
                    // its last link.
                    if env.accountExists(user) {
                        events.append(
                            linkEvent(
                                user, Self.platformSSOLinkCheck, before: before,
                                "\(user)'s Mac account is no longer linked to \(before ?? "-") in Platform SSO",
                                after: nil, now: now, device: device))
                    }
                    continue
                }
                next.last[user] = nil
                let last = before ?? record.last[user]
                let sharedWith = links.filter { $0.key != user && $0.value.lowercased() == after.lowercased() }.keys.sorted()
                let (check, problem): (String, String) =
                    if let before {
                        (Self.platformSSOLinkChangedCheck, "\(user)'s Mac account moved from \(before) to \(after) in Platform SSO")
                    } else if let last, last != after {
                        (
                            Self.platformSSOLinkChangedCheck,
                            "\(user)'s Mac account, last linked to \(last), is now linked to \(after) in Platform SSO"
                        )
                    } else if let other = sharedWith.first {
                        (
                            Self.platformSSOLinkChangedCheck,
                            "\(user)'s Mac account is now linked to \(after) in Platform SSO, as \(other)'s already is"
                        )
                    } else if elevated {
                        (
                            Self.platformSSOLinkChangedCheck,
                            "\(user)'s Mac account was linked to \(after) in Platform SSO while someone held admin rights"
                        )
                    } else {
                        (Self.platformSSOLinkCheck, "\(user)'s Mac account is now linked to \(after) in Platform SSO")
                    }
                events.append(linkEvent(user, check, before: last, problem, after: after, now: now, device: device))
            }
            try saveRecord(next)
            for event in events { try store.enqueue(event, now: now) }
            return events
        }
    }

    private func linkEvent(
        _ user: String, _ check: String, before: String?, _ problem: String, after: String?, now: Date,
        device: DeviceInfo
    ) -> AltiwardEvent {
        tamper(
            check, .detected, problem: problem,
            extra: [
                "user": .string(user), "previous_upn": before.map(JSONValue.string) ?? .null,
                "upn": after.map(JSONValue.string) ?? .null,
            ], now: now, device: device)
    }

    private func saveRecord(_ record: PlatformSSORecord) throws {
        try store.setValue(String(decoding: try JSONEncoder().encode(record), as: UTF8.self), forKey: Self.platformSSOLinksKey)
    }

    /// The links as last recorded; empty before the first read.
    private func recordedLinks() throws -> [String: String] {
        try store.value(forKey: Self.platformSSOLinksKey)
            .flatMap { try? JSONDecoder().decode(PlatformSSORecord.self, from: Data($0.utf8)) }?.links ?? [:]
    }

    /// A person's UPN now (``AgentConfiguration/upn(for:platformSSO:)``), with the link as
    /// recorded, never as read: a change reaches events only after it was reported.
    func upn(for user: String) -> String? {
        env.config.upn(for: user) { user in
            guard env.config.platformSSOIdentity else { return nil }
            do {
                return try recordedLinks()[user]
            } catch {
                log.error("can't read the recorded Platform SSO links: \(String(describing: error), privacy: .public)")
                return nil
            }
        }
    }

    /// The UPN a pin holds, or for a session or claim an older agent stored, the one now.
    func upn(_ pin: PinnedUPN, of user: String) -> String? {
        guard case .read(let upn) = pin else { return upn(for: user) }
        return upn
    }

    /// Who a session's events are about: the UPN it started with, so a link changed during it
    /// can't move it onto someone else.
    func sessionUser(_ session: OpenSession) -> UserInfo {
        UserInfo(localName: session.user, upn: upn(session.upn, of: session.user))
    }
}
