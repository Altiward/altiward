import Foundation
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "claims")

/// What ``ElevationTracker/submit(_:callerUID:)`` did with a claim.
public enum ClaimOutcome: Sendable {
    /// Recorded at once; the event was queued.
    case recorded(AltiwardEvent)
    /// A grant claim held until Privileges' log confirms it, under this id.
    case pending(claimID: String)
}

/// Grant claims while Privileges' log is available. The hook runs as the logged-in user, who
/// can run it by hand with any arguments, so a grant claim is held until SAP's own log backs
/// it. Without the log there is nothing to check a claim against, and ``record(_:callerUID:)``
/// handles it as it always has.
extension ElevationTracker {
    /// The most grant claims one caller may send in ``claimRateWindow`` seconds.
    static let maxClaimsPerMinute = 5
    /// The most give-back claims one caller may send in ``claimRateWindow`` seconds before
    /// only the ones that end a session count.
    static let maxGiveBacksPerMinute = 5
    static let claimRateWindow: TimeInterval = 60

    /// Takes a claim from the XPC handler.
    ///
    /// 1. A caller that has sent ``maxClaimsPerMinute`` grant claims in the last minute is
    ///    refused (`tooManyClaims`) before anything else, and the refusal is logged, not
    ///    reported: reporting it would let the caller flood the outbox. Give-back claims
    ///    don't count towards it. They have an allowance of their own,
    ///    ``maxGiveBacksPerMinute``: past it, a give-back that ends an open session is still
    ///    recorded, so a real give-back always is, and any other is ignored and logged
    ///    (`tooManyGiveBacks`), not recorded or reported.
    /// 2. Without the log, or for a permanent admin, a grant claim whose expiry comes from
    ///    Privileges' timer (no fixed `ExpirationInterval`) is held: reading the timer can
    ///    take seconds, and the hook waits 5 s for its answer. ``resolvePendingClaims()``
    ///    then records it as below, refusals included, without waiting for the log.
    ///    Otherwise the claim goes to ``record(_:callerUID:)``. A grant claim recorded because the log isn't available
    ///    says so (`privileges_log: "unavailable"`), and on a Mac where the agent has read the
    ///    log before it is also reported (`grant_claim`, `accepted_unconfirmed`).
    /// 3. With the log, a caller who is neither root nor the claimed user is refused
    ///    (`callerMismatch`) and reported as an `agent.tamper`.
    /// 4. A give-back claim is recorded as before.
    /// 5. A grant claim is stored as pending, with the daemon-set `invokedAt`.
    ///
    /// A claim ``record(_:callerUID:)`` refuses (`late`, `stillAdmin`,
    /// `privilegesNotInstalled`) is reported as an `agent.tamper` (`grant_claim`, `refused`)
    /// before the refusal is thrown on. Every refusal is reported except `tooManyClaims` and
    /// `tooManyGiveBacks`.
    ///
    /// The hook waits only 5 s for the answer. An answer slower than
    /// ``ClaimSteps/slowAnswer`` is logged with what it waited for (#91).
    public func submit(_ invocation: HookInvocation, callerUID: UInt32?) throws -> ClaimOutcome {
        let steps = ClaimSteps()
        defer {
            if let slow = steps.slowSummary() {
                log.notice("answered a claim for \(invocation.user, privacy: .public) in \(slow, privacy: .public)")
            }
        }
        return try submit(invocation, callerUID: callerUID, steps: steps)
    }

    private func submit(_ invocation: HookInvocation, callerUID: UInt32?, steps: ClaimSteps) throws -> ClaimOutcome {
        let now = env.now()
        if invocation.state == .admin, overTheLimit(recentClaims, Self.maxClaimsPerMinute, from: callerUID ?? 0, at: now) {
            log.notice("ignoring a claim for \(invocation.user, privacy: .public): too many grant claims from this caller")
            throw ClaimRefused(user: invocation.user, reason: .tooManyClaims)
        }
        let endingOnly =
            invocation.state == .user
            && overTheLimit(recentGiveBacks, Self.maxGiveBacksPerMinute, from: callerUID ?? 0, at: now)

        let availability = steps.time("Privileges' log check") { env.privilegesLogAvailability() }
        try notePrivilegesLog(availability)
        let permanent = env.config.permanentAdmins.contains(invocation.user)
        if invocation.state == .admin, availability != .available || permanent,
            steps.time("settings", { env.privileges().expirationIntervalMinutes == nil })
        {
            return try hold(invocation, callerUID: callerUID)
        }
        guard availability == .available, !permanent else {
            guard invocation.state == .admin, !permanent else {
                return .recorded(try reportingRefusal(invocation, callerUID: callerUID, now: now) {
                    try record(invocation, callerUID: callerUID, grantDetail: [:], endingOnly: endingOnly) { _ in nil }
                })
            }
            return .recorded(try reportingRefusal(invocation, callerUID: callerUID, now: now) {
                try recordWithoutTheLog(invocation, callerUID: callerUID, now: now)
            })
        }

        if let callerUID, callerUID != 0, let owner = steps.time("user lookup", { env.userID(invocation.user) }),
            owner != callerUID
        {
            // Another user's give-back can't end this user's session, so past the allowance
            // it isn't reported either.
            if endingOnly {
                log.notice("ignoring a give-back for \(invocation.user, privacy: .public): too many give-back claims from this caller")
                throw ClaimRefused(user: invocation.user, reason: .tooManyGiveBacks)
            }
            let refusal = ClaimRefused(user: invocation.user, reason: .callerMismatch(callerUID: callerUID))
            let event = claimRefusedEvent(
                refusal, kind: invocation.state == .admin ? "grant" : "give_back", outcome: "refused",
                callerUID: callerUID, evidence: nil, now: now, device: env.device())
            try store.transaction { try store.enqueue(event, now: now) }
            throw refusal
        }

        guard invocation.state == .admin else {
            return .recorded(try reportingRefusal(invocation, callerUID: callerUID, now: now) {
                try record(invocation, callerUID: callerUID, grantDetail: [:], endingOnly: endingOnly) { _ in nil }
            })
        }
        return try hold(invocation, callerUID: callerUID)
    }

    /// Holds a grant claim for ``resolvePendingClaims()``.
    private func hold(_ invocation: HookInvocation, callerUID: UInt32?) throws -> ClaimOutcome {
        let claimID = newID()
        try store.addPendingClaim(PendingClaim(claimID: claimID, invocation: invocation, callerUID: callerUID))
        return .pending(claimID: claimID)
    }

    /// Runs `body`, which records `invocation`, and when it throws ``ClaimRefused`` queues a
    /// `grant_claim` event (`refused`) in a transaction of its own, then throws it on. The
    /// refusal left the ledger and the outbox as they were, so the report is all it adds.
    /// `tooManyGiveBacks` is only logged.
    private func reportingRefusal(
        _ invocation: HookInvocation, callerUID: UInt32?, now: Date, _ body: () throws -> AltiwardEvent
    ) throws -> AltiwardEvent {
        do {
            return try body()
        } catch let refusal as ClaimRefused where refusal.reason == .tooManyGiveBacks {
            log.notice("ignoring a give-back for \(invocation.user, privacy: .public): too many give-back claims from this caller")
            throw refusal
        } catch let refusal as ClaimRefused {
            let event = claimRefusedEvent(
                refusal, kind: invocation.state == .admin ? "grant" : "give_back", outcome: "refused",
                callerUID: callerUID, evidence: nil, now: now, device: env.device())
            try store.transaction { try store.enqueue(event, now: now) }
            throw refusal
        }
    }

    /// Records a grant claim that would have been held, but can't be, as Privileges' log isn't
    /// available. Its event says so, and on a Mac where the log has been seen, an
    /// `agent.tamper` (`accepted_unconfirmed`) is queued with it: losing the log is how a
    /// hand-run claim would get past the check.
    private func recordWithoutTheLog(_ invocation: HookInvocation, callerUID: UInt32?, now: Date) throws
        -> AltiwardEvent
    {
        let seen = try store.value(forKey: Self.privilegesLogSeenKey) != nil
        let device = env.device()
        return try record(invocation, callerUID: callerUID, grantDetail: ["privileges_log": "unavailable"]) { event in
            guard seen else { return nil }
            return claimRefusedEvent(
                ClaimRefused(user: invocation.user, reason: .privilegesLogLost),
                kind: event.detail["renewed"] == true ? "renewal" : "grant", outcome: "accepted_unconfirmed",
                callerUID: callerUID, evidence: nil, now: now, device: device)
        }
    }

    /// Counts a claim from `uid` in `counts` and says whether it is over `limit` claims in
    /// ``claimRateWindow``. Claims over the limit aren't counted, so a caller waits out its
    /// own window instead of extending it.
    private func overTheLimit(
        _ counts: OSAllocatedUnfairLock<[UInt32: [Date]]>, _ limit: Int, from uid: UInt32, at now: Date
    ) -> Bool {
        counts.withLock { claims in
            var recent = (claims[uid] ?? []).filter { now.timeIntervalSince($0) < Self.claimRateWindow }
            defer { claims[uid] = recent.isEmpty ? nil : recent }
            guard recent.count < limit else { return true }
            recent.append(now)
            return false
        }
    }

    /// The `agent.tamper` for a claim that was refused, or accepted without confirmation.
    /// `kind` is `grant`, `renewal` or `give_back`; `outcome` is `refused` or
    /// `accepted_unconfirmed`. `evidence` is what the log held for the claim, when anything.
    func claimRefusedEvent(
        _ refusal: ClaimRefused, kind: String, outcome: String, callerUID: UInt32?, evidence: GrantEvidence?,
        now: Date, device: DeviceInfo
    ) -> AltiwardEvent {
        var extra: [String: JSONValue] = [
            "user": .string(refusal.user),
            "claimed_state": .string(kind == "give_back" ? "user" : "admin"),
            "kind": .string(kind),
            "outcome": .string(outcome),
            "reason": .string(refusal.description),
            "caller_uid": callerUID.map { .number(Double($0)) } ?? .null,
        ]
        if let evidence {
            extra["evidence_at"] = .date(evidence.date)
            extra["evidence_sources"] = .strings(evidence.sources.map(\.rawValue).sorted())
        }
        return tamper("grant_claim", .detected, problem: refusal.description, extra: extra, now: now, device: device)
    }
}

/// Resolving held grant claims: each is confirmed when Privileges' own log backs it, and once
/// its confirmation window is over without that, refused (or in `alert` mode accepted and
/// reported). Every claim leaves the store when it is resolved.
extension ElevationTracker {
    /// The pieces of evidence that have confirmed a claim, as JSON `{key: date}`, so none
    /// confirms a second one, even after a restart.
    static let consumedEvidenceKey = "grant_evidence_consumed"
    /// When the agent first found Privileges' log available on this Mac.
    static let privilegesLogSeenKey = "privileges_log_seen"
    /// Set when a grant was confirmed by the daemon's line alone while the extension's log was
    /// available, so the extension isn't logging; cleared when a confirmed grant carries the
    /// extension's record.
    static let extensionSilentKey = "extension_silent_since"
    /// How long spent evidence is remembered: well past any claim that could still use it.
    static let consumedEvidenceKept: TimeInterval = 5 * 60

    /// Resolves the held grant claims, oldest first, and returns the events it queued.
    ///
    /// - Privileges' log backs the claim (``ClaimEvidence/find(user:claimedAt:now:daemonLines:records:identity:consumed:lookBack:window:)``,
    ///   from ``ClaimEvidence/lookBack`` before it arrived to ``grantReplacementWindow``
    ///   after): the grant is recorded as ``record(_:callerUID:)`` would, with its expiry
    ///   counted from the evidence, and replaces an out-of-band session however late
    ///   (`privileges_log: "confirmed"`). The evidence is spent.
    /// - The evidence is the daemon's line alone, Privileges' log is available, and the line
    ///   is less than ``ClaimEvidence/combineWithin`` old: it stays held for the next check.
    ///   The extension's record lands a moment after the line and can take up to a second to
    ///   be readable, and confirming without it would fail `grant_confirmation` for nothing.
    /// - Nothing backs it and Privileges' log has become unavailable since it was held: it is
    ///   resolved at once, as no evidence can arrive. A grant is recorded with
    ///   `privileges_log: "unavailable"` and reported (`accepted_unconfirmed`), in every
    ///   mode, as it would have been had it arrived without the log: losing the log must not
    ///   strip a real grant. A renewal is still refused.
    /// - Nothing backs it yet and its window (``grantReplacementWindow`` after it arrived)
    ///   isn't over: it stays held, as the log can lag the grant.
    /// - The window is over. A renewal (the user is admin with a Privileges session open) is
    ///   refused in every mode and the session keeps its expiry. A grant is refused in
    ///   `OutOfBandEnforcement` `enforce` mode, and rights the user holds without a session
    ///   become out of band from when they were first seen; in other modes it is recorded
    ///   with `privileges_log: "not_confirmed"`. Each is reported as an `agent.tamper`
    ///   (`grant_claim`).
    ///
    /// The log is read once, outside the store's transaction, and the decisions are made
    /// inside one, on the claims still held then.
    @discardableResult
    public func resolvePendingClaims() throws -> [AltiwardEvent] {
        let held = try store.pendingClaims()
        guard let oldest = held.first else { return [] }
        let now = env.now()
        let device = env.device()
        let availability = env.privilegesLogAvailability()
        let window = Self.grantReplacementWindow

        // Read outside the transaction: the log and the code-signature checks take a moment.
        let since = oldest.invocation.invokedAt.addingTimeInterval(-ClaimEvidence.lookBack)
        let users = Set(held.map(\.invocation.user))
        let lines = env.privilegesDaemonLines(since).filter { users.contains($0.user) }
        let records = env.privilegesAudit(since)
        let pids = Set(lines.map(\.loggerPID) + records.filter { users.contains($0.subject) }.map(\.loggerPID))
        let identities = Dictionary(uniqueKeysWithValues: pids.map { ($0, env.processIdentity($0)) })
        func evidence(for claim: PendingClaim, consumed: Set<String>) -> GrantEvidence? {
            ClaimEvidence.find(
                user: claim.invocation.user, claimedAt: claim.invocation.invokedAt, now: now, daemonLines: lines,
                records: records, identity: { identities[$0] ?? nil }, consumed: consumed,
                lookBack: ClaimEvidence.lookBack, window: window)
        }
        // The daemon's line alone, while the extension's record of the same grant may still
        // be on its way: the claim waits for the next check rather than confirm without it.
        func awaitingExtension(_ found: GrantEvidence) -> Bool {
            !found.sources.contains(.systemExtension) && availability == .available
                && now < found.date.addingTimeInterval(ClaimEvidence.combineWithin)
        }
        func windowOver(_ claim: PendingClaim) -> Bool {
            now >= claim.invocation.invokedAt.addingTimeInterval(window)
        }
        let logLost = availability != .available

        // And Privileges' timer, for each claim that may be recorded: it can wait a moment
        // for Privileges to write it. A fixed ExpirationInterval decides the expiry without it.
        var timers: [String: Date] = [:]
        if env.privileges().expirationIntervalMinutes == nil {
            var consumed = Set(try consumedEvidence().keys)
            for claim in held {
                if env.config.permanentAdmins.contains(claim.invocation.user) {
                    timers[claim.claimID] = env.privilegesTimer(claim.invocation.user, claim.invocation.invokedAt)
                } else if let found = evidence(for: claim, consumed: consumed) {
                    guard !awaitingExtension(found) else { continue }
                    consumed.formUnion(found.keys)
                    timers[claim.claimID] = env.privilegesTimer(claim.invocation.user, found.date)
                } else if logLost || (windowOver(claim) && env.config.outOfBandEnforcement != .enforce) {
                    timers[claim.claimID] = env.privilegesTimer(claim.invocation.user, claim.invocation.invokedAt)
                }
            }
        }

        let ids = Set(held.map(\.claimID))
        return try store.transaction {
            try notePrivilegesLog(availability)
            let seen = try store.value(forKey: Self.privilegesLogSeenKey) != nil
            var consumed = try consumedEvidence()
            var events: [AltiwardEvent] = []
            func queue(_ event: AltiwardEvent) throws {
                try store.enqueue(event, now: now)
                events.append(event)
            }

            // Read again inside the transaction: another check may have resolved some already.
            for claim in try store.pendingClaims() where ids.contains(claim.claimID) {
                let invocation = claim.invocation
                // Held only so Privileges' timer was read after the hook's call, by a permanent
                // admin or on a Mac that has never had the log: recorded as that call would have.
                let permanent = env.config.permanentAdmins.contains(invocation.user)
                if permanent || (logLost && !seen) {
                    try store.removePendingClaim(id: claim.claimID)
                    do {
                        let granted = try applyGrant(
                            invocation, callerUID: claim.callerUID, grantedAt: invocation.invokedAt,
                            timer: timers[claim.claimID],
                            extraDetail: permanent ? [:] : ["privileges_log": "unavailable"],
                            skipLateCheck: false, device: device)
                        if let replaced = granted.replaced { try queue(replaced) }
                        try queue(granted.event)
                    } catch let refusal as ClaimRefused {
                        try queue(
                            claimRefusedEvent(
                                refusal, kind: "grant", outcome: "refused", callerUID: claim.callerUID, evidence: nil,
                                now: now, device: device))
                    }
                    continue
                }
                if let found = evidence(for: claim, consumed: Set(consumed.keys)) {
                    // Held, its evidence unspent: the next check confirms it, with or without
                    // the extension's record.
                    guard !awaitingExtension(found) else { continue }
                    try store.removePendingClaim(id: claim.claimID)
                    for key in found.keys { consumed[key] = found.date }
                    do {
                        let granted = try applyGrant(
                            invocation, callerUID: claim.callerUID, grantedAt: found.date,
                            timer: timers[claim.claimID],
                            extraDetail: [
                                "privileges_log": "confirmed", "confirmed_at": .date(now),
                                "evidence": .strings(found.sources.map(\.rawValue).sorted()),
                            ],
                            skipLateCheck: true, device: device)
                        if let replaced = granted.replaced { try queue(replaced) }
                        try queue(granted.event)
                    } catch let refusal as ClaimRefused {
                        // In enforce mode on a Mac that doesn't report SAP Privileges installed.
                        try queue(
                            claimRefusedEvent(
                                refusal, kind: "grant", outcome: "refused", callerUID: claim.callerUID,
                                evidence: found, now: now, device: device))
                        continue
                    }
                    if found.sources.contains(.systemExtension) {
                        try store.setValue(nil, forKey: Self.extensionSilentKey)
                    } else if availability == .available, try store.value(forKey: Self.extensionSilentKey) == nil {
                        try store.setValue(AltiwardJSON.format(found.date), forKey: Self.extensionSilentKey)
                    }
                    continue
                }

                guard logLost || windowOver(claim) else { continue }
                try store.removePendingClaim(id: claim.claimID)
                let isAdmin = env.admins.isAdmin(user: invocation.user)
                let open = try store.openSession(user: invocation.user)
                if isAdmin, open?.source == .privileges {
                    // A real renewal sends no claim, so this one moves nothing, in any mode.
                    try queue(
                        claimRefusedEvent(
                            ClaimRefused(user: invocation.user, reason: .notConfirmed(renewal: true)), kind: "renewal",
                            outcome: "refused", callerUID: claim.callerUID, evidence: nil, now: now, device: device))
                } else if logLost {
                    // As the immediate path records a grant claim without the log, late check included.
                    do {
                        let granted = try applyGrant(
                            invocation, callerUID: claim.callerUID, grantedAt: invocation.invokedAt,
                            timer: timers[claim.claimID], extraDetail: ["privileges_log": "unavailable"],
                            skipLateCheck: false, device: device)
                        if let replaced = granted.replaced { try queue(replaced) }
                        try queue(granted.event)
                        try queue(
                            claimRefusedEvent(
                                ClaimRefused(user: invocation.user, reason: .privilegesLogLost), kind: "grant",
                                outcome: "accepted_unconfirmed", callerUID: claim.callerUID, evidence: nil, now: now,
                                device: device))
                    } catch let refusal as ClaimRefused {
                        try queue(
                            claimRefusedEvent(
                                refusal, kind: "grant", outcome: "refused", callerUID: claim.callerUID, evidence: nil,
                                now: now, device: device))
                    }
                } else if env.config.outOfBandEnforcement == .enforce {
                    try queue(
                        claimRefusedEvent(
                            ClaimRefused(user: invocation.user, reason: .notConfirmed(renewal: false)), kind: "grant",
                            outcome: "refused", callerUID: claim.callerUID, evidence: nil, now: now, device: device))
                    // Out of band from when the rights were first seen, so a hand-run claim
                    // doesn't lengthen the grace period.
                    if isAdmin, open == nil, !env.config.permanentAdmins.contains(invocation.user) {
                        let firstSeen = untrackedSince.withLock { $0[invocation.user] } ?? invocation.invokedAt
                        try queue(
                            openOutOfBand(
                                invocation.user, now: now, startedAt: min(firstSeen, invocation.invokedAt),
                                device: device, audit: records))
                    }
                } else {
                    let granted = try applyGrant(
                        invocation, callerUID: claim.callerUID, grantedAt: invocation.invokedAt,
                        timer: timers[claim.claimID], extraDetail: ["privileges_log": "not_confirmed"],
                        skipLateCheck: false, device: device)
                    if let replaced = granted.replaced { try queue(replaced) }
                    try queue(granted.event)
                    try queue(
                        claimRefusedEvent(
                            ClaimRefused(user: invocation.user, reason: .notConfirmed(renewal: false)), kind: "grant",
                            outcome: "accepted_unconfirmed", callerUID: claim.callerUID, evidence: nil, now: now,
                            device: device))
                }
            }

            try saveConsumedEvidence(consumed, now: now)
            return events
        }
    }

    /// ``resolvePendingClaims()`` for the checks that run it first. A failure is logged and
    /// leaves the claims held, so it can't stop the check after it.
    func resolveHeldClaims() -> [AltiwardEvent] {
        do {
            return try resolvePendingClaims()
        } catch {
            log.error("resolving held grant claims failed: \(String(describing: error), privacy: .public)")
            return []
        }
    }

    /// Users with a claim held and still in its confirmation window: the untracked-admin
    /// checks don't raise them out-of-band yet. A claim left held past its window (when
    /// resolving fails) no longer holds anything back.
    func heldUsers(now: Date) throws -> Set<String> {
        Set(
            try store.pendingClaims()
                .filter { now < $0.invocation.invokedAt.addingTimeInterval(Self.grantReplacementWindow) }
                .map(\.invocation.user))
    }

    /// Remembers that Privileges' log has been available on this Mac, from when it first was.
    func notePrivilegesLog(_ availability: PrivilegesLogAvailability) throws {
        guard availability == .available, try store.value(forKey: Self.privilegesLogSeenKey) == nil else { return }
        try store.setValue(AltiwardJSON.format(env.now()), forKey: Self.privilegesLogSeenKey)
    }

    /// The evidence already spent. Only this daemon writes it, as root; an unreadable value is
    /// logged and treated as empty.
    private func consumedEvidence() throws -> [String: Date] {
        guard let raw = try store.value(forKey: Self.consumedEvidenceKey) else { return [:] }
        guard let stored = try? JSONDecoder().decode([String: String].self, from: Data(raw.utf8)) else {
            log.error("ignoring unreadable \(Self.consumedEvidenceKey, privacy: .public)")
            return [:]
        }
        return stored.compactMapValues(AltiwardJSON.parse)
    }

    /// Saves the spent evidence, without what no claim can use now: entries from more than
    /// ``consumedEvidenceKept`` before both now and the oldest claim still held.
    private func saveConsumedEvidence(_ consumed: [String: Date], now: Date) throws {
        let oldestHeld = try store.pendingClaims().first?.invocation.invokedAt ?? now
        let cutoff = min(now, oldestHeld).addingTimeInterval(-Self.consumedEvidenceKept)
        let kept = consumed.filter { $0.value >= cutoff }
        guard !kept.isEmpty else {
            try store.setValue(nil, forKey: Self.consumedEvidenceKey)
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(kept.mapValues(AltiwardJSON.format))
        try store.setValue(String(decoding: data, as: UTF8.self), forKey: Self.consumedEvidenceKey)
    }
}

/// How long answering one hook claim took, and its steps that can wait: what the agent logs
/// when the answer is slow. The rest is recording the claim, waiting for the store included.
final class ClaimSteps {
    /// Well inside the hook's 5 s, so a slow Mac shows up before the hook times out.
    static let slowAnswer: TimeInterval = 1

    private let started: TimeInterval
    private let uptime: () -> TimeInterval
    private var steps: [(name: String, seconds: TimeInterval)] = []

    init(uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.uptime = uptime
        started = uptime()
    }

    func time<T>(_ name: String, _ body: () throws -> T) rethrows -> T {
        let start = uptime()
        defer { steps.append((name, uptime() - start)) }
        return try body()
    }

    /// "3.2 s (Privileges' log check 0.1 s, settings 0.0 s, recording 3.1 s)", or nil
    /// when the answer took less than ``slowAnswer``.
    func slowSummary() -> String? {
        let total = uptime() - started
        guard total >= Self.slowAnswer else { return nil }
        let rest = total - steps.reduce(0) { $0 + $1.seconds }
        let parts = (steps + [("recording", max(rest, 0))]).map { "\($0.name) \(Self.seconds($0.seconds))" }
        return "\(Self.seconds(total)) (\(parts.joined(separator: ", ")))"
    }

    private static func seconds(_ t: TimeInterval) -> String { String(format: "%.1f s", t) }
}
