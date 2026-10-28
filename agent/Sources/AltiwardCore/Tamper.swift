import Foundation

/// Tamper reporting. The heartbeat runs the integrity checks and sends `agent.tamper`
/// when one changes: `failed` when it starts failing (or fails the first time it runs),
/// `restored` when it passes again, `retired` when a failing check stops applying (so its
/// alert doesn't stay open), and `detected` for a one-off finding: a downgrade, or an
/// attempt Privileges blocked (``blockedEvents(_:now:device:)``). A failing check that names
/// what fails (``IntegrityResult/findings``) is reported `failed` again when that changes.
/// The last result of each check is kept in the store, so a restart doesn't repeat alerts.
extension ElevationTracker {
    static let integrityKey = "integrity_state"
    /// What each failing check named, by check: `{"settings_managed": ["…", …]}`.
    static let integrityFindingsKey = "integrity_findings"
    /// When each check that says so last looked (``IntegrityResult/observedAt``), in seconds
    /// since 1970, so an older result doesn't overwrite a newer one.
    static let integrityObservedKey = "integrity_observed_at"
    /// When each check was last reported failed, for spacing out reports of a changed failure.
    static let integrityReportedKey = "integrity_reported_at"
    static let versionKey = "agent_version_seen"
    /// The least time between two `failed` reports of a check that only changed what fails.
    static let changedFailureInterval: TimeInterval = 600

    public enum TamperState: String, Sendable {
        case failed
        case restored
        case retired
        case detected
    }

    /// Runs inside the heartbeat's transaction. With `partial`, `results` holds only some
    /// checks (``checkManagedSettings()``): the others keep their state, and none is retired.
    func tamperEvents(
        _ results: [IntegrityCheck: IntegrityResult], now: Date, device: DeviceInfo, partial: Bool = false
    ) throws -> [AltiwardEvent] {
        func stored<T: Decodable>(_ key: String, as: T.Type) throws -> T? {
            try store.value(forKey: key).flatMap { try? JSONDecoder().decode(T.self, from: Data($0.utf8)) }
        }
        let previous = try stored(Self.integrityKey, as: [String: Bool].self) ?? [:]
        let previousFindings = try stored(Self.integrityFindingsKey, as: [String: [String]].self) ?? [:]
        let observed = try stored(Self.integrityObservedKey, as: [String: Double].self) ?? [:]
        var reported = try stored(Self.integrityReportedKey, as: [String: Double].self) ?? [:]
        var events: [AltiwardEvent] = []
        var state = partial ? previous : [:]
        var findings = partial ? previousFindings : [:]
        var observedNow = observed
        for (check, result) in results.sorted(by: { $0.key < $1.key }) {
            let name = check.rawValue
            var before = previous[name]
            var beforeFindings = previousFindings[name]
            // A failure that came and went since the last run: said first, unless already said,
            // and even when the rest of this result is too old to count, as it is the only report
            // of that failure.
            var reportedEarlier = false
            if let earlier = result.earlier,
                !(before == false && Set(earlier.findings).isSubset(of: Set(beforeFindings ?? [])))
            {
                events.append(tamper(name, .failed, problem: earlier.problem, now: now, device: device))
                before = false
                beforeFindings = earlier.findings
                reported[name] = now.timeIntervalSince1970
                reportedEarlier = true
            }
            // Looked before the result already recorded (the heartbeat read while a file change
            // was checked): the newer one stands, so the next result sends `restored` if the
            // earlier failure is gone.
            if let at = result.observedAt?.timeIntervalSince1970, let last = observed[name], at < last {
                state[name] = before
                findings[name] = beforeFindings
                continue
            }
            if let at = result.observedAt { observedNow[name] = at.timeIntervalSince1970 }
            if result.held {
                // Keeps whatever it had, including not having run yet.
                state[name] = before
                findings[name] = beforeFindings
                continue
            }
            let changes = before != result.ok && !(before == nil && result.ok)
            // Still failing, but on something else: a later problem mustn't hide behind the first.
            // At most once every ``changedFailureInterval``, so a changing failure can't flood the SIEM;
            // until then the findings last reported are kept, so the change is reported later.
            let other = before == false && !result.ok && result.findings != nil && beforeFindings != result.findings
            if other, !changes, !reportedEarlier, let last = reported[name],
                now.timeIntervalSince1970 - last < Self.changedFailureInterval
            {
                state[name] = false
                findings[name] = beforeFindings
                continue
            }
            state[name] = result.ok
            findings[name] = result.ok ? nil : result.findings
            // Unchanged, or passing the first time it runs: nothing to say.
            guard changes || other else { continue }
            events.append(tamper(name, result.ok ? .restored : .failed, problem: result.problem, now: now, device: device))
            if !result.ok { reported[name] = now.timeIntervalSince1970 }
        }
        if !partial {
            // A check that no longer applies is forgotten, closing its alert if it was failing. That
            // includes a stored name this agent no longer knows, from an earlier version's check.
            for (name, passing) in previous.sorted(by: { $0.key < $1.key }) where !passing {
                let check = IntegrityCheck(rawValue: name)
                if let check, results[check] != nil { continue }
                let reason = check.map { retiredReason($0, device: device) } ?? "Altiward no longer runs this check"
                events.append(tamper(name, .retired, problem: reason, now: now, device: device))
            }
        }
        try store.setValue(
            String(decoding: try JSONEncoder().encode(state), as: UTF8.self), forKey: Self.integrityKey)
        try store.setValue(
            String(decoding: try JSONEncoder().encode(findings), as: UTF8.self), forKey: Self.integrityFindingsKey)
        try store.setValue(
            String(decoding: try JSONEncoder().encode(observedNow), as: UTF8.self), forKey: Self.integrityObservedKey)
        try store.setValue(
            String(decoding: try JSONEncoder().encode(reported), as: UTF8.self), forKey: Self.integrityReportedKey)
        guard !partial else { return events }

        if let seen = try store.value(forKey: Self.versionKey), AgentVersion.isOlder(device.agentVersion, than: seen) {
            events.append(
                tamper(
                    IntegrityCheck.agentVersion.rawValue, .detected,
                    problem: "the agent went from \(seen) to \(device.agentVersion)",
                    extra: ["previous_version": .string(seen), "current_version": .string(device.agentVersion)],
                    now: now, device: device))
        }
        try store.setValue(device.agentVersion, forKey: Self.versionKey)
        return events
    }

    /// Why a check no longer runs, from what decides whether it applies (SystemIntegrity).
    private func retiredReason(_ check: IntegrityCheck, device: DeviceInfo) -> String {
        switch check {
        case .privilegesTamperProtection, .privilegesHook, .privilegesTimer, .privilegesExpiryCap,
            .privilegesGiveBackHook, .privilegesRevokeExclusions:
            return "SAP Privileges isn't installed now"
        case .privilegesRenewal:
            return device.privilegesVersion == nil
                ? "SAP Privileges isn't installed now" : "ExpiryEnforcement isn't enforce now"
        case .grantConfirmation:
            return device.privilegesVersion == nil
                ? "SAP Privileges isn't installed now"
                : "neither OutOfBandEnforcement nor ExpiryEnforcement is enforce now"
        default:
            return "the check no longer applies on this Mac"
        }
    }

    func tamper(
        _ check: String, _ state: TamperState, problem: String?, extra: [String: JSONValue] = [:], now: Date,
        device: DeviceInfo
    ) -> AltiwardEvent {
        var detail: [String: JSONValue] = [
            "check": .string(check), "state": .string(state.rawValue),
            "problem": problem.map(JSONValue.string) ?? .null,
        ]
        detail.merge(extra) { $1 }
        return AltiwardEvent(
            type: .agentTamper, sessionID: nil, timestamp: now, device: device, user: nil, elevation: nil, detail: detail)
    }
}
