import Foundation

/// Tamper reporting. The heartbeat runs the integrity checks and sends `agent.tamper`
/// when one changes: `failed` when it starts failing (or fails the first time it runs),
/// `restored` when it passes again, `retired` when a failing check stops applying (so its
/// alert doesn't stay open), and `detected` for a one-off finding: a downgrade, or an
/// attempt Privileges blocked (``blockedEvents(_:now:device:)``).
/// The last result of each check is kept in the store, so a restart doesn't repeat alerts.
extension ElevationTracker {
    static let integrityKey = "integrity_state"
    static let versionKey = "agent_version_seen"

    public enum TamperState: String, Sendable {
        case failed
        case restored
        case retired
        case detected
    }

    /// Runs inside the heartbeat's transaction.
    func tamperEvents(_ results: [IntegrityCheck: IntegrityResult], now: Date, device: DeviceInfo) throws
        -> [AltiwardEvent]
    {
        let previous = try store.value(forKey: Self.integrityKey)
            .flatMap { try? JSONDecoder().decode([String: Bool].self, from: Data($0.utf8)) } ?? [:]
        var events: [AltiwardEvent] = []
        for (check, result) in results.sorted(by: { $0.key < $1.key }) {
            let before = previous[check.rawValue]
            // Unchanged, or passing the first time it runs: nothing to say.
            guard before != result.ok, !(before == nil && result.ok) else { continue }
            events.append(
                tamper(
                    check.rawValue, result.ok ? .restored : .failed, problem: result.problem, now: now, device: device))
        }
        // A check that no longer applies is forgotten, closing its alert if it was failing. That
        // includes a stored name this agent no longer knows, from an earlier version's check.
        for (name, passing) in previous.sorted(by: { $0.key < $1.key }) where !passing {
            let check = IntegrityCheck(rawValue: name)
            if let check, results[check] != nil { continue }
            let reason = check.map { retiredReason($0, device: device) } ?? "Altiward no longer runs this check"
            events.append(tamper(name, .retired, problem: reason, now: now, device: device))
        }
        let state = Dictionary(uniqueKeysWithValues: results.map { ($0.key.rawValue, $0.value.ok) })
        try store.setValue(
            String(decoding: try JSONEncoder().encode(state), as: UTF8.self), forKey: Self.integrityKey)

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
        case .privilegesTamperProtection, .privilegesHook, .privilegesTimer:
            return "SAP Privileges isn't installed now"
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
