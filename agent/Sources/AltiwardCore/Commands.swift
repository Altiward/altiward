import Foundation

// Remote commands. Wire format: docs/schema/commands.

public struct AgentCommand: Codable, Sendable, Equatable {
    public var commandID: String
    public var type: String
    /// Nil: every admin on the Mac except permanent admins.
    public var user: String?
    /// Set: act only while this session is still open for `user`.
    public var sessionID: String?
    public var expiresAt: Date

    public init(commandID: String, type: String, user: String?, sessionID: String?, expiresAt: Date) {
        self.commandID = commandID
        self.type = type
        self.user = user
        self.sessionID = sessionID
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case commandID = "command_id", type, user
        case sessionID = "session_id"
        case expiresAt = "expires_at"
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(commandID, forKey: .commandID)
        try c.encode(type, forKey: .type)
        try c.encode(user, forKey: .user)
        try c.encode(sessionID, forKey: .sessionID)
        try c.encode(expiresAt, forKey: .expiresAt)
    }
}

public struct AgentCommandList: Codable, Sendable {
    public var commands: [AgentCommand]
}

public struct CommandResult: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable { case completed, failed, skipped }
    public enum SkipReason: String, Codable, Sendable {
        case permanentAdmin = "permanent_admin"
        case notAdmin = "not_admin"
        case sessionEnded = "session_ended"
    }
    public struct UserError: Codable, Sendable, Equatable {
        public var user: String
        public var error: String
    }
    public struct UserSkip: Codable, Sendable, Equatable {
        public var user: String
        public var reason: SkipReason
    }

    public var status: Status
    public var error: String?
    public var revoked: [String] = []
    public var failed: [UserError] = []
    public var skipped: [UserSkip] = []
    public var completedAt: Date

    enum CodingKeys: String, CodingKey {
        case status, error, revoked, failed, skipped
        case completedAt = "completed_at"
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(status, forKey: .status)
        try c.encode(error, forKey: .error)
        try c.encode(revoked, forKey: .revoked)
        try c.encode(failed, forKey: .failed)
        try c.encode(skipped, forKey: .skipped)
        try c.encode(completedAt, forKey: .completedAt)
    }
}

public struct CommandPollSummary: Sendable, Equatable {
    public var executed = 0
    public var reported = 0
    public var error: String?
}

/// Fetches this Mac's commands, runs them through the tracker and reports results
/// until the server acknowledges them. The tracker never runs a command twice,
/// so a redelivered command just re-reports its stored result.
public actor CommandLoop {
    private let store: AgentStore
    private let tracker: ElevationTracker
    private let authenticator: DeviceAuthenticator
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void

    public init(
        store: AgentStore, tracker: ElevationTracker, authenticator: DeviceAuthenticator,
        now: @escaping @Sendable () -> Date = { Date() }, log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.store = store
        self.tracker = tracker
        self.authenticator = authenticator
        self.now = now
        self.log = log
    }

    /// How long a long poll asks the server to hold the request; the API's limit.
    public static let longPollWait = 50

    /// Fetches and runs this Mac's commands, then reports results still owed. With `wait`,
    /// the server holds the request for up to that many seconds until a command is queued,
    /// so a revoke lands within about a second.
    @discardableResult
    public func poll(wait: Int = 0) async -> CommandPollSummary {
        var summary = CommandPollSummary()
        do {
            let (data, response, _) = try await authenticator.send(
                method: "GET", path: wait > 0 ? "v1/agent/commands?wait=\(wait)" : "v1/agent/commands", body: Data(),
                timeout: wait > 0 ? TimeInterval(wait) + 20 : 30)
            guard response.statusCode == 200 else {
                throw DeliveryError.http(status: response.statusCode, body: String(decoding: data, as: UTF8.self))
            }
            for command in try AltiwardJSON.decoder().decode(AgentCommandList.self, from: data).commands {
                let result = try tracker.execute(command)
                log("command \(command.commandID) (\(command.type)): \(result.status.rawValue)")
                summary.executed += 1
            }
        } catch {
            summary.error = String(describing: error)
        }
        // Report even when fetching failed: results from earlier polls may still be owed.
        do {
            for (id, result) in try store.unreportedCommandResults() {
                let body = try AltiwardJSON.encoder().encode(result)
                let (data, response, _) = try await authenticator.send(
                    method: "POST", path: "v1/agent/commands/\(id)/result", body: body)
                switch response.statusCode {
                case 200:
                    summary.reported += 1
                case 400, 404:
                    // The server will never take this result; retrying would loop forever.
                    log("server refused result for command \(id): \(String(decoding: data, as: UTF8.self))")
                default:
                    throw DeliveryError.http(status: response.statusCode, body: String(decoding: data, as: UTF8.self))
                }
                try store.markCommandResultReported(id: id, at: now())
            }
            try store.pruneCommandResults(reportedBefore: now().addingTimeInterval(-30 * 86400))
        } catch {
            summary.error = summary.error ?? String(describing: error)
        }
        if let error = summary.error { log("command poll: \(error)") }
        return summary
    }

    /// Seconds to pause before the next long poll. None after one the server held to its
    /// deadline. `interval` after an error, or when an empty answer came straight back, as
    /// from a server too old to hold requests. A second after commands, so a result the
    /// server keeps refusing can't turn into a tight loop.
    public static func pauseAfterLongPoll(
        _ summary: CommandPollSummary, elapsed: TimeInterval, wait: Int, interval: TimeInterval
    ) -> TimeInterval {
        if summary.error != nil { return interval }
        if summary.executed > 0 { return 1 }
        return elapsed >= TimeInterval(wait) - 5 ? 0 : interval
    }
}
