import Foundation

/// The arguments SAP Privileges passes to its post-change executable.
///
/// Privileges (via `PostChangeExecutablePath`) runs the hook as the logged-in user with
/// `$1` = short user name, `$2` = `admin` or `user`, and, when `PassReasonToExecutable`
/// is enabled, `$3` = the reason the user typed. Nothing here is trusted by itself:
/// the daemon re-checks real `admin` group membership before recording the change.
public struct HookInvocation: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        case admin
        case user
    }

    public static let maxReasonLength = 2048

    public var user: String
    public var state: State
    public var reason: String?
    public var invokedAt: Date

    public init(user: String, state: State, reason: String?, invokedAt: Date) {
        self.user = user
        self.state = state
        self.reason = reason
        self.invokedAt = invokedAt
    }

    /// Parses `CommandLine.arguments` minus the program name.
    public static func parse(arguments: [String], now: Date = Date()) throws(HookArgumentError) -> HookInvocation {
        guard arguments.count >= 2 else {
            throw .missingArguments(count: arguments.count)
        }
        let user = arguments[0]
        guard isValidShortName(user) else {
            throw .invalidUser(user)
        }
        guard let state = State(rawValue: arguments[1].lowercased()) else {
            throw .invalidState(arguments[1])
        }
        // Privileges passes the reason as one argument; join defensively in case a
        // wrapper script splits it on whitespace.
        let reason = normalizedReason(arguments.dropFirst(2).joined(separator: " "))
        return HookInvocation(user: user, state: state, reason: reason, invokedAt: now)
    }

    /// Trims the reason and cuts it to `maxReasonLength`, trimming again in case the cut
    /// lands on whitespace. Nil when nothing is left.
    public static func normalizedReason(_ raw: String?) -> String? {
        let trimmed = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let reason = String(trimmed.prefix(maxReasonLength)).trimmingCharacters(in: .whitespacesAndNewlines)
        return reason.isEmpty ? nil : reason
    }

    /// macOS short names: no whitespace, slashes, colons or control characters; at most 255 bytes.
    static func isValidShortName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 255, !name.hasPrefix("-") else { return false }
        let forbidden = CharacterSet.whitespacesAndNewlines
            .union(.controlCharacters)
            .union(CharacterSet(charactersIn: "/:"))
        return name.unicodeScalars.allSatisfy { !forbidden.contains($0) }
    }
}

public enum HookArgumentError: Error, Equatable, CustomStringConvertible {
    case missingArguments(count: Int)
    case invalidUser(String)
    case invalidState(String)

    public var description: String {
        switch self {
        case .missingArguments(let count):
            "expected at least 2 arguments (user, admin|user), got \(count)"
        case .invalidUser(let user):
            "invalid user name: \(user.debugDescription)"
        case .invalidState(let state):
            "invalid state \(state.debugDescription); expected admin or user"
        }
    }
}
