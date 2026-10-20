import Foundation
import Testing

@testable import AltiwardCore

struct HookInvocationTests {
    let now = Date(timeIntervalSince1970: 1_792_000_000)

    @Test func parsesGrantWithReason() throws {
        let inv = try HookInvocation.parse(arguments: ["jdoe", "admin", "Installing Xcode"], now: now)
        #expect(inv == HookInvocation(user: "jdoe", state: .admin, reason: "Installing Xcode", invokedAt: now))
    }

    @Test func parsesRevokeWithoutReason() throws {
        let inv = try HookInvocation.parse(arguments: ["jdoe", "user"], now: now)
        #expect(inv.state == .user)
        #expect(inv.reason == nil)
    }

    @Test func blankReasonIsNil() throws {
        let inv = try HookInvocation.parse(arguments: ["jdoe", "admin", "   "], now: now)
        #expect(inv.reason == nil)
    }

    @Test func joinsSplitReason() throws {
        let inv = try HookInvocation.parse(arguments: ["jdoe", "admin", "fix", "printer"], now: now)
        #expect(inv.reason == "fix printer")
    }

    @Test func capsReasonLength() throws {
        let long = String(repeating: "x", count: 5000)
        let inv = try HookInvocation.parse(arguments: ["jdoe", "admin", long], now: now)
        #expect(inv.reason?.count == HookInvocation.maxReasonLength)

        let spaced = String(repeating: "x", count: 2047) + "   tail"
        let cut = try HookInvocation.parse(arguments: ["jdoe", "admin", spaced], now: now)
        #expect(cut.reason == String(repeating: "x", count: 2047))
    }

    @Test func stateIsCaseInsensitive() throws {
        #expect(try HookInvocation.parse(arguments: ["jdoe", "ADMIN"]).state == .admin)
    }

    @Test func rejectsMissingArguments() {
        #expect(throws: HookArgumentError.missingArguments(count: 1)) {
            try HookInvocation.parse(arguments: ["jdoe"])
        }
    }

    @Test(arguments: ["", "a b", "../etc", "-rf", "x:y", "tab\tname"])
    func rejectsBadUserNames(_ name: String) {
        #expect(throws: HookArgumentError.invalidUser(name)) {
            try HookInvocation.parse(arguments: [name, "admin"])
        }
    }

    @Test func rejectsUnknownState() {
        #expect(throws: HookArgumentError.invalidState("root")) {
            try HookInvocation.parse(arguments: ["jdoe", "root"])
        }
    }

    @Test func roundTripsThroughJSONForXPC() throws {
        let inv = HookInvocation(user: "jdoe", state: .admin, reason: "r", invokedAt: now)
        let data = try AltiwardJSON.encoder().encode(inv)
        #expect(try AltiwardJSON.decoder().decode(HookInvocation.self, from: data) == inv)
    }
}
