import Foundation
import Testing

@testable import AltiwardCore

struct SystemAdminGroupTests {
    /// Tests run unprivileged, so dseditgroup must refuse; the wrapper has to surface that
    /// as an error carrying the tool's exit status rather than report success.
    @Test(.enabled(if: getuid() != 0))
    func removalFailureIsReportedWithToolStatus() throws {
        let error = try #require(throws: SystemAdminGroup.EditFailed.self) {
            try SystemAdminGroup().removeAdmin(user: "altiward-test-no-such-user")
        }
        #expect(error.status > 0)
    }

    /// Every macOS account is in `staff`, so this exercises the generalised membership check.
    @Test func currentUserIsInStaff() {
        #expect(SystemAdminGroup().isMember(user: NSUserName(), group: "staff"))
    }

    @Test func unknownUserIsInNoGroup() {
        #expect(!SystemAdminGroup().isMember(user: "no-such-user-altiward", group: "staff"))
    }

    @Test func unknownGroupHasNoMembers() {
        #expect(!SystemAdminGroup().isMember(user: NSUserName(), group: "no-such-group-altiward"))
    }
}
