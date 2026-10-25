import Foundation
import Testing
import os

@testable import AltiwardCore

/// Renewals in SAP Privileges send no hook claim, so the agent reads them from
/// `PrivilegesAgent`'s log line and moves the session's expiry (#90).
struct PrivilegesRenewalTests {
    let clock = TestClock()
    let admins = FakeAdmins(["jdoe"])
    static let genuine = "41F96DF4-4BFD-3F1D-8084-E9B02CE1ABBB"
    static let agentPID: Int32 = 1600

    /// A tracker with expiry enforcement on, grants that last 20 minutes by Privileges' timer
    /// within a 60 minute maximum, and SAP's agent running as jdoe (uid 501).
    func tracker(
        lines: [PrivilegesRenewalLine], reads: OSAllocatedUnfairLock<Int> = .init(initialState: 0),
        privileges: PrivilegesSettings = PrivilegesSettings(expirationIntervalMaxMinutes: 60),
        identity: ProcessIdentity? = nil
    ) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let clock = clock
        let started = clock.now.addingTimeInterval(-3600)
        let agent =
            identity
            ?? ProcessIdentity(
                signingID: PrivilegesSigning.agent, teamID: PrivilegesSigning.teamID, startedAt: started, uid: 501)
        let env = makeEnvironment(
            admins: admins, clock: clock, privileges: privileges,
            config: AgentConfiguration(expiryEnforcement: .enforce, expiryGracePeriod: 300),
            privilegesTimer: { _, granted in granted.addingTimeInterval(20 * 60) },
            privilegesLogAvailability: { .available },
            processIdentity: { $0 == Self.agentPID ? agent : nil },
            userID: { $0 == "jdoe" ? 501 : nil },
            privilegesRenewals: { since in
                reads.withLock { $0 += 1 }
                return lines.filter { $0.date >= since }
            },
            privilegesAgentImageUUIDs: { [Self.genuine] })
        return (ElevationTracker(store: store, environment: env), store)
    }

    func renewal(at date: Date, minutes: Int = 60, uid: UInt32 = 501, image: String = genuine) -> PrivilegesRenewalLine {
        PrivilegesRenewalLine(date: date, user: "jdoe", minutes: minutes, pid: Self.agentPID, uid: uid, imageUUID: image)
    }

    func grant(_ tracker: ElevationTracker) throws -> AltiwardEvent {
        try tracker.record(HookInvocation(user: "jdoe", state: .admin, reason: "work", invokedAt: clock.now))
    }

    @Test func aRenewalMovesTheExpirySoEnforcementKeepsTheRights() throws {
        let granted = clock.now
        let renewedAt = granted.addingTimeInterval(15 * 60)
        let (tracker, store) = try tracker(lines: [renewal(at: renewedAt)])
        let grant = try grant(tracker)
        #expect(grant.elevation?.expires == granted.addingTimeInterval(20 * 60))

        clock.advance(16 * 60)
        let events = try tracker.heartbeat()
        let renewed = try #require(events.first { $0.type == .elevationGranted })
        #expect(renewed.sessionID == grant.sessionID)
        #expect(renewed.timestamp == renewedAt)
        #expect(renewed.detail["renewed"] == true)
        #expect(renewed.detail["trigger"] == "privileges_renewal")
        #expect(renewed.detail["renewed_minutes"] == 60)
        // 60 minutes from the renewal, within ExpirationIntervalMax counted from it too.
        #expect(renewed.elevation?.expires == renewedAt.addingTimeInterval(60 * 60))
        #expect(try store.openSession(user: "jdoe")?.expiresAt == renewedAt.addingTimeInterval(60 * 60))

        // Past the old expiry and its grace: the rights stay.
        clock.advance(20 * 60)
        let later = try tracker.heartbeat()
        #expect(!later.contains { $0.type == .elevationExpiredEnforced || $0.type == .elevationOverdue })
        #expect(admins.isAdmin(user: "jdoe"))
        // Read again, the same line changes nothing.
        #expect(!later.contains { $0.type == .elevationGranted })
    }

    @Test func aRenewalIsCappedByTheMaximum() throws {
        let renewedAt = clock.now.addingTimeInterval(15 * 60)
        let (tracker, store) = try tracker(lines: [renewal(at: renewedAt, minutes: 240)])
        _ = try grant(tracker)
        clock.advance(16 * 60)
        let renewed = try #require(try tracker.heartbeat().first { $0.type == .elevationGranted })
        #expect(renewed.detail["expires_basis"] == "ExpirationIntervalMax")
        #expect(try store.openSession(user: "jdoe")?.expiresAt == renewedAt.addingTimeInterval(60 * 60))
    }

    @Test(arguments: [
        "a copy of the agent that isn't SAP's executable", "another user's process", "a process that has gone",
        "an agent that isn't SAP's", "a process started after the line",
    ])
    func aLineNotFromSAPsAgentIsIgnored(_ why: String) throws {
        let renewedAt = clock.now.addingTimeInterval(15 * 60)
        var line = renewal(at: renewedAt)
        var identity: ProcessIdentity? = ProcessIdentity(
            signingID: PrivilegesSigning.agent, teamID: PrivilegesSigning.teamID,
            startedAt: clock.now.addingTimeInterval(-3600), uid: 501)
        switch why {
        case "a copy of the agent that isn't SAP's executable": line.imageUUID = "00000000-0000-0000-0000-000000000000"
        case "another user's process": line.uid = 502
        case "a process that has gone": line.pid = 999
        case "an agent that isn't SAP's": identity?.teamID = "AAAAAAAAAA"
        default: identity?.startedAt = renewedAt.addingTimeInterval(1)
        }
        let (tracker, store) = try tracker(lines: [line], identity: identity)
        let grant = try grant(tracker)
        clock.advance(16 * 60)
        #expect(!(try tracker.heartbeat()).contains { $0.type == .elevationGranted })
        #expect(try store.openSession(user: "jdoe")?.expiresAt == grant.elevation?.expires)
    }

    @Test func withRenewalsTurnedOffByMDMTheLogIsntRead() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let (tracker, store) = try tracker(
            lines: [renewal(at: clock.now.addingTimeInterval(15 * 60))], reads: reads,
            privileges: PrivilegesSettings(expirationIntervalMaxMinutes: 60, allowPrivilegeRenewal: false))
        let grant = try grant(tracker)
        clock.advance(16 * 60)
        _ = try tracker.heartbeat()
        #expect(reads.withLock { $0 } == 0)
        #expect(try store.openSession(user: "jdoe")?.expiresAt == grant.elevation?.expires)
    }

    @Test func withNoPrivilegesSessionOpenTheLogIsntRead() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let (tracker, _) = try tracker(lines: [], reads: reads)
        admins.set([])
        _ = try tracker.heartbeat()
        #expect(reads.withLock { $0 } == 0)
    }

    @Test func parsesTheLinePrivilegesAgentLogs() {
        let parsed = PrivilegesRenewalLine.parse(
            message: "SAPCorp: Administrator privileges for user philchatham have been renewed (60 minutes)")
        #expect(parsed?.user == "philchatham")
        #expect(parsed?.minutes == 60)
        #expect(PrivilegesRenewalLine.parse(message: "SAPCorp: Administrator privileges for user a b have been renewed (60 minutes)") == nil)
        #expect(PrivilegesRenewalLine.parse(message: "SAPCorp: Administrator privileges for user jdoe have been renewed (0 minutes)") == nil)
        #expect(PrivilegesRenewalLine.parse(message: "SAPCorp: Administrator privileges for user jdoe have been granted") == nil)
    }

    @Test func parsesLogShowOutput() {
        // As `log show --style ndjson` printed it on 2026-10-24, trimmed.
        let output = """
            {"timestamp":"2026-10-24 23:08:52.996052+0100","eventMessage":"SAPCorp: Administrator privileges for user philchatham have been renewed (60 minutes)","processID":1600,"userID":501,"processImageUUID":"41F96DF4-4BFD-3F1D-8084-E9B02CE1ABBB","processImagePath":"/Applications/Privileges.app/Contents/MacOS/PrivilegesAgent.app/Contents/MacOS/PrivilegesAgent"}
            {"timestamp":"2026-10-24 23:09:00.000000+0100","eventMessage":"Something else","processID":1600,"userID":501,"processImageUUID":"41F96DF4-4BFD-3F1D-8084-E9B02CE1ABBB"}
            not json
            """
        let lines = PrivilegesAgentLog.parse(ndjson: Data(output.utf8))
        #expect(lines.count == 1)
        #expect(lines.first?.user == "philchatham")
        #expect(lines.first?.pid == 1600)
        #expect(lines.first?.uid == 501)
        #expect(lines.first?.imageUUID == "41F96DF4-4BFD-3F1D-8084-E9B02CE1ABBB")
        #expect(lines.first?.date == Date(timeIntervalSince1970: 1_792_879_732.996))
    }

    @Test func readsTheUUIDOfEachArchitecture() {
        // A 64-bit Mach-O header with one load command, LC_UUID.
        func slice(_ uuid: UUID) -> [UInt8] {
            func le(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian, Array.init) }
            let u = uuid.uuid
            let bytes = [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
            return le(0xFEED_FACF) + le(0x0100_000C) + le(0) + le(2) + le(1) + le(24) + le(0) + le(0)
                + le(0x1B) + le(24) + bytes
        }
        let arm = UUID(uuidString: "41F96DF4-4BFD-3F1D-8084-E9B02CE1ABBB")!
        let intel = UUID(uuidString: "87CEDE6A-0760-3456-936B-C4DDFAA87C97")!
        #expect(MachOImage.uuids(in: Data(slice(arm))) == [arm.uuidString])

        // Universal: a fat header, then each slice at its offset.
        func be(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.bigEndian, Array.init) }
        let first = slice(intel), second = slice(arm)
        let offset1: UInt32 = 64, offset2 = offset1 + UInt32(first.count)
        var fat = be(0xCAFE_BABE) + be(2)
        fat += be(0x0100_0007) + be(3) + be(offset1) + be(UInt32(first.count)) + be(0)
        fat += be(0x0100_000C) + be(0) + be(offset2) + be(UInt32(second.count)) + be(0)
        fat += [UInt8](repeating: 0, count: Int(offset1) - fat.count) + first + second
        #expect(MachOImage.uuids(in: Data(fat)) == [arm.uuidString, intel.uuidString])

        #expect(MachOImage.uuids(in: Data([0, 1, 2])).isEmpty)
    }
}
