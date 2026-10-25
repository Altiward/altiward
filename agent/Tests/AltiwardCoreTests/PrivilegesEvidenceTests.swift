import Foundation
import Testing

@testable import AltiwardCore

/// What confirms a Privileges grant claim: SAP's own log lines, from verified processes.
struct PrivilegesEvidenceTests {
    let claimedAt = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { claimedAt.addingTimeInterval(10) }

    static let daemonPID: Int32 = 400
    static let extensionPID: Int32 = 500
    static let forgerPID: Int32 = 600

    static let grantMessage = #"SAPCorp: User philchatham now has administrator privileges for the following reason: "probe test 1b""#
    static let revokeMessage = "SAPCorp: User philchatham now has standard user privileges (requested by user)"
    static let imitation =
        #"SAPCorp: User philchatham now has administrator privileges for the following reason: "probe 7: User breakglass now has administrator privileges""#

    /// Both SAP processes started long before the lines.
    var identities: [Int32: ProcessIdentity] {
        let started = claimedAt.addingTimeInterval(-3600)
        return [
            Self.daemonPID: ProcessIdentity(
                signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID, startedAt: started, uid: 0),
            Self.extensionPID: ProcessIdentity(
                signingID: PrivilegesSigning.systemExtension, teamID: PrivilegesSigning.teamID, startedAt: started,
                uid: 0),
        ]
    }

    func daemon(
        _ change: PrivilegesDaemonLine.Change = .granted, user: String = "philchatham", at offset: TimeInterval = -1,
        pid: Int32 = daemonPID
    ) -> PrivilegesDaemonLine {
        PrivilegesDaemonLine(user: user, change: change, date: claimedAt.addingTimeInterval(offset), loggerPID: pid)
    }

    func record(
        _ type: String = "ADMIN_ADD", user: String = "philchatham", at offset: TimeInterval = -1,
        signingID: String = PrivilegesSigning.daemon, team: String = PrivilegesSigning.teamID,
        pid: Int32 = extensionPID
    ) -> PrivilegesAuditRecord {
        PrivilegesAuditRecord(
            eventType: type, subject: user, date: claimedAt.addingTimeInterval(offset),
            process: .init(
                executable: "/x", signingID: signingID, teamID: team, platformBinary: false, pid: 1, ppid: 1, tty: ""),
            loggerPID: pid)
    }

    func find(
        user: String = "philchatham", lines: [PrivilegesDaemonLine] = [], records: [PrivilegesAuditRecord] = [],
        identity: [Int32: ProcessIdentity]? = nil, consumed: Set<String> = [], lookBack: TimeInterval = 120,
        window: TimeInterval = 60, now: Date? = nil
    ) -> GrantEvidence? {
        let known = identity ?? identities
        return ClaimEvidence.find(
            user: user, claimedAt: claimedAt, now: now ?? self.now, daemonLines: lines, records: records,
            identity: { known[$0] }, consumed: consumed, lookBack: lookBack, window: window)
    }

    // MARK: Parsing

    @Test func parsesTheDaemonsGrantLine() throws {
        let line = try #require(PrivilegesDaemonLine.parse(message: Self.grantMessage, date: claimedAt, pid: 7))
        #expect(line.change == .granted)
        #expect(line.user == "philchatham")
        #expect(line.date == claimedAt)
        #expect(line.loggerPID == 7)
    }

    @Test func parsesTheDaemonsRevokeLine() throws {
        let line = try #require(PrivilegesDaemonLine.parse(message: Self.revokeMessage, date: claimedAt, pid: 7))
        #expect(line.change == .revoked)
        #expect(line.user == "philchatham")
    }

    @Test func ignoresOtherLines() {
        for message in [
            "SAPCorp: Exiting", "", "  SAPCorp: User jdoe now has administrator privileges",
            "SAPCorp: User  now has administrator privileges", "SAPCorp: User jdoe now has some privileges",
            "xSAPCorp: User jdoe now has administrator privileges",
        ] {
            #expect(PrivilegesDaemonLine.parse(message: message, date: claimedAt, pid: 1) == nil, "\(message)")
        }
    }

    @Test func aReasonImitatingAnotherGrantDoesNotParseAsThatUser() throws {
        let line = try #require(PrivilegesDaemonLine.parse(message: Self.imitation, date: claimedAt, pid: Self.daemonPID))
        #expect(line.user == "philchatham")
        #expect(line.change == .granted)
        #expect(find(user: "breakglass", lines: [line]) == nil)
        #expect(find(user: "philchatham", lines: [line]) != nil)
    }

    // MARK: Confirming

    @Test func daemonAndExtensionLinesConfirm() throws {
        let evidence = try #require(find(lines: [daemon(at: -1)], records: [record(at: -1.5)]))
        #expect(evidence.sources == [.daemon, .systemExtension])
        #expect(evidence.date == claimedAt.addingTimeInterval(-1.5))
        // Whole milliseconds since 1970, then the logger's pid.
        #expect(evidence.keys == ["1799999998500|\(Self.extensionPID)", "1799999999000|\(Self.daemonPID)"])
    }

    @Test func theDaemonLineAloneConfirms() throws {
        let evidence = try #require(find(lines: [daemon()]))
        #expect(evidence.sources == [.daemon])
        #expect(evidence.keys == ["1799999999000|\(Self.daemonPID)"])
    }

    @Test func theExtensionRecordAloneConfirms() throws {
        let evidence = try #require(find(records: [record()]))
        #expect(evidence.sources == [.systemExtension])
    }

    @Test func linesMoreThanFiveSecondsApartAreNotCombined() throws {
        let evidence = try #require(find(lines: [daemon(at: -10)], records: [record(at: -1)]))
        #expect(evidence.sources == [.daemon])
        #expect(evidence.date == claimedAt.addingTimeInterval(-10))
    }

    @Test func aGrantAfterTheClaimWithinTheWindowConfirms() throws {
        let evidence = try #require(find(lines: [daemon(at: 5)]))
        #expect(evidence.sources == [.daemon])
    }

    @Test func anAddByDseditgroupDoesNotConfirm() {
        #expect(find(records: [record(signingID: "com.apple.dseditgroup", team: "")]) == nil)
    }

    @Test func anAddByAnotherSapBinaryDoesNotConfirm() {
        #expect(find(records: [record(signingID: "corp.sap.privileges.helper")]) == nil)
    }

    @Test func aLineFromAnUnsignedOrWrongProcessDoesNotCount() {
        var unknown = identities
        unknown[Self.daemonPID] = nil
        unknown[Self.extensionPID] = nil
        #expect(find(lines: [daemon()], records: [record()], identity: unknown) == nil)

        let wrongTeam = ProcessIdentity(
            signingID: PrivilegesSigning.daemon, teamID: "ABCDE12345", startedAt: claimedAt.addingTimeInterval(-3600),
            uid: 0)
        var wrong = identities
        wrong[Self.daemonPID] = wrongTeam
        #expect(find(lines: [daemon()], identity: wrong) == nil)

        // The right team but the wrong SAP binary logging as the daemon.
        wrong[Self.daemonPID] = ProcessIdentity(
            signingID: "corp.sap.privileges.helper", teamID: PrivilegesSigning.teamID,
            startedAt: claimedAt.addingTimeInterval(-3600), uid: 0)
        #expect(find(lines: [daemon()], identity: wrong) == nil)

        // A daemon identity cannot vouch for an extension record.
        #expect(find(records: [record(pid: Self.daemonPID)]) == nil)
    }

    @Test func aLineFromANonRootProcessDoesNotCount() throws {
        // A process can log a forged line and then exec the genuine SAP binary, which keeps
        // its pid and start time but not root: PrivilegesDaemon and the extension run as root.
        var userOwned = identities
        userOwned[Self.daemonPID]?.uid = 501
        #expect(find(lines: [daemon()], identity: userOwned) == nil)
        let rest = try #require(find(lines: [daemon()], records: [record()], identity: userOwned))
        #expect(rest.sources == [.systemExtension])

        userOwned = identities
        userOwned[Self.extensionPID]?.uid = 501
        #expect(find(records: [record()], identity: userOwned) == nil)
        // Nor can a non-root extension record void a grant.
        #expect(find(lines: [daemon(at: -2)], records: [record("ADMIN_REMOVE", at: -1)], identity: userOwned) != nil)
    }

    @Test func aLineFromAProcessStartedAfterItDoesNotCount() {
        var late = identities
        late[Self.daemonPID]?.startedAt = claimedAt.addingTimeInterval(0)
        #expect(find(lines: [daemon(at: -1)], identity: late) == nil)
        late[Self.extensionPID]?.startedAt = claimedAt.addingTimeInterval(0)
        #expect(find(records: [record(at: -1)], identity: late) == nil)
    }

    @Test func aVerifiedDaemonLineConfirmsWhenTheExtensionRecordIsUnverified() throws {
        var known = identities
        known[Self.extensionPID] = nil
        let evidence = try #require(find(lines: [daemon()], records: [record()], identity: known))
        #expect(evidence.sources == [.daemon])
    }

    @Test func evidenceUpToTwoMinutesBeforeTheClaimCounts() throws {
        // The hook's claim can arrive well after the grant (Altiward/altiward#91).
        let evidence = try #require(find(lines: [daemon(at: -100)], records: [record(at: -100)]))
        #expect(evidence.sources == [.daemon, .systemExtension])
        #expect(find(lines: [daemon(at: -119)]) != nil)
    }

    @Test func evidenceOlderThanTheWindowDoesNotCount() {
        #expect(find(lines: [daemon(at: -121)], records: [record(at: -121)]) == nil)
    }

    @Test func evidenceLaterThanTheWindowDoesNotCount() {
        let later = claimedAt.addingTimeInterval(120)
        #expect(find(lines: [daemon(at: 61)], records: [record(at: 61)], now: later) == nil)
        #expect(find(lines: [daemon(at: 59)], now: later) != nil)
    }

    @Test func evidenceFromTheFutureDoesNotCount() {
        #expect(find(lines: [daemon(at: 11)], records: [record(at: 11)]) == nil)
    }

    @Test func theWindowIsAParameter() {
        #expect(find(lines: [daemon(at: -20)], lookBack: 10) == nil)
        #expect(find(lines: [daemon(at: -20)], lookBack: 30) != nil)
        #expect(find(lines: [daemon(at: 5)], window: 3) == nil)
        #expect(find(lines: [daemon(at: 5)], window: 6) != nil)
    }

    @Test func anotherUsersGrantDoesNotCount() {
        #expect(find(user: "philchatham", lines: [daemon(user: "mallory")], records: [record(user: "mallory")]) == nil)
    }

    // MARK: Voiding

    @Test func aRemoveAfterTheAddVoidsIt() {
        #expect(find(records: [record("ADMIN_ADD", at: -5), record("ADMIN_REMOVE", at: -3)]) == nil)
    }

    @Test func aRemoveByAnyVerifiedExtensionRecordVoidsTheDaemonLineToo() {
        let remove = record("ADMIN_REMOVE", at: -3, signingID: "com.apple.dseditgroup", team: "")
        #expect(find(lines: [daemon(at: -5)], records: [remove]) == nil)
    }

    @Test func aDaemonRevokeAfterTheGrantVoidsIt() {
        #expect(find(lines: [daemon(.granted, at: -5), daemon(.revoked, at: -3)]) == nil)
        #expect(find(lines: [daemon(.granted, at: -5)], records: [record(at: -5)]) != nil)
        #expect(find(lines: [daemon(.revoked, at: -3)], records: [record(at: -5)]) == nil)
    }

    @Test func aGrantAfterARevokeStillConfirms() throws {
        let evidence = try #require(find(lines: [daemon(.granted, at: -5), daemon(.revoked, at: -4), daemon(.granted, at: -2)]))
        #expect(evidence.date == claimedAt.addingTimeInterval(-2))
    }

    @Test func aGiveBackAfterTheClaimDoesNotVoidIt() throws {
        // A real grant given back seconds after its claim arrived: the claim was true.
        let lines = [daemon(.granted, at: -1), daemon(.revoked, at: 5)]
        let records = [record("ADMIN_ADD", at: -0.8), record("ADMIN_REMOVE", at: 5.2)]
        let evidence = try #require(find(lines: lines, records: records))
        #expect(evidence.sources == [.daemon, .systemExtension])
        #expect(find(lines: [daemon(.granted, at: -1), daemon(.revoked, at: 5)]) != nil)
        #expect(find(records: [record("ADMIN_ADD", at: -1), record("ADMIN_REMOVE", at: 5)]) != nil)
    }

    @Test func aChangeAtTheClaimsArrivalStillVoids() {
        #expect(find(lines: [daemon(.granted, at: -1), daemon(.revoked, at: 0)]) == nil)
        #expect(find(lines: [daemon(at: -1)], records: [record("ADMIN_REMOVE", at: 0)]) == nil)
    }

    @Test func aNonSapAddAfterTheClaimDoesNotBlockIt() throws {
        let dseditgroup = record(at: 3, signingID: "com.apple.dseditgroup", team: "")
        let evidence = try #require(find(lines: [daemon(at: -1)], records: [record(at: -0.8), dseditgroup]))
        #expect(evidence.sources == [.daemon, .systemExtension])
    }

    @Test func aNonSapAddBeforeTheClaimStillBlocksALaterSapAdd() {
        // The latest change at the claim's arrival is what counts.
        let dseditgroup = record(at: -2, signingID: "com.apple.dseditgroup", team: "")
        #expect(find(lines: [daemon(at: 3)], records: [dseditgroup, record(at: 3.2)]) == nil)
    }

    @Test func anUnverifiedRemoveDoesNotVoid() {
        var known = identities
        known[Self.extensionPID] = nil
        #expect(find(lines: [daemon(at: -5)], records: [record("ADMIN_REMOVE", at: -3)], identity: known) != nil)
    }

    @Test func aLatestNonSapAddBlocksADaemonLine() {
        let dseditgroup = record(at: -2, signingID: "com.apple.dseditgroup", team: "")
        #expect(find(lines: [daemon(at: -5)], records: [dseditgroup]) == nil)
    }

    @Test func aLaterSapAddAfterANonSapAddConfirms() throws {
        let dseditgroup = record(at: -5, signingID: "com.apple.dseditgroup", team: "")
        let evidence = try #require(find(lines: [daemon(at: -1)], records: [dseditgroup, record(at: -1)]))
        #expect(evidence.sources == [.daemon, .systemExtension])
    }

    // MARK: Consuming

    @Test func consumedEvidenceDoesNotConfirmTwice() throws {
        let lines = [daemon(at: -1)]
        let first = try #require(find(lines: lines))
        #expect(find(lines: lines, consumed: first.keys) == nil)
    }

    @Test func aLineReadAgainKeepsItsKey() throws {
        // Two reads of the log can give the same entry dates that differ below a millisecond.
        let first = try #require(find(lines: [daemon(at: -1)]))
        #expect(find(lines: [daemon(at: -1 + 0.0001)], consumed: first.keys) == nil)
        #expect(find(lines: [daemon(at: -1 - 0.0001)], consumed: first.keys) == nil)
    }

    @Test func aSecondGrantConfirmsAfterTheFirstIsConsumed() throws {
        let lines = [daemon(at: -30), daemon(at: -1)]
        let first = try #require(find(lines: lines))
        #expect(first.date == claimedAt.addingTimeInterval(-30))
        let second = try #require(find(lines: lines, consumed: first.keys))
        #expect(second.date == claimedAt.addingTimeInterval(-1))
    }

    @Test func bothHalvesOfConsumedEvidenceAreSpent() throws {
        // Whichever line is earlier, consuming the keys returned spends both lines.
        for (daemonAt, recordAt) in [(-1.0, -1.5), (-1.5, -1.0)] {
            let lines = [daemon(at: daemonAt)]
            let records = [record(at: recordAt)]
            let first = try #require(find(lines: lines, records: records))
            #expect(first.sources == [.daemon, .systemExtension])
            #expect(first.keys.count == 2)
            #expect(find(lines: lines, records: records, consumed: first.keys) == nil)
            #expect(find(lines: lines, consumed: first.keys) == nil)
            #expect(find(records: records, consumed: first.keys) == nil)
        }
    }

    @Test func aConsumedLineLeavesTheOtherUnspent() throws {
        let lines = [daemon(at: -1)]
        let records = [record(at: -1.5)]
        let first = try #require(find(lines: lines, records: records))
        let daemonKey = try #require(first.keys.first { $0.hasSuffix("|\(Self.daemonPID)") })
        let rest = try #require(find(lines: lines, records: records, consumed: [daemonKey]))
        #expect(rest.sources == [.systemExtension])
    }

    // MARK: Verifying a process

    @Test func theCodeRequirementTakesOnlyPlainASCIIValues() {
        #expect(
            ProcessIdentity.requirement(signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID)
                == #"identifier "corp.sap.privileges.daemon" and anchor apple generic and certificate leaf[subject.OU] = "7R5ZEU67FQ""#)
        // Letters and digits outside ASCII, which CharacterSet counts as upper case or digits.
        for team in ["\u{FF17}R5ZEU67FQ", "\u{C4}R5ZEU67FQ", "7r5zeu67fq", "7R5ZEU67F\"", ""] {
            #expect(ProcessIdentity.requirement(signingID: PrivilegesSigning.daemon, teamID: team) == nil, "\(team)")
        }
        for id in ["corp.sap.privileges.d\u{E6}mon", #"a" or anchor apple"#, ""] {
            #expect(ProcessIdentity.requirement(signingID: id, teamID: PrivilegesSigning.teamID) == nil, "\(id)")
        }
    }

    // MARK: Whether the log can be read

    func decide(
        version: String? = "2.6.0", osMajor: Int = 27, extensionPID: Int32? = extensionPID,
        identities: [Int32: ProcessIdentity]? = nil
    ) -> PrivilegesLogAvailability {
        let known = identities ?? self.identities
        return PrivilegesLogAvailability.decide(
            privilegesVersion: version, osMajor: osMajor, extensionPID: extensionPID, identity: { known[$0] })
    }

    @Test func theLogIsAvailableWithPrivileges26OnASupportedMac() {
        #expect(decide() == .available)
    }

    @Test func versionsCompareNumericallyByComponent() {
        #expect(decide(version: "2.10.0") == .available)
        #expect(decide(version: "3.0") == .available)
        #expect(decide(version: "2.6") == .available)
        #expect(decide(version: "2.5.9") == .unavailable("SAP Privileges 2.5.9 is older than 2.6.0"))
    }

    @Test func theLogIsUnavailableWithoutPrivileges() {
        #expect(decide(version: nil) == .unavailable("SAP Privileges isn't installed"))
    }

    @Test func theLogIsUnavailableWithAnOlderPrivileges() {
        #expect(decide(version: "2.4.2") == .unavailable("SAP Privileges 2.4.2 is older than 2.6.0"))
    }

    @Test func theLogIsUnavailableOnAnOlderMacOS() {
        #expect(decide(osMajor: 13) == .unavailable("macOS 13 is older than 14"))
    }

    @Test func theLogIsUnavailableWithoutTheExtension() {
        #expect(decide(extensionPID: nil) == .unavailable("Privileges' system extension isn't running"))
    }

    @Test func theLogIsUnavailableWhenTheExtensionIsNotSignedBySAP() {
        let started = claimedAt.addingTimeInterval(-3600)
        let unsigned = "Privileges' system extension isn't signed by SAP"
        #expect(decide(identities: [:]) == .unavailable(unsigned))
        #expect(
            decide(identities: [
                Self.extensionPID: ProcessIdentity(
                    signingID: PrivilegesSigning.systemExtension, teamID: "ABCDE12345", startedAt: started, uid: 0)
            ]) == .unavailable(unsigned))
        #expect(
            decide(identities: [
                Self.extensionPID: ProcessIdentity(
                    signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID, startedAt: started, uid: 0)
            ]) == .unavailable(unsigned))
        #expect(
            decide(identities: [
                Self.extensionPID: ProcessIdentity(
                    signingID: PrivilegesSigning.systemExtension, teamID: PrivilegesSigning.teamID, startedAt: started,
                    uid: 501)
            ]) == .unavailable(unsigned))
    }
}
