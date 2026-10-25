import CryptoKit
import Foundation
import Testing

@testable import AltiwardCore

/// The checks against a fake install in a temporary folder.
struct SystemIntegrityTests {
    let root: URL
    let bundle: URL
    let daemons: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("integrity-\(UUID().uuidString)")
        bundle = root.appendingPathComponent("Altiward.app")
        daemons = root.appendingPathComponent("LaunchDaemons")
        let resources = bundle.appendingPathComponent("Contents/Resources")
        for dir in [resources, daemons] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        let data = Data("<plist>com.altiward.agent.plist</plist>".utf8)
        try data.write(to: resources.appendingPathComponent("com.altiward.agent.plist"))
        try data.write(to: daemons.appendingPathComponent("com.altiward.agent.plist"))
    }

    func integrity(
        bundle: URL?? = nil, local: Set<String> = [], forced: Set<String> = [],
        privileges: PrivilegesSettings = PrivilegesSettings(), privilegesInstalled: Bool = false,
        extensionProblem: String? = nil
    ) -> SystemIntegrity {
        var s = SystemIntegrity(
            bundleURL: bundle ?? self.bundle, hasValue: { local.union(forced).contains($0) },
            isForced: { forced.contains($0) }, privileges: { privileges }, privilegesInstalled: { privilegesInstalled },
            privilegesExtensionProblem: { extensionProblem })
        s.launchDaemonsDirectory = daemons
        return s
    }

    @Test func aLaunchDaemonMatchingTheBundlePasses() {
        #expect(integrity().run()[.launchDaemon] == .ok)
    }

    @Test func aMissingOrEditedLaunchDaemonFails() throws {
        let installed = daemons.appendingPathComponent("com.altiward.agent.plist")
        try Data("<plist>edited</plist>".utf8).write(to: installed)
        #expect(
            integrity().run()[.launchDaemon]?.problem?.contains("differs from the one Altiward installed")
                == true)
        try FileManager.default.removeItem(at: installed)
        let r = integrity().run()
        #expect(r[.launchDaemon]?.ok == false)
        #expect(r[.launchDaemon]?.problem?.hasSuffix("com.altiward.agent.plist is missing") == true)
    }

    @Test func anUnsignedBundleFailsAndASignedOnePasses() {
        #expect(integrity().run()[.codeSignature]?.ok == false)
        // Any app Apple signed passes the same strict check.
        #expect(SystemIntegrity.signature(of: URL(fileURLWithPath: "/System/Applications/Calculator.app")) == .ok)
    }

    @Test func withoutABundleOnlyBundleFreeChecksRun() {
        let r = integrity(bundle: .some(nil)).run()
        #expect(Set(r.keys) == [.settingsManaged])
    }

    @Test func policySetOutsideMDMFails() {
        #expect(integrity(forced: ["ExpiryEnforcement", "PermanentAdmins"]).run()[.settingsManaged] == .ok)
        let r = integrity(local: ["PermanentAdmins", "ExpiryEnforcement"], forced: ["ServerURL"]).run()
        #expect(r[.settingsManaged] == .failed("set outside MDM: PermanentAdmins, ExpiryEnforcement"))
        // Removing rights nobody granted is policy too: switching it off locally keeps them.
        for key in ["OutOfBandEnforcement", "OutOfBandGraceMinutes"] {
            #expect(integrity(local: [key]).run()[.settingsManaged] == .failed("set outside MDM: \(key)"))
            #expect(integrity(forced: [key]).run()[.settingsManaged] == .ok)
        }
        // Keys that aren't policy don't count.
        #expect(integrity(local: ["FlushInterval"]).run()[.settingsManaged] == .ok)
    }

    @Test func privilegesChecksRunWithPrivilegesInstalled() {
        // Installed as "Altiward", the name Privileges shows for its post-change executable.
        let hook = bundle.appendingPathComponent("Contents/MacOS/Altiward").path
        let good = PrivilegesSettings(postChangeExecutablePath: hook, systemExtensionEnabled: true)
        let r = integrity(privileges: good, privilegesInstalled: true).run()
        #expect(r[.privilegesTamperProtection] == .ok)
        #expect(r[.privilegesHook] == .ok)

        let bad = PrivilegesSettings(postChangeExecutablePath: "/tmp/other", systemExtensionEnabled: false)
        let failing = integrity(privileges: bad, privilegesInstalled: true).run()
        #expect(failing[.privilegesTamperProtection]?.ok == false)
        #expect(failing[.privilegesHook]?.problem?.hasPrefix("PostChangeExecutablePath is /tmp/other") == true)

        let removed = integrity(privileges: bad, privilegesInstalled: false).run()
        #expect(removed[.privilegesHook] == nil)
        #expect(removed[.privilegesTamperProtection] == nil)
    }

    /// The setting alone isn't protection: the extension must be running, and be SAP's (#93).
    @Test func tamperProtectionNeedsTheExtensionRunning() {
        let on = PrivilegesSettings(systemExtensionEnabled: true)
        #expect(
            integrity(privileges: on, privilegesInstalled: true, extensionProblem: "isn't running").run()[
                .privilegesTamperProtection]
                == .failed("Privileges' tamper protection is on, but its system extension isn't running"))
        #expect(
            integrity(privileges: on, privilegesInstalled: true, extensionProblem: "isn't signed by SAP").run()[
                .privilegesTamperProtection]
                == .failed("Privileges' tamper protection is on, but its system extension isn't signed by SAP"))
        // Switched off in the settings fails as before, whether or not the extension still runs.
        let off = PrivilegesSettings(systemExtensionEnabled: false)
        #expect(
            integrity(privileges: off, privilegesInstalled: true).run()[.privilegesTamperProtection]
                == .failed("Privileges' tamper protection (EnableSystemExtension) is off"))
    }

    @Test func theExtensionsProblemNamesWhatIsWrong() {
        let sap = ProcessIdentity(
            signingID: PrivilegesSigning.systemExtension, teamID: PrivilegesSigning.teamID, startedAt: Date(), uid: 0)
        #expect(PrivilegesExtensionProcess.problem(pid: nil, identity: { _ in sap }) == "isn't running")
        #expect(PrivilegesExtensionProcess.problem(pid: 42, identity: { _ in sap }) == nil)
        #expect(PrivilegesExtensionProcess.problem(pid: 42, identity: { _ in nil }) == "isn't signed by SAP")
        var other = sap
        other.teamID = "ABCDE12345"
        #expect(PrivilegesExtensionProcess.problem(pid: 42, identity: { _ in other }) == "isn't signed by SAP")
        var user = sap
        user.uid = 501
        #expect(PrivilegesExtensionProcess.problem(pid: 42, identity: { _ in user }) == "isn't signed by SAP")
    }

    @Test func theHookChecksumMustMatchWhenPrivilegesHasOne() throws {
        let hook = bundle.appendingPathComponent("Contents/MacOS/Altiward")
        try FileManager.default.createDirectory(at: hook.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("hook".utf8).write(to: hook)
        // No checksum: Privileges runs the hook unchecked.
        #expect(SystemIntegrity.checksum(nil, matches: hook.path) == .ok)

        let real = SHA256.hash(data: Data("hook".utf8)).map { String(format: "%02x", $0) }.joined()
        let stale = String(repeating: "0", count: 64)
        func check(_ checksum: String) -> IntegrityResult? {
            let settings = PrivilegesSettings(postChangeExecutablePath: hook.path, postChangeExecutableChecksum: checksum)
            return integrity(privileges: settings, privilegesInstalled: true).run()[.privilegesHook]
        }
        #expect(check(real) == .ok)
        #expect(check(real.uppercased()) == .ok)  // Privileges ignores case
        #expect(check(stale)?.problem?.hasPrefix("PostChangeExecutableChecksum doesn't match Altiward's hook") == true)

        try FileManager.default.removeItem(at: hook)
        #expect(check(real)?.problem?.hasPrefix("cannot read") == true)
    }

    @Test func privilegesUsesTheChecksumOnlyWhenMDMForcesBothKeys() {
        let values: [String: Any] = ["PostChangeExecutablePath": "/hook", "PostChangeExecutableChecksum": "abc"]
        let both = PrivilegesSettings.settings(
            from: Preferences(values: values, forced: ["PostChangeExecutablePath", "PostChangeExecutableChecksum"]))
        #expect(both.postChangeExecutableChecksum == "abc")
        let pathOnly = PrivilegesSettings.settings(from: Preferences(values: values, forced: ["PostChangeExecutablePath"]))
        #expect(pathOnly.postChangeExecutableChecksum == nil)
        let local = PrivilegesSettings.settings(from: Preferences(values: values))
        #expect(local.postChangeExecutableChecksum == nil)
        #expect(local.postChangeExecutablePath == "/hook")
    }

    // MARK: The settings Altiward recommends (#92)

    /// The settings that pass every recommended check.
    static let recommended = PrivilegesSettings(
        expiryCapped: true, allowPrivilegeRenewal: false, postChangeActionOnGrantOnly: false, revokeAtLogin: true,
        revokeAtLoginExcludedUsers: ["itadmin"], revokeAfterTimeChange: true,
        revokeAfterTimeChangeExcludedUsers: ["itadmin"])

    func settingsChecks(
        _ settings: PrivilegesSettings, expiry: ExpiryEnforcement = .enforce, permanentAdmins: Set<String> = ["itadmin"]
    ) -> [IntegrityCheck: IntegrityResult] {
        SystemIntegrity.settingsChecks(settings, expiryEnforcement: expiry, permanentAdmins: permanentAdmins)
    }

    @Test func theRecommendedSettingsPass() {
        let r = settingsChecks(Self.recommended)
        #expect(
            r == [
                .privilegesExpiryCap: .ok, .privilegesRenewal: .ok, .privilegesGiveBackHook: .ok,
                .privilegesRevokeExclusions: .ok,
            ])
        // run() adds them while Privileges is installed, and only then.
        var system = integrity(privileges: Self.recommended, privilegesInstalled: true)
        system.expiryEnforcement = .enforce
        system.permanentAdmins = ["itadmin"]
        #expect(system.run()[.privilegesRenewal] == .ok)
        #expect(integrity(privileges: Self.recommended).run()[.privilegesExpiryCap] == nil)
    }

    @Test func noExpiryCapFails() {
        var s = Self.recommended
        s.expiryCapped = false
        #expect(settingsChecks(s)[.privilegesExpiryCap]?.problem?.hasPrefix("MDM doesn't cap how long") == true)
        // In alert mode too: an uncapped grant is never overdue either.
        #expect(settingsChecks(s, expiry: .alert)[.privilegesExpiryCap]?.ok == false)
    }

    @Test func renewalsFailOnlyWhileExpiryIsEnforced() {
        var s = Self.recommended
        s.allowPrivilegeRenewal = nil
        #expect(
            settingsChecks(s)[.privilegesRenewal]?.problem?.hasPrefix("MDM doesn't set AllowPrivilegeRenewal to false")
                == true)
        s.allowPrivilegeRenewal = true
        #expect(settingsChecks(s)[.privilegesRenewal]?.ok == false)
        #expect(settingsChecks(s, expiry: .alert)[.privilegesRenewal] == nil)
        #expect(settingsChecks(s, expiry: .off)[.privilegesRenewal] == nil)
        // AutoRenewalProcessPaths renews whatever AllowPrivilegeRenewal says.
        var auto = Self.recommended
        auto.autoRenewalConfigured = true
        #expect(settingsChecks(auto)[.privilegesRenewal]?.problem?.hasPrefix("AutoRenewalProcessPaths renews") == true)
    }

    @Test func theGiveBackHookMustBeForcedOn() {
        var s = Self.recommended
        s.postChangeActionOnGrantOnly = nil
        #expect(
            settingsChecks(s)[.privilegesGiveBackHook]?.problem?.hasPrefix(
                "MDM doesn't set PostChangeActionOnGrantOnly to false") == true)
        s.postChangeActionOnGrantOnly = true
        #expect(
            settingsChecks(s)[.privilegesGiveBackHook]
                == .failed("PostChangeActionOnGrantOnly is true, so Privileges doesn't run Altiward's hook on a give-back"))
    }

    @Test func revokeExclusionsMustCoverPermanentAdmins() {
        let admins: Set<String> = ["itadmin", "breakglass"]
        #expect(
            settingsChecks(Self.recommended, permanentAdmins: admins)[.privilegesRevokeExclusions]
                == .failed(
                    "PermanentAdmins accounts aren't excluded: RevokeAtLoginExcludedUsers leaves out breakglass, "
                        + "so Privileges removes their admin rights at sign-in; RevokeAfterTimeChangeExcludedUsers "
                        + "leaves out breakglass, so Privileges removes their admin rights after a clock change"))
        // A revoke that is off excludes nobody, so it needs no list.
        var off = Self.recommended
        off.revokeAtLogin = false
        off.revokeAfterTimeChange = nil
        off.revokeAtLoginExcludedUsers = nil
        off.revokeAfterTimeChangeExcludedUsers = nil
        #expect(settingsChecks(off, permanentAdmins: admins)[.privilegesRevokeExclusions] == .ok)
        var noList = Self.recommended
        noList.revokeAtLoginExcludedUsers = nil
        #expect(
            settingsChecks(noList)[.privilegesRevokeExclusions]?.problem
                == "PermanentAdmins accounts aren't excluded: RevokeAtLoginExcludedUsers leaves out itadmin, "
                + "so Privileges removes their admin rights at sign-in")
    }

    /// Privileges lets the user change a setting its profile doesn't force, so the cap, renewals
    /// and the give-back hook count only from MDM.
    @Test func theRecommendedSettingsCountOnlyFromMDM() {
        let values: [String: Any] = [
            "ExpirationIntervalMax": 60, "AllowPrivilegeRenewal": false, "PostChangeActionOnGrantOnly": false,
            "RevokePrivilegesAtLogin": true, "RevokeAtLoginExcludedUsers": ["itadmin"],
            "RevokePrivilegesAfterSystemTimeChange": true, "RevokeAfterTimeChangeExcludedUsers": ["itadmin"],
            "AutoRenewalProcessPaths": ["/Applications/Xcode.app"],
        ]
        let managed = PrivilegesSettings.settings(from: Preferences(values: values, forced: Set(values.keys)))
        #expect(managed.expiryCapped)
        #expect(managed.allowPrivilegeRenewal == false)
        #expect(managed.postChangeActionOnGrantOnly == false)
        #expect(managed.autoRenewalConfigured)
        #expect(managed.revokeAtLogin == true && managed.revokeAtLoginExcludedUsers == ["itadmin"])
        #expect(managed.revokeAfterTimeChange == true && managed.revokeAfterTimeChangeExcludedUsers == ["itadmin"])

        let local = PrivilegesSettings.settings(from: Preferences(values: values))
        #expect(!local.expiryCapped)
        #expect(local.allowPrivilegeRenewal == nil)
        #expect(local.postChangeActionOnGrantOnly == nil)

        // ExpirationInterval wins when it is set: 0 means no expiry, whatever the maximum.
        let never = Preferences(
            values: ["ExpirationInterval": 0, "ExpirationIntervalMax": 60],
            forced: ["ExpirationInterval", "ExpirationIntervalMax"])
        #expect(!PrivilegesSettings.settings(from: never).expiryCapped)
        let fixed = Preferences(values: ["ExpirationInterval": 20], forced: ["ExpirationInterval"])
        #expect(PrivilegesSettings.settings(from: fixed).expiryCapped)

        guard case .object(let fields) = managed.healthDetail else { Issue.record("not an object"); return }
        #expect(fields["expiry_capped"] == true)
        #expect(fields["allow_privilege_renewal"] == false)
        #expect(fields["auto_renewal_configured"] == true)
        #expect(fields["post_change_action_on_grant_only"] == false)
        #expect(fields["revoke_at_login_excluded_users"] == ["itadmin"])
        #expect(fields["revoke_after_time_change"] == true)
        guard case .object(let unset) = PrivilegesSettings().healthDetail else { Issue.record("not an object"); return }
        #expect(unset["allow_privilege_renewal"] == .null)
        #expect(unset["revoke_at_login_excluded_users"] == .null)
    }
}
