import Foundation
import Testing

@testable import AltiwardCore

/// The profiles tool's output, from a Mac enrolled in Intune: `profiles show -output
/// stdout-xml` and `profiles list -verbose`, with everything outside Altiward's and
/// Privileges' settings left out.
func profilesFixture(_ name: String) throws -> Data {
    try Data(contentsOf: repoFile("agent/Tests/Fixtures/profiles/\(name)"))
}

/// The fixture's MDM payloads, as the agent reads them.
func fixturePayloads() throws -> [MDMPayload] {
    try InstalledProfiles.mdmPayloads(
        shown: InstalledProfiles.shown(profilesFixture("show.xml"), user: nil),
        listed: InstalledProfiles.listed(String(decoding: profilesFixture("list-verbose.txt"), as: UTF8.self), user: nil))
}

struct InstalledProfilesTests {
    var listing: String { get throws { String(decoding: try profilesFixture("list-verbose.txt"), as: UTF8.self) } }

    func payloads(show: Data? = nil, list: String? = nil) throws -> [MDMPayload] {
        try InstalledProfiles.mdmPayloads(
            shown: InstalledProfiles.shown(show ?? profilesFixture("show.xml"), user: nil),
            listed: InstalledProfiles.listed(list ?? listing, user: nil))
    }

    func malformed(show: Data? = nil, list: String? = nil) -> Bool {
        do {
            _ = try payloads(show: show, list: list)
            return false
        } catch {
            return error is ProfilesReadError
        }
    }

    @Test func readsAltiwardsAndPrivilegesPayloadsFromMDMsProfiles() throws {
        let found = try payloads()
        #expect(found.map(\.domain) == ["corp.sap.privileges", "com.altiward.agent"])
        #expect(found.map(\.payloadUUID) == ["3B3B3B3B-0003-4000-8000-000000000003", "4B4B4B4B-0004-4000-8000-000000000004"])
        #expect(found[1].profileUUID == "4A4A4A4A-0004-4000-8000-000000000004")
        let agent = found[1].settings
        #expect(agent["ServerURL"] == .string("https://altiward-agents.example.com"))
        #expect(agent["HeartbeatInterval"] == .integer(60))
        #expect(agent["PermanentAdmins"] == .array([.string("breakglass")]))
        #expect(agent["UserPrincipalNames"] == .dictionary(["jdoe": .string("jane.doe@example.com")]))
        #expect(found[0].settings["EnableSystemExtension"] == .bool(true))
        #expect(found[0].settings["AllowPrivilegeRenewal"] == .bool(false))
        #expect(InstalledProfiles.hasEnrolmentPayload(try InstalledProfiles.shown(profilesFixture("show.xml"), user: nil)))
    }

    @Test func aProfileMDMDidntInstallIsLeftOut() throws {
        let byHand = try listing.replacingOccurrences(
            of: "_computerlevel[4] attribute: installedByMDM: TRUE", with: "_computerlevel[4] attribute: installedByMDM: FALSE")
        #expect(try payloads(list: byHand).map(\.domain) == ["corp.sap.privileges"])
    }

    /// Lines the listing has that the agent doesn't use are skipped.
    @Test func otherLinesAreSkipped() throws {
        let more = try listing.replacingOccurrences(
            of: "_computerlevel[4]            payload[1] uuid",
            with: "_computerlevel[4]            payload[1] type\t\t\t= com.altiward.agent\n"
                + "_computerlevel[4]            payload[1] displayName\t\t= (null)\n"
                + "a line the tool might wrap\n_computerlevel[4]            payload[1] uuid")
        #expect(try payloads(list: more) == payloads())
    }

    /// A profile installed by hand can carry text that reads as more lines of the listing.
    @Test func anythingUnexpectedFailsTheRead() throws {
        let list = try listing
        // The same attribute twice: an injected line claiming MDM installed a profile.
        #expect(
            malformed(
                list: list.replacingOccurrences(
                    of: "_computerlevel[4] attribute: profileType",
                    with: "_computerlevel[4] attribute: installedByMDM: TRUE\n_computerlevel[4] attribute: profileType")))
        // A payload field twice.
        #expect(
            malformed(
                list: list.replacingOccurrences(
                    of: "_computerlevel[3]            payload[1] uuid\t\t\t= 3B3B3B3B",
                    with: "_computerlevel[3]            payload[1] uuid = 00000000\n"
                        + "_computerlevel[3]            payload[1] uuid\t\t\t= 3B3B3B3B")))
        // No installedByMDM, or an answer that isn't TRUE or FALSE.
        #expect(malformed(list: list.replacingOccurrences(of: "_computerlevel[4] attribute: installedByMDM: TRUE\n", with: "")))
        #expect(
            malformed(
                list: list.replacingOccurrences(
                    of: "_computerlevel[4] attribute: installedByMDM: TRUE", with: "_computerlevel[4] attribute: installedByMDM: YES")))
        // No profileUUID.
        #expect(malformed(list: list.replacingOccurrences(of: "_computerlevel[4] attribute: profileUUID", with: "_computerlevel[4] attribute: x")))
        // A whole extra profile, which the count gives away.
        #expect(
            malformed(
                list: list + "_computerlevel[6] attribute: profileUUID: 11111111-2222-3333-4444-555555555555\n"
                    + "_computerlevel[6] attribute: installedByMDM: TRUE\n"))
        // No count, or the count twice.
        #expect(malformed(list: list.replacingOccurrences(of: "There are 5 system configuration profiles installed", with: "")))
        #expect(malformed(list: list + "There are 5 system configuration profiles installed\n"))
        // A payload listed under another profile than the one showing it.
        let moved = list.replacingOccurrences(
            of: "_computerlevel[4]            payload[1] uuid\t\t\t= 4B4B4B4B-0004-4000-8000-000000000004",
            with: "_computerlevel[3]            payload[2] uuid\t\t\t= 4B4B4B4B-0004-4000-8000-000000000004")
        #expect(moved != list)
        #expect(malformed(list: moved))
        // The same profile UUID twice.
        #expect(
            malformed(
                list: list.replacingOccurrences(
                    of: "profileUUID: 3a3a3a3a-0003-4000-8000-000000000003", with: "profileUUID: 4a4a4a4a-0004-4000-8000-000000000004")))
    }

    @Test func profilesShowMustMatchTheListing() throws {
        var show = try PropertyListSerialization.propertyList(from: profilesFixture("show.xml"), format: nil) as! [String: Any]
        var profiles = show["_computerlevel"] as! [[String: Any]]
        // A profile the listing doesn't have.
        profiles.append(["ProfileUUID": "99999999-0000-0000-0000-000000000000", "ProfileItems": [[String: Any]]()])
        show["_computerlevel"] = profiles
        #expect(malformed(show: try PropertyListSerialization.data(fromPropertyList: show, format: .xml, options: 0)))

        // The same payload UUID in two profiles.
        profiles.removeLast()
        var items = profiles[3]["ProfileItems"] as! [[String: Any]]
        items[0]["PayloadUUID"] = "3B3B3B3B-0003-4000-8000-000000000003"
        profiles[3]["ProfileItems"] = items
        show["_computerlevel"] = profiles
        #expect(malformed(show: try PropertyListSerialization.data(fromPropertyList: show, format: .xml, options: 0)))

        #expect(malformed(show: Data("not a property list".utf8)))
        #expect(malformed(show: Data("<plist version=\"1.0\"><array/></plist>".utf8)))
    }

    @Test func managedClientPreferencesPayloadsCountEveryForcedEntry() throws {
        let content: [String: Any] = [
            "com.altiward.agent": [
                "Forced": [
                    ["mcx_preference_settings": ["ServerURL": "https://altiward.example.com"]],
                    ["mcx_preference_settings": ["HeartbeatInterval": 60]],
                ]
            ],
            "com.example.other": ["Forced": [["mcx_preference_settings": ["Secret": "x"]]]],
        ]
        let show: [String: Any] = [
            "_computerlevel": [
                [
                    "ProfileUUID": "P1",
                    "ProfileItems": [
                        [
                            "PayloadType": "com.apple.ManagedClient.preferences", "PayloadUUID": "U1",
                            "PayloadContent": content,
                        ]
                    ],
                ]
            ]
        ]
        let list = """
            _computerlevel[1] attribute: profileUUID: P1
            _computerlevel[1] attribute: installedByMDM: TRUE
            _computerlevel[1]            payload[1] uuid\t\t\t= U1
            There are 1 system configuration profiles installed
            """
        let found = try payloads(
            show: try PropertyListSerialization.data(fromPropertyList: show, format: .xml, options: 0), list: list)
        #expect(found.map(\.domain) == ["com.altiward.agent", "com.altiward.agent"])
        #expect(found.map(\.settings) == [["ServerURL": .string("https://altiward.example.com")], ["HeartbeatInterval": .integer(60)]])
    }

    @Test func payloadKeysAreLeftOut() {
        let p = MDMPayload(
            domain: "com.altiward.agent", profileUUID: "p", payloadUUID: "u",
            settings: ["PayloadUUID": .string("u"), "PayloadDisplayName": .string("x"), "ServerURL": .string("s")])
        #expect(p.settings == ["ServerURL": .string("s")])
    }

    @Test func readsTheEnrolmentStatus() throws {
        #expect(try InstalledProfiles.enrolled(status: "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n"))
        #expect(try !InstalledProfiles.enrolled(status: "Enrolled via DEP: No\nMDM enrollment: No\n"))
        #expect(throws: ProfilesReadError.self) { try InstalledProfiles.enrolled(status: "") }
        #expect(throws: ProfilesReadError.self) { try InstalledProfiles.enrolled(status: "MDM enrollment: maybe\n") }
    }

    @Test func readsAUsersProfiles() throws {
        let show: [String: Any] = [
            "jdoe": [
                [
                    "ProfileUUID": "P9",
                    "ProfileItems": [
                        ["PayloadType": "corp.sap.privileges", "PayloadUUID": "U9", "PayloadContent": ["ReasonRequired": true]]
                    ],
                ]
            ]
        ]
        let list = """
            jdoe[1] attribute: profileUUID: P9
            jdoe[1] attribute: installedByMDM: TRUE
            jdoe[1]            payload[1] uuid = U9
            There are 1 configuration profiles installed for user 'jdoe'
            """
        let found = try InstalledProfiles.mdmPayloads(
            shown: InstalledProfiles.shown(
                try PropertyListSerialization.data(fromPropertyList: show, format: .xml, options: 0), user: "jdoe"),
            listed: InstalledProfiles.listed(list, user: "jdoe"))
        #expect(found == [MDMPayload(domain: "corp.sap.privileges", profileUUID: "P9", payloadUUID: "U9", settings: ["ReasonRequired": .bool(true)])])
        // None installed: what the tool prints for a user without profiles.
        #expect(
            try InstalledProfiles.listed("There are no configuration profiles installed for user 'jdoe'\n", user: "jdoe").isEmpty)
        // A word before "configuration profiles", as the device's count line has.
        #expect(
            try InstalledProfiles.listed(
                list.replacingOccurrences(of: "There are 1 configuration", with: "There are 1 user configuration"), user: "jdoe"
            ).count == 1)
        #expect(try InstalledProfiles.shown(Data("<plist version=\"1.0\"><dict/></plist>".utf8), user: "jdoe").isEmpty)
    }

    @Test func errorsNeverCarryTheOutput() {
        #expect(
            ProfilesReadError.command("profiles show", .exited(1)).description == "profiles show exited with status 1")
        #expect(
            ProfilesReadError.malformed("profile [4] has no installedByMDM").description
                == "the profiles tool's output can't be used: profile [4] has no installedByMDM")
    }
}
