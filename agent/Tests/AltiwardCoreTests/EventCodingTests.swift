import Foundation
import Testing

@testable import AltiwardCore

/// The agent must produce and accept exactly the shapes in docs/schema/examples,
/// which the Go backend tests against too.
struct EventCodingTests {
    static let fixtures = [
        "elevation-granted", "elevation-revoked", "elevation-overdue", "elevation-expired-enforced",
        "admin-out-of-band", "agent-health", "agent-tamper", "agent-silent", "persistence-detected",
        "elevation-revoked-permanent-admin", "agent-tamper-retired", "elevation-revoked-privileges-grant",
        "agent-tamper-privileges-blocked",
    ]

    @Test(arguments: fixtures)
    func decodesContractFixture(_ name: String) throws {
        let data = try Data(contentsOf: repoFile("docs/schema/examples/\(name).json"))
        let event = try AltiwardJSON.decoder().decode(AltiwardEvent.self, from: data)
        #expect(event.schemaVersion == 1)
        #expect(event.device.serial == "C02XK0AAJGH5")
    }

    @Test(arguments: fixtures)
    func reencodesFixtureLosslessly(_ name: String) throws {
        let data = try Data(contentsOf: repoFile("docs/schema/examples/\(name).json"))
        let event = try AltiwardJSON.decoder().decode(AltiwardEvent.self, from: data)
        let original = try JSONSerialization.jsonObject(with: data) as! NSDictionary
        let reencoded =
            try JSONSerialization.jsonObject(with: AltiwardJSON.encoder().encode(event)) as! NSDictionary
        #expect(normalizeDates(reencoded) == normalizeDates(original))
    }

    @Test func grantedFixtureFields() throws {
        let data = try Data(contentsOf: repoFile("docs/schema/examples/elevation-granted.json"))
        let event = try AltiwardJSON.decoder().decode(AltiwardEvent.self, from: data)
        #expect(event.type == .elevationGranted)
        #expect(event.user == UserInfo(localName: "jdoe", upn: "jane.doe@example.com"))
        #expect(event.elevation?.source == .privileges)
        #expect(event.elevation?.reason == "Installing Xcode command line tools")
        #expect(event.detail["verified"] == .bool(true))
        #expect(event.detail["caller_uid"] == .number(501))
    }

    /// The heartbeat's agent.health carries exactly the detail keys in the fixture, and the
    /// same keys under `privileges`, with Privileges installed and the persistence check on.
    @Test func heartbeatHealthHasTheFixtureKeys() throws {
        let data = try Data(contentsOf: repoFile("docs/schema/examples/agent-health.json"))
        let fixture = try AltiwardJSON.decoder().decode(AltiwardEvent.self, from: data)

        var env = makeEnvironment(admins: FakeAdmins(["itadmin"]))
        env.persistence = { PersistenceSnapshot(items: []) }
        let tracker = ElevationTracker(store: try makeStore(), environment: env)
        try tracker.checkPersistence()
        let health = try #require(try tracker.heartbeat().first { $0.type == .agentHealth })

        #expect(Set(health.detail.keys) == Set(fixture.detail.keys))
        guard case .object(let sent) = health.detail["privileges"],
            case .object(let documented) = fixture.detail["privileges"]
        else {
            Issue.record("privileges is not an object in the event or the fixture")
            return
        }
        #expect(Set(sent.keys) == Set(documented.keys))
    }

    @Test func encodesSnakeCaseNullsAndLowercaseIDs() throws {
        let event = AltiwardEvent(
            type: .elevationRevoked, sessionID: newID(), timestamp: Date(timeIntervalSince1970: 0),
            device: testDevice, user: UserInfo(localName: "jdoe", upn: nil),
            elevation: ElevationInfo(source: .privileges))
        let json = String(decoding: try AltiwardJSON.encoder().encode(event), as: UTF8.self)
        #expect(json.contains(#""event_id":"\#(event.eventID)""#))
        #expect(event.eventID == event.eventID.lowercased())
        #expect(json.contains(#""timestamp":"1970-01-01T00:00:00.000Z""#))
        #expect(json.contains(#""upn":null"#))
        #expect(json.contains(#""expires":null"#))
        #expect(json.contains(#""hardware_uuid":"HW-UUID""#))
    }

    @Test(arguments: [
        ("2026-10-16T09:31:47.004Z", "2026-10-16T09:31:47.004Z"),
        ("2026-10-16T09:31:47Z", "2026-10-16T09:31:47.000Z"),
        ("2026-10-16T09:31:47.999Z", "2026-10-16T09:31:47.999Z"),
        ("1969-12-31T23:59:59.500Z", "1969-12-31T23:59:59.500Z"),
    ])
    func dateFormattingRoundTrips(_ input: String, _ expected: String) throws {
        let date = try #require(AltiwardJSON.parse(input))
        #expect(AltiwardJSON.format(date) == expected)
    }

    /// Dates may differ in precision ("…:00Z" vs "…:00.000Z"); compare them as instants.
    private func normalizeDates(_ value: Any) -> NSObject {
        switch value {
        case let dict as NSDictionary:
            let out = NSMutableDictionary()
            for (k, v) in dict { out[k] = normalizeDates(v) }
            return out
        case let array as NSArray:
            return array.map(normalizeDates) as NSArray
        case let s as String:
            if s.count >= 20, let date = AltiwardJSON.parse(s) { return date.timeIntervalSince1970 as NSNumber }
            return s as NSString
        default:
            return value as! NSObject
        }
    }
}
