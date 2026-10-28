import CryptoKit
import Foundation

/// Event types from the core event schema (docs/schema/event.schema.json).
public enum EventType: String, Codable, Sendable, CaseIterable {
    case elevationGranted = "elevation.granted"
    case elevationRevoked = "elevation.revoked"
    case elevationExpiredEnforced = "elevation.expired_enforced"
    case elevationOverdue = "elevation.overdue"
    case adminOutOfBand = "admin.out_of_band"
    case adminOutOfBandRemoved = "admin.out_of_band_removed"
    case activity = "activity"
    case persistenceDetected = "persistence.detected"
    case agentHealth = "agent.health"
    case agentTamper = "agent.tamper"
    /// Raised by the backend when a Mac stops checking in; the agent never sends it.
    case agentSilent = "agent.silent"
    /// A permanent admin account was used: a sign-in, an authorisation prompt or screen sharing.
    case adminPermanentUse = "admin.permanent_use"
    /// Raised by the backend when a Mac enrols a key; the agent never sends it.
    case agentEnrollment = "agent.enrollment"
    /// Raised by the backend to send a Mac's admin group to the SIEM; the agent never sends it.
    case agentAdminGroup = "agent.admin_group"
}

public struct DeviceInfo: Codable, Sendable, Equatable {
    public var serial: String
    public var hardwareUUID: String
    public var osVersion: String
    public var agentVersion: String
    public var privilegesVersion: String?

    public init(serial: String, hardwareUUID: String, osVersion: String, agentVersion: String, privilegesVersion: String?) {
        self.serial = serial
        self.hardwareUUID = hardwareUUID
        self.osVersion = osVersion
        self.agentVersion = agentVersion
        self.privilegesVersion = privilegesVersion
    }

    enum CodingKeys: String, CodingKey {
        case serial
        case hardwareUUID = "hardware_uuid"
        case osVersion = "os_version"
        case agentVersion = "agent_version"
        case privilegesVersion = "privileges_version"
    }

    // Encode the null explicitly (a Mac without SAP Privileges has no version) so every event has the same shape.
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serial, forKey: .serial)
        try c.encode(hardwareUUID, forKey: .hardwareUUID)
        try c.encode(osVersion, forKey: .osVersion)
        try c.encode(agentVersion, forKey: .agentVersion)
        try c.encode(privilegesVersion, forKey: .privilegesVersion)
    }
}

public struct UserInfo: Codable, Sendable, Equatable {
    public var localName: String
    public var upn: String?

    public init(localName: String, upn: String?) {
        self.localName = localName
        self.upn = upn
    }

    enum CodingKeys: String, CodingKey {
        case localName = "local_name"
        case upn
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(localName, forKey: .localName)
        try c.encode(upn, forKey: .upn)
    }
}

public enum ElevationSource: String, Codable, Sendable {
    case privileges
    case outOfBand = "out_of_band"
}

public struct ElevationInfo: Codable, Sendable, Equatable {
    public var reason: String?
    public var expires: Date?
    public var source: ElevationSource

    public init(reason: String? = nil, expires: Date? = nil, source: ElevationSource) {
        self.reason = reason
        self.expires = expires
        self.source = source
    }

    enum CodingKeys: String, CodingKey {
        case reason
        case expires
        case source
    }

    // Encode nulls explicitly so every event has the same shape on the wire.
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(reason, forKey: .reason)
        try c.encode(expires, forKey: .expires)
        try c.encode(source, forKey: .source)
    }
}

/// One record sent from the agent to the Altiward API.
public struct AltiwardEvent: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    /// Lower-case UUID string.
    public var eventID: String
    public var type: EventType
    /// Lower-case UUID string; nil for events outside an elevation session.
    public var sessionID: String?
    public var timestamp: Date
    public var device: DeviceInfo
    public var user: UserInfo?
    public var elevation: ElevationInfo?
    public var delayed: Bool
    public var detail: [String: JSONValue]

    public init(
        eventID: String = newID(),
        type: EventType,
        sessionID: String?,
        timestamp: Date,
        device: DeviceInfo,
        user: UserInfo?,
        elevation: ElevationInfo?,
        delayed: Bool = false,
        detail: [String: JSONValue] = [:]
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.eventID = eventID
        self.type = type
        self.sessionID = sessionID
        self.timestamp = timestamp
        self.device = device
        self.user = user
        self.elevation = elevation
        self.delayed = delayed
        self.detail = detail
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case eventID = "event_id"
        case type
        case sessionID = "session_id"
        case timestamp
        case device
        case user
        case elevation
        case delayed
        case detail
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try c.encode(eventID, forKey: .eventID)
        try c.encode(type, forKey: .type)
        try c.encode(sessionID, forKey: .sessionID)
        try c.encode(timestamp, forKey: .timestamp)
        try c.encode(device, forKey: .device)
        try c.encode(user, forKey: .user)
        try c.encode(elevation, forKey: .elevation)
        try c.encode(delayed, forKey: .delayed)
        try c.encode(detail, forKey: .detail)
    }
}

/// New lower-case UUID string, the form the schema requires.
public func newID() -> String {
    UUID().uuidString.lowercased()
}

/// Lower-case name-based UUID (version 5, RFC 9562 section 5.5) of `name` under the URL namespace,
/// so the same name always gives the same ID and a repeated report is a duplicate, not a new event.
public func nameBasedID(_ name: String) -> String {
    let namespace: [UInt8] = [
        0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
    ]
    var hash = Insecure.SHA1()
    hash.update(data: namespace)
    hash.update(data: Data(name.utf8))
    var bytes = Array(hash.finalize().prefix(16))
    bytes[6] = (bytes[6] & 0x0f) | 0x50
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    let parts = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { r -> String in
        let start = hex.index(hex.startIndex, offsetBy: r.lowerBound)
        return String(hex[start..<hex.index(hex.startIndex, offsetBy: r.upperBound)])
    }
    return parts.joined(separator: "-")
}
