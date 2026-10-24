import Foundation
import IOKit

public enum AgentVersion {
    public static let current = "0.3.0"
}

/// Reads the Mac's identity for the `device` block of every event.
public enum DeviceIdentity {
    public static let privilegesAppPath = "/Applications/Privileges.app"

    public static func current() -> DeviceInfo {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return DeviceInfo(
            serial: platformProperty(kIOPlatformSerialNumberKey) ?? "unknown",
            hardwareUUID: platformProperty(kIOPlatformUUIDKey) ?? "unknown",
            osVersion: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            agentVersion: AgentVersion.current,
            privilegesVersion: privilegesVersion())
    }

    public static func privilegesVersion(appPath: String = privilegesAppPath) -> String? {
        let plist = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
            let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        return info["CFBundleShortVersionString"] as? String
    }

    private static func platformProperty(_ key: String) -> String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        return IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String
    }
}
