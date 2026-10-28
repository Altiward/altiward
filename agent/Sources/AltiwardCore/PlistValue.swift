import CoreFoundation
import Foundation

/// A property-list value, for comparing a setting as macOS stores it with the value an MDM
/// profile sets. Built by CF type, so a boolean is never read as the number 1 (Foundation
/// bridges `NSNumber(1) as? Bool` to true). Equality is by value: an integer and a real are
/// equal when their values are, arrays compare in order, dictionaries without order, and
/// dates to the second.
public indirect enum PlistValue: Sendable, CustomStringConvertible {
    case bool(Bool)
    case integer(Int64)
    case real(Double)
    case string(String)
    case date(Date)
    case data(Data)
    case array([PlistValue])
    case dictionary([String: PlistValue])

    /// Nil for anything that isn't a property-list type, or a dictionary with a key that
    /// isn't a string.
    public init?(_ value: Any) {
        let object = value as AnyObject
        if CFGetTypeID(object) == CFBooleanGetTypeID(), let flag = object as? NSNumber {
            self = .bool(flag.boolValue)
        } else if CFGetTypeID(object) == CFNumberGetTypeID(), let number = object as? NSNumber {
            self = CFNumberIsFloatType(number as CFNumber) ? .real(number.doubleValue) : .integer(number.int64Value)
        } else if let string = value as? String {
            self = .string(string)
        } else if let date = value as? Date {
            self = .date(date)
        } else if let data = value as? Data {
            self = .data(data)
        } else if let array = value as? [Any] {
            var items: [PlistValue] = []
            for item in array {
                guard let v = PlistValue(item) else { return nil }
                items.append(v)
            }
            self = .array(items)
        } else if let dictionary = value as? NSDictionary {
            var entries: [String: PlistValue] = [:]
            for (key, item) in dictionary {
                guard let key = key as? String, let v = PlistValue(item) else { return nil }
                entries[key] = v
            }
            self = .dictionary(entries)
        } else {
            return nil
        }
    }

    /// The value as Foundation property-list objects, for `PropertyListSerialization` and
    /// ``Preferences``.
    public var propertyList: Any {
        switch self {
        case .bool(let b): b as NSNumber
        case .integer(let i): NSNumber(value: i)
        case .real(let d): NSNumber(value: d)
        case .string(let s): s
        case .date(let d): d
        case .data(let d): d
        case .array(let a): a.map(\.propertyList)
        case .dictionary(let d): d.mapValues(\.propertyList)
        }
    }

    /// The type only, never the value: settings such as `EnrollmentToken` are secrets.
    public var description: String {
        switch self {
        case .bool: "boolean"
        case .integer: "integer"
        case .real: "real"
        case .string: "string"
        case .date: "date"
        case .data: "data"
        case .array: "array"
        case .dictionary: "dictionary"
        }
    }

    /// A dictionary of values from property-list objects; nil when any value isn't one.
    public static func dictionary(_ object: Any) -> [String: PlistValue]? {
        guard case .dictionary(let d)? = PlistValue(object) else { return nil }
        return d
    }

    /// A binary property list of `settings`, for the store.
    static func encode(_ settings: [String: PlistValue]) throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: settings.mapValues(\.propertyList), format: .binary, options: 0)
    }

    static func decode(_ data: Data) throws -> [String: PlistValue] {
        let object = try PropertyListSerialization.propertyList(from: data, format: nil)
        guard let settings = dictionary(object) else { throw CocoaError(.propertyListReadCorrupt) }
        return settings
    }
}

extension PlistValue: Equatable {
    public static func == (a: PlistValue, b: PlistValue) -> Bool {
        switch (a, b) {
        case (.bool(let x), .bool(let y)): x == y
        case (.integer(let x), .integer(let y)): x == y
        case (.real(let x), .real(let y)): x == y
        case (.integer(let x), .real(let y)), (.real(let y), .integer(let x)): Int64(exactly: y) == x
        case (.string(let x), .string(let y)): x == y
        case (.date(let x), .date(let y)):
            x.timeIntervalSinceReferenceDate.rounded(.down) == y.timeIntervalSinceReferenceDate.rounded(.down)
        case (.data(let x), .data(let y)): x == y
        case (.array(let x), .array(let y)): x == y
        case (.dictionary(let x), .dictionary(let y)): x == y
        default: false
        }
    }
}
