import Foundation

/// A JSON value, used for the free-form `detail` object.
public enum JSONValue: Codable, Sendable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? c.decode(Double.self) {
            self = .number(n)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else {
            self = .object(try c.decode([String: JSONValue].self))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .number(let n):
            // Keep integers integral on the wire ("501", not "501.0").
            if n.rounded() == n, abs(n) < 1e15 { try c.encode(Int64(n)) } else { try c.encode(n) }
        case .bool(let b): try c.encode(b)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        case .null: try c.encodeNil()
        }
    }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByBooleanLiteral,
    ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral, ExpressibleByNilLiteral
{
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
    public init(nilLiteral: ()) { self = .null }
}

extension JSONValue {
    public static func strings(_ values: some Sequence<String>) -> JSONValue {
        .array(values.map { .string($0) })
    }

    public static func optional(_ value: String?) -> JSONValue {
        value.map { .string($0) } ?? .null
    }

    public static func date(_ value: Date) -> JSONValue {
        .string(AltiwardJSON.format(value))
    }
}

/// Shared JSON configuration: RFC 3339 dates with milliseconds, UTC, sorted keys.
public enum AltiwardJSON {
    private static let fractional = Date.ISO8601FormatStyle(includingFractionalSeconds: true)
    private static let whole = Date.ISO8601FormatStyle()

    /// Formats with exactly three fractional digits, rounded (not truncated) to the
    /// millisecond, so values survive decode/encode round trips unchanged.
    public static func format(_ date: Date) -> String {
        let millis = Int64((date.timeIntervalSince1970 * 1000).rounded())
        let (seconds, ms) = millis.quotientAndRemainder(dividingBy: 1000)
        let whole = Date(timeIntervalSince1970: TimeInterval(ms < 0 ? seconds - 1 : seconds))
        let base = whole.formatted(Self.whole)  // "2026-10-16T09:31:47Z"
        return base.dropLast() + String(format: ".%03lldZ", ms < 0 ? ms + 1000 : ms)
    }

    public static func parse(_ string: String) -> Date? {
        (try? fractional.parse(string)) ?? (try? whole.parse(string))
    }

    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        e.dateEncodingStrategy = .custom { date, encoder in
            var c = encoder.singleValueContainer()
            try c.encode(format(date))
        }
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let c = try decoder.singleValueContainer()
            let s = try c.decode(String.self)
            guard let date = parse(s) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "Invalid RFC 3339 date: \(s)")
            }
            return date
        }
        return d
    }
}
