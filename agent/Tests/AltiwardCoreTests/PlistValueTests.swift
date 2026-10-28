import Foundation
import Testing

@testable import AltiwardCore

struct PlistValueTests {
    @Test func booleansAreNeverNumbers() throws {
        // Foundation bridges NSNumber(1) to true, so the type has to come from CF.
        #expect(PlistValue(NSNumber(value: 1)) == .integer(1))
        #expect(PlistValue(true) == .bool(true))
        #expect(PlistValue(kCFBooleanFalse as Any) == .bool(false))
        #expect(PlistValue.bool(true) != .integer(1))
        #expect(PlistValue.integer(0) != .bool(false))

        // As read from a property list.
        let xml = Data(
            """
            <plist version="1.0"><dict><key>b</key><true/><key>i</key><integer>1</integer>\
            <key>r</key><real>1</real><key>s</key><string>1</string></dict></plist>
            """.utf8)
        let read = try #require(PlistValue.dictionary(try PropertyListSerialization.propertyList(from: xml, format: nil)))
        #expect(read == ["b": .bool(true), "i": .integer(1), "r": .real(1), "s": .string("1")])
        #expect(read["b"] != read["i"])
    }

    @Test func numbersCompareByValue() {
        #expect(PlistValue.integer(60) == .real(60))
        #expect(PlistValue.real(60) == .integer(60))
        #expect(PlistValue.real(60.5) != .integer(60))
        #expect(PlistValue.integer(60) != .string("60"))
    }

    @Test func arraysKeepOrderAndDictionariesDont() {
        #expect(PlistValue.array([.string("a"), .string("b")]) != .array([.string("b"), .string("a")]))
        #expect(PlistValue(["a": 1, "b": 2] as [String: Any]) == PlistValue(["b": 2, "a": 1] as [String: Any]))
        #expect(PlistValue(["a": 1] as [String: Any]) != PlistValue(["a": 1, "b": 2] as [String: Any]))
    }

    @Test func datesCompareToTheSecond() {
        let date = Date(timeIntervalSinceReferenceDate: 800_000_000.2)
        #expect(PlistValue.date(date) == .date(Date(timeIntervalSinceReferenceDate: 800_000_000.9)))
        #expect(PlistValue.date(date) != .date(Date(timeIntervalSinceReferenceDate: 800_000_001)))
    }

    @Test func otherObjectsArentPropertyLists() {
        #expect(PlistValue(NSObject()) == nil)
        #expect(PlistValue([NSObject()]) == nil)
        #expect(PlistValue.dictionary([1: "a"] as NSDictionary) == nil)
    }

    @Test func roundTripsThroughABinaryPropertyList() throws {
        let settings: [String: PlistValue] = [
            "b": .bool(false), "i": .integer(-3), "r": .real(2.5), "s": .string("x"), "d": .data(Data([1, 2])),
            "t": .date(Date(timeIntervalSinceReferenceDate: 800_000_000)),
            "a": .array([.bool(true), .integer(1)]), "m": .dictionary(["k": .string("v")]),
        ]
        let back = try PlistValue.decode(try PlistValue.encode(settings))
        #expect(back == settings)
        #expect(back["a"] == .array([.bool(true), .integer(1)]))
    }

    @Test func describesTheTypeNeverTheValue() {
        #expect(PlistValue.string("token-not-shown").description == "string")
    }
}
