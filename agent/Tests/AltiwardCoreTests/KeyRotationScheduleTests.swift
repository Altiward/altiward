import Foundation
import Testing
import os

@testable import AltiwardCore

/// The daemon's rotation schedule, driven by a test clock and a stand-in for the key, so
/// nothing waits for real time.
struct KeyRotationScheduleTests {
    let clock = TestClock()

    /// What the stand-in key was asked, and what it answers.
    final class Key: Sendable {
        private struct State {
            var asked: [Date] = []
            var rotated: [String] = []
            var due: String? = "test reason"
            var outcome: RotationOutcome = .unknown
            var failure: Bool = false
        }
        struct Failed: Error {}
        private let state = OSAllocatedUnfairLock(initialState: State())

        var asked: [Date] { state.withLock { $0.asked } }
        var rotated: [String] { state.withLock { $0.rotated } }
        func answer(due: String?, outcome: RotationOutcome = .unknown) {
            state.withLock {
                $0.due = due
                $0.outcome = outcome
            }
        }
        func fail(_ failure: Bool) { state.withLock { $0.failure = failure } }

        func due(_ now: Date) throws -> String? {
            try state.withLock {
                $0.asked.append(now)
                if $0.failure { throw Failed() }
                return $0.due
            }
        }
        func rotate(_ reason: String) -> RotationOutcome {
            state.withLock {
                $0.rotated.append(reason)
                return $0.outcome
            }
        }
    }

    func schedule(_ key: Key, firstCheckAfter: TimeInterval = 600) -> KeyRotationSchedule {
        KeyRotationSchedule(
            due: { try key.due($0) }, rotate: { key.rotate($0) }, now: { clock.now }, firstCheckAfter: firstCheckAfter)
    }

    @Test(.timeLimit(.minutes(1))) func theFirstCheckComesFiveToSixtyFiveMinutesAfterStart() {
        #expect(KeyRotationSchedule.firstCheckDelay == 300...3900)
        #expect(KeyRotationSchedule.checkInterval == 3600)
    }

    @Test(.timeLimit(.minutes(1))) func nothingIsCheckedBeforeTheFirstCheck() async {
        let key = Key()
        let schedule = schedule(key, firstCheckAfter: 600)
        clock.advance(599)
        #expect(await schedule.checkIfDue() == nil)
        #expect(key.asked.isEmpty)
        clock.advance(1)
        #expect(await schedule.checkIfDue() == .unknown)
        #expect(key.asked == [clock.now])
        #expect(key.rotated == ["test reason"])
    }

    @Test(.timeLimit(.minutes(1))) func everyCheckAfterTheFirstAsksAgain() async {
        let key = Key()
        key.answer(due: nil)
        let schedule = schedule(key, firstCheckAfter: 300)
        clock.advance(300)
        for _ in 0..<3 {
            #expect(await schedule.checkIfDue() == nil)
            clock.advance(60)
        }
        #expect(key.asked.count == 3)
        #expect(key.rotated.isEmpty)

        key.answer(due: "now due", outcome: .rotated(.software))
        #expect(await schedule.checkIfDue() == .rotated(.software))
        #expect(key.rotated == ["now due"])
    }

    @Test(.timeLimit(.minutes(1))) func aDeferralIsHonouredByTheWallClock() async {
        let key = Key()
        key.answer(due: "test reason", outcome: .deferred(until: clock.now.addingTimeInterval(600 + 86400)))
        let schedule = schedule(key, firstCheckAfter: 600)
        clock.advance(600)
        #expect(await schedule.checkIfDue() == .deferred(until: clock.now.addingTimeInterval(86400)))

        // A sleeping Mac's wall clock moves on while the daemon doesn't, so the time counts.
        clock.advance(86400 - 1)
        #expect(await schedule.checkIfDue() == nil)
        #expect(key.asked.count == 1)
        key.answer(due: "test reason", outcome: .rotated(.software))
        clock.advance(1)
        #expect(await schedule.checkIfDue() == .rotated(.software))
        #expect(key.asked.count == 2)
    }

    @Test(.timeLimit(.minutes(1))) func aFailureToCheckIsTriedAgainAtTheNextCheck() async {
        let key = Key()
        key.fail(true)
        let schedule = schedule(key, firstCheckAfter: 0)
        #expect(await schedule.checkIfDue() == nil)
        #expect(key.rotated.isEmpty)
        key.fail(false)
        #expect(await schedule.checkIfDue() == .unknown)
        #expect(key.rotated == ["test reason"])
    }
}
