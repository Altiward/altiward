import Foundation
import os

/// Why a command gave no output to use.
public enum CommandFailure: Error, Equatable, Sendable, CustomStringConvertible {
    /// It couldn't be started.
    case couldNotStart(String)
    /// It hadn't finished within the time allowed, and was stopped.
    case timedOut(TimeInterval)
    /// It exited with this status, not 0.
    case exited(Int32)
    /// It printed more than this many bytes.
    case tooLarge(Int)

    public var description: String {
        switch self {
        case .couldNotStart(let why): "couldn't be started (\(why))"
        case .timedOut(let seconds): "didn't finish within \(Int(seconds)) s"
        case .exited(let status): "exited with status \(status)"
        case .tooLarge(let limit): "printed more than \(limit) bytes"
        }
    }
}

/// Runs a command for its standard output: the output when it exits 0 within `timeout` and
/// prints no more than `maxBytes`, and otherwise why not. Its input is the null device. The
/// output is read while the command runs, in chunks, and reading stops at the limit, so a
/// large one can't fill the pipe or memory. A command that overruns is stopped, with SIGKILL
/// if SIGTERM hasn't ended it within ``killGrace``.
enum CommandOutput {
    static let killGrace: TimeInterval = 2
    static let chunk = 64 << 10

    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval, maxBytes: Int)
        -> Result<Data, CommandFailure>
    {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            return .failure(.couldNotStart((error as NSError).localizedDescription))
        }
        let deadline = DispatchTime.now() + timeout
        let output = OSAllocatedUnfairLock(initialState: (data: Data(), over: false))
        let read = DispatchSemaphore(value: 0)
        let handle = pipe.fileHandleForReading
        DispatchQueue.global().async {
            var data = Data()
            var over = false
            while let more = try? handle.read(upToCount: chunk), !more.isEmpty {
                data.append(more)
                if data.count > maxBytes {
                    over = true
                    break
                }
            }
            let result = (data: data, over: over)
            output.withLock { $0 = result }
            read.signal()
        }
        guard read.wait(timeout: deadline) == .success else {
            stop(process, exited: exited)
            return .failure(.timedOut(timeout))
        }
        let (data, over) = output.withLock { $0 }
        if over {
            stop(process, exited: exited)
            return .failure(.tooLarge(maxBytes))
        }
        // The output has ended; the command may still not exit.
        guard exited.wait(timeout: deadline) == .success else {
            stop(process, exited: exited)
            return .failure(.timedOut(timeout))
        }
        guard process.terminationStatus == 0 else { return .failure(.exited(process.terminationStatus)) }
        return .success(data)
    }

    /// SIGTERM, then SIGKILL if it hasn't exited within ``killGrace``.
    private static func stop(_ process: Process, exited: DispatchSemaphore) {
        guard process.isRunning else { return }
        process.terminate()
        if exited.wait(timeout: .now() + killGrace) != .success {
            kill(process.processIdentifier, SIGKILL)
            _ = exited.wait(timeout: .now() + killGrace)
        }
    }
}
