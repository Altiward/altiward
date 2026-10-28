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
/// large one can't fill the pipe or memory. A command that overruns is stopped, with its
/// process group, by SIGKILL if SIGTERM hasn't ended it within ``killGrace``.
///
/// Everything happens on the calling thread (`posix_spawn`, `poll`, `waitpid`), with no
/// dispatch queue or Foundation `Process` to wait for: under load those could leave a
/// command that had already finished looking as if it had timed out.
enum CommandOutput {
    static let killGrace: TimeInterval = 2
    static let chunk = 64 << 10

    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval, maxBytes: Int)
        -> Result<Data, CommandFailure>
    {
        let deadline = Date().addingTimeInterval(timeout)
        var ends: [Int32] = [-1, -1]
        guard pipe(&ends) == 0 else { return .failure(.couldNotStart(String(cString: strerror(errno)))) }
        let (readEnd, writeEnd) = (ends[0], ends[1])
        defer { close(readEnd) }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, writeEnd, 1)
        posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0)
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // Only the three descriptors above reach the command, with default signal handling
        // and mask, in a process group of its own so that stopping it stops its children.
        var none = sigset_t(), all = sigset_t()
        sigemptyset(&none)
        sigfillset(&all)
        posix_spawnattr_setsigmask(&attributes, &none)
        posix_spawnattr_setsigdefault(&attributes, &all)
        posix_spawnattr_setpgroup(&attributes, 0)
        posix_spawnattr_setflags(
            &attributes,
            Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP))

        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, argv, environ)
        close(writeEnd)
        guard spawned == 0 else { return .failure(.couldNotStart(String(cString: strerror(spawned)))) }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: chunk)
        while true {
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else {
                stop(pid)
                return .failure(.timedOut(timeout))
            }
            var ready = pollfd(fd: readEnd, events: Int16(POLLIN), revents: 0)
            let polled = poll(&ready, 1, Int32(min(left * 1000, 60_000).rounded(.up)))
            if polled < 0 && errno != EINTR {
                stop(pid)
                return .failure(.couldNotStart("poll: \(String(cString: strerror(errno)))"))
            }
            guard polled > 0 else { continue }
            let count = read(readEnd, &buffer, chunk)
            if count < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                stop(pid)
                return .failure(.couldNotStart("read: \(String(cString: strerror(errno)))"))
            }
            if count == 0 { break }  // the output has ended; the command may still not exit
            data.append(buffer, count: count)
            if data.count > maxBytes {
                stop(pid)
                return .failure(.tooLarge(maxBytes))
            }
        }
        guard let status = reap(pid, until: deadline) else {
            stop(pid)
            return .failure(.timedOut(timeout))
        }
        guard status == 0 else { return .failure(.exited(status)) }
        return .success(data)
    }

    /// Waits for `pid` to exit until `deadline`: its exit status, or the signal that ended it;
    /// nil if it hasn't exited by then.
    private static func reap(_ pid: pid_t, until deadline: Date) -> Int32? {
        var status: Int32 = 0
        while true {
            let reaped = waitpid(pid, &status, WNOHANG)
            if reaped == pid {
                let signal = status & 0x7f
                return signal == 0 ? (status >> 8) & 0xff : signal
            }
            if reaped < 0 && errno != EINTR { return -1 }
            if deadline.timeIntervalSinceNow <= 0 { return nil }
            usleep(10_000)
        }
    }

    /// SIGTERM to its process group, then SIGKILL if it hasn't exited within ``killGrace``;
    /// reaped either way.
    private static func stop(_ pid: pid_t) {
        kill(-pid, SIGTERM)
        if reap(pid, until: Date().addingTimeInterval(killGrace)) != nil { return }
        kill(-pid, SIGKILL)
        _ = reap(pid, until: Date().addingTimeInterval(killGrace))
    }
}
