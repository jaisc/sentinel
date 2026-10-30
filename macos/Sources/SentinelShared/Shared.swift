import Foundation

/// Locations shared with the Python engine (see engine/sentinel/paths.py).
public enum SentinelPaths {
    public static let home = FileManager.default.homeDirectoryForCurrentUser
    public static let dataDir = home.appendingPathComponent(".Sentinel", isDirectory: true)
    public static let reportsDir = home.appendingPathComponent("Sentinel/Reports", isDirectory: true)
    public static let quarantineDir = dataDir.appendingPathComponent("Quarantine", isDirectory: true)
    public static let feed = dataDir.appendingPathComponent("events.jsonl")
    public static let config = dataDir.appendingPathComponent("config.json")
    public static let agentStatus = dataDir.appendingPathComponent("state/agent-status.json")
    /// Installed by setup.sh: a wrapper that runs the engine with an absolute python3 path.
    public static let engineCLI = home.appendingPathComponent("Library/Application Support/Sentinel/bin/sentinel")

    public static func expand(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }
}

/// Distributed notifications between the menu-bar app and the agent (no payloads with secrets).
public enum SentinelSignals {
    public static let configChanged = Notification.Name("com.sentinel.configChanged")
    public static let pause = Notification.Name("com.sentinel.pause")
    public static let resume = Notification.Name("com.sentinel.resume")
}

public struct EngineResult {
    public let status: Int32
    public let stdout: String
    public let stderr: String
}

/// Runs the Python engine CLI. Arguments are passed as an argv array (no shell).
public enum Engine {
    @discardableResult
    public static func run(_ args: [String], stdin: String? = nil) -> EngineResult {
        let p = Process()
        p.executableURL = SentinelPaths.engineCLI
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        let inPipe = Pipe()
        p.standardInput = inPipe
        do {
            try p.run()
        } catch {
            return EngineResult(status: 127, stdout: "", stderr: "Could not start the Sentinel engine at \(SentinelPaths.engineCLI.path): \(error.localizedDescription)")
        }
        if let s = stdin, let d = s.data(using: .utf8) {
            inPipe.fileHandleForWriting.write(d)
        }
        try? inPipe.fileHandleForWriting.close()
        // Read before waiting so a large output can't fill the pipe and deadlock.
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return EngineResult(status: p.terminationStatus,
                            stdout: String(data: o, encoding: .utf8) ?? "",
                            stderr: String(data: e, encoding: .utf8) ?? "")
    }
}

/// One line of ~/.Sentinel/events.jsonl
public struct FeedEvent: Codable, Identifiable, Hashable {
    public let id: String
    public let kind: String?
    public let verdict: String?
    public let title: String?
    public let summary: String?
    public let at: String?
    public let report: String?
    public let plan: String?
    public let path: String?
    public let allowlisted: Bool?

    public var isFlagged: Bool { verdict == "caution" || verdict == "dangerous" }

    public static func recent(limit: Int = 30, flaggedOnly: Bool = true) -> [FeedEvent] {
        guard let data = try? Data(contentsOf: SentinelPaths.feed),
              let text = String(data: data, encoding: .utf8) else { return [] }
        let dec = JSONDecoder()
        var out: [FeedEvent] = []
        var seen = Set<String>()
        for line in text.split(separator: "\n").reversed() {
            guard let d = line.data(using: .utf8), let e = try? dec.decode(FeedEvent.self, from: d) else { continue }
            if seen.contains(e.id) { continue }
            seen.insert(e.id)
            if flaggedOnly && !e.isFlagged { continue }
            out.append(e)
            if out.count >= limit { break }
        }
        return out
    }
}

/// config.json as a loosely-typed dictionary, so unknown keys written by the engine are preserved.
public enum SentinelConfig {
    public static func load() -> [String: Any] {
        guard let d = try? Data(contentsOf: SentinelPaths.config),
              let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return [:] }
        return obj
    }

    public static func save(_ cfg: [String: Any]) throws {
        try FileManager.default.createDirectory(at: SentinelPaths.dataDir, withIntermediateDirectories: true)
        let d = try JSONSerialization.data(withJSONObject: cfg, options: [.prettyPrinted, .sortedKeys])
        try d.write(to: SentinelPaths.config, options: .atomic)
        DistributedNotificationCenter.default().postNotificationName(SentinelSignals.configChanged, object: nil, userInfo: nil, deliverImmediately: true)
    }

    public static let defaultWatchFolders = [
        "~/Downloads", "~/Desktop", "~/Library/Mail Downloads",
        "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
    ]
    public static let defaultPersistenceFolders = ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]

    public static func watchFolders(_ cfg: [String: Any]) -> [String] {
        (cfg["watch_folders"] as? [String]) ?? defaultWatchFolders
    }

    public static func persistenceFolders(_ cfg: [String: Any]) -> [String] {
        (cfg["persistence_folders"] as? [String]) ?? defaultPersistenceFolders
    }

    public static func section(_ cfg: [String: Any], _ name: String) -> [String: Any] {
        (cfg[name] as? [String: Any]) ?? [:]
    }
}

/// Keychain access for the apps. Writes go through `/usr/bin/security -i` with the command on
/// stdin, so secrets never appear in process arguments, and the engine (which reads with the
/// same `security` tool) can read them without an extra Keychain prompt. Secrets are never logged.
public enum SentinelKeychain {
    public static let service = "Sentinel"

    private static func quote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    public static func store(account: String, secret: String) -> Bool {
        let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("\n") else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["-i"]
        let inPipe = Pipe(), out = Pipe()
        p.standardInput = inPipe
        p.standardOutput = out
        p.standardError = out
        do { try p.run() } catch { return false }
        let cmd = "add-generic-password -U -s \(quote(service)) -a \(quote(account)) -l \(quote("Sentinel: " + account)) -w \(quote(trimmed))\n"
        inPipe.fileHandleForWriting.write(cmd.data(using: .utf8)!)
        try? inPipe.fileHandleForWriting.close()
        let o = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        return p.terminationStatus == 0 && !o.lowercased().contains("error")
    }

    /// True if an item exists (does not read the secret).
    public static func exists(account: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", service, "-a", account]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    public static func delete(account: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["delete-generic-password", "-s", service, "-a", account]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }
}

public struct AgentStatus: Codable {
    public var watching: Bool
    public var folders: [String]
    public var pid: Int32
    public var updated: String

    public init(watching: Bool, folders: [String], pid: Int32, updated: String) {
        self.watching = watching
        self.folders = folders
        self.pid = pid
        self.updated = updated
    }

    public static func load() -> AgentStatus? {
        guard let d = try? Data(contentsOf: SentinelPaths.agentStatus) else { return nil }
        return try? JSONDecoder().decode(AgentStatus.self, from: d)
    }

    public func save() {
        let url = SentinelPaths.agentStatus
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(self) { try? d.write(to: url, options: .atomic) }
    }

    /// The agent is considered alive if its process still exists.
    public var isAlive: Bool { pid > 0 && kill(pid, 0) == 0 }
}

public func isoNow() -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f.string(from: Date())
}
