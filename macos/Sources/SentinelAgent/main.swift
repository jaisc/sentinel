// SentinelAgent — the always-on download/persistence watcher (launchd agent, no Dock icon).
//
// FSEvents watches the configured folders. When a new file has settled (no events for a few
// seconds, size stable, no .crdownload sibling) the engine scans it:
//     sentinel scan --if-new --json --no-notify --source watcher <path>
// Caution/Dangerous results become a macOS notification with Open report / Allow once /
// Always allow / Remove… buttons. "Remove…" asks for confirmation before anything moves.
// Changes in LaunchAgents/LaunchDaemons folders trigger `sentinel persistence check`.

import AppKit
import CoreServices
import Foundation
import SentinelShared
import UserNotifications

final class AgentDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var stream: FSEventStreamRef?
    private var watchFolders: [String] = []
    private var persistenceFolders: [String] = []
    private var pending: [String: (lastEvent: Date, size: Int64)] = [:]
    private var settleSeconds: TimeInterval = 2.0
    private var minVerdict = "caution"
    private var notificationsEnabled = true
    private var paused = false
    private var notificationsAuthorized = false
    private var persistenceTimer: Timer?
    private var settleTimer: Timer?
    private var persistenceCheckScheduled = false
    private let scanQueue = DispatchQueue(label: "sentinel.scan")   // serial: one engine at a time

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupNotifications()
        loadConfig()
        startStream()
        let dnc = DistributedNotificationCenter.default()
        dnc.addObserver(self, selector: #selector(configChanged), name: SentinelSignals.configChanged, object: nil)
        dnc.addObserver(self, selector: #selector(pause), name: SentinelSignals.pause, object: nil)
        dnc.addObserver(self, selector: #selector(resume), name: SentinelSignals.resume, object: nil)
        settleTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in self?.checkPending() }
        // FSEvents doesn't see cron jobs or profiles, so also check startup items every 10 minutes.
        persistenceTimer = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in self?.runPersistenceCheck() }
        runPersistenceCheck()  // first run records the baseline silently
        writeStatus()
    }

    // MARK: config

    private func loadConfig() {
        let cfg = SentinelConfig.load()
        watchFolders = SentinelConfig.watchFolders(cfg).map(SentinelPaths.expand).filter { isDir($0) }
        persistenceFolders = SentinelConfig.persistenceFolders(cfg).map(SentinelPaths.expand).filter { isDir($0) }
        let w = SentinelConfig.section(cfg, "watcher")
        settleSeconds = (w["settle_seconds"] as? Double) ?? 2.0
        let n = SentinelConfig.section(cfg, "notifications")
        notificationsEnabled = (n["enabled"] as? Bool) ?? true
        minVerdict = (n["min_verdict"] as? String) ?? "caution"
    }

    private func isDir(_ p: String) -> Bool {
        var d: ObjCBool = false
        return FileManager.default.fileExists(atPath: p, isDirectory: &d) && d.boolValue
    }

    @objc private func configChanged() {
        loadConfig()
        stopStream()
        startStream()
        writeStatus()
    }

    @objc private func pause() {
        paused = true
        stopStream()
        writeStatus()
    }

    @objc private func resume() {
        paused = false
        loadConfig()
        startStream()
        writeStatus()
    }

    private func writeStatus() {
        AgentStatus(watching: !paused && stream != nil, folders: watchFolders, pid: ProcessInfo.processInfo.processIdentifier,
                    updated: isoNow()).save()
    }

    // MARK: FSEvents

    private func startStream() {
        guard !paused else { return }
        let paths = (watchFolders + persistenceFolders) as CFArray
        if watchFolders.isEmpty && persistenceFolders.isEmpty { return }
        var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                       retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info = info else { return }
            let me = Unmanaged<AgentDelegate>.fromOpaque(info).takeUnretainedValue()
            let arr = unsafeBitCast(eventPaths, to: NSArray.self)
            for i in 0..<count {
                if let p = arr[i] as? String { me.handleEvent(path: p) }
            }
        }
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagNoDefer)
        guard let s = FSEventStreamCreate(kCFAllocatorDefault, callback, &ctx, paths,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.5, flags) else {
            NSLog("Sentinel: could not create FSEvents stream")
            return
        }
        FSEventStreamSetDispatchQueue(s, DispatchQueue.main)
        FSEventStreamStart(s)
        stream = s
        NSLog("Sentinel: watching %@", (watchFolders + persistenceFolders).joined(separator: ", "))
    }

    private func stopStream() {
        if let s = stream {
            FSEventStreamStop(s)
            FSEventStreamInvalidate(s)
            FSEventStreamRelease(s)
        }
        stream = nil
    }

    private static let partialSuffixes = [".crdownload", ".download", ".part", ".partial", ".opdownload", ".tmp"]
    private static let bundleSuffixes = [".app", ".pkg", ".mpkg", ".bundle", ".plugin", ".framework", ".scptd", ".workflow"]

    /// Map an event path to the item to scan: the file itself, or the enclosing bundle (Foo.app).
    private func scanTarget(for path: String) -> String? {
        guard let root = watchFolders.first(where: { path == $0 || path.hasPrefix($0 + "/") }) else { return nil }
        let rel = path.dropFirst(root.count).split(separator: "/").map(String.init)
        if rel.isEmpty { return nil }
        var current = root
        for (i, comp) in rel.enumerated() {
            if comp.hasPrefix(".") { return nil }
            current += "/" + comp
            let lower = comp.lowercased()
            if Self.bundleSuffixes.contains(where: { lower.hasSuffix($0) }) { return current }
            if Self.partialSuffixes.contains(where: { lower.hasSuffix($0) }) { return nil }
            if i >= 2 { return nil }  // watch folder + 2 levels (Mail Downloads/<uuid>/file)
        }
        return current
    }

    fileprivate func handleEvent(path: String) {
        if path.hasPrefix(SentinelPaths.dataDir.path) { return }
        if persistenceFolders.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) {
            schedulePersistenceCheck()
            return
        }
        guard let target = scanTarget(for: path) else { return }
        pending[target] = (Date(), fileSize(target))
    }

    private func fileSize(_ p: String) -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: p)
        return (attrs?[.size] as? NSNumber)?.int64Value ?? -1
    }

    private func checkPending() {
        let now = Date()
        for (path, state) in pending {
            guard now.timeIntervalSince(state.lastEvent) >= settleSeconds else { continue }
            if !FileManager.default.fileExists(atPath: path) { pending[path] = nil; continue }
            // Plain folders (e.g. Mail's per-message folders) aren't items; their files get their own events.
            let lowerPath = path.lowercased()
            if isDir(path) && !Self.bundleSuffixes.contains(where: { lowerPath.hasSuffix($0) }) { pending[path] = nil; continue }
            let size = fileSize(path)
            if size != state.size {  // still growing: wait another round
                pending[path] = (now, size)
                continue
            }
            if Self.partialSuffixes.contains(where: { FileManager.default.fileExists(atPath: path + $0) }) { continue }
            pending[path] = nil
            scan(path)
        }
    }

    // MARK: engine

    private func scan(_ path: String) {
        scanQueue.async { [weak self] in
            let r = Engine.run(["scan", "--if-new", "--json", "--no-notify", "--source", "watcher", path])
            for line in r.stdout.split(separator: "\n") {
                guard let d = line.data(using: .utf8),
                      let rec = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
                DispatchQueue.main.async { self?.alert(rec) }
            }
            if r.status == 127 { NSLog("Sentinel: %@", r.stderr) }
        }
    }

    private func schedulePersistenceCheck() {
        if persistenceCheckScheduled { return }
        persistenceCheckScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            self?.persistenceCheckScheduled = false
            self?.runPersistenceCheck()
        }
    }

    private func runPersistenceCheck() {
        scanQueue.async { [weak self] in
            let r = Engine.run(["persistence", "check", "--json", "--no-notify"])
            for line in r.stdout.split(separator: "\n") {
                guard let d = line.data(using: .utf8),
                      let rec = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
                DispatchQueue.main.async { self?.alert(rec) }
            }
        }
    }

    // MARK: notifications

    private func rank(_ v: String) -> Int { ["clean": 0, "caution": 1, "dangerous": 2][v] ?? 0 }

    private func setupNotifications() {
        let c = UNUserNotificationCenter.current()
        c.delegate = self
        let open = UNNotificationAction(identifier: "OPEN", title: "Open report", options: [.foreground])
        let remove = UNNotificationAction(identifier: "REMOVE", title: "Remove…", options: [.foreground])
        let once = UNNotificationAction(identifier: "ALLOW_ONCE", title: "Allow once", options: [])
        let always = UNNotificationAction(identifier: "ALWAYS_ALLOW", title: "Always allow this source", options: [])
        let cat = UNNotificationCategory(identifier: "SENTINEL_ALERT", actions: [open, remove, once, always],
                                         intentIdentifiers: [], options: [])
        c.setNotificationCategories([cat])
        c.requestAuthorization(options: [.alert, .sound]) { [weak self] granted, _ in
            DispatchQueue.main.async { self?.notificationsAuthorized = granted }
        }
    }

    private func alert(_ rec: [String: Any]) {
        guard notificationsEnabled,
              let verdict = rec["verdict"] as? String, rank(verdict) >= max(1, rank(minVerdict)),
              (rec["allowlisted"] as? [String: Any]) == nil,
              let id = rec["id"] as? String else { return }
        let title = "Sentinel — " + ((rec["title"] as? String) ?? "alert")
        let body = (rec["summary"] as? String) ?? ""
        let report = (rec["report_path"] as? String) ?? ""
        if notificationsAuthorized {
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body + ((rec["kind"] as? String) == "file" ? "\nTap Open report for where it came from and how to remove it." : "")
            content.sound = .default
            content.categoryIdentifier = "SENTINEL_ALERT"
            content.userInfo = ["id": id, "report": report, "name": (rec["name"] as? String) ?? id]
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
        } else {
            // Fallback when notification permission was not granted.
            let esc = { (s: String) in s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", "display notification \"\(esc(body))\" with title \"\(esc(title))\""]
            try? p.run()
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let info = response.notification.request.content.userInfo
        let id = (info["id"] as? String) ?? ""
        let report = (info["report"] as? String) ?? ""
        let name = (info["name"] as? String) ?? id
        let action = response.actionIdentifier
        completionHandler()
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            switch action {
            case "REMOVE":
                self.confirmRemove(id: id, name: name)
            case "ALLOW_ONCE":
                self.scanQueue.async { _ = Engine.run(["allow-once", id]) }
            case "ALWAYS_ALLOW":
                self.scanQueue.async { _ = Engine.run(["allow", id]) }
            default:  // OPEN or a click on the banner itself
                if !report.isEmpty { NSWorkspace.shared.open(URL(fileURLWithPath: report)) }
            }
        }
    }

    /// Explicit, per-item approval before anything is moved.
    private func confirmRemove(id: String, name: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Move “\(name)” to Sentinel quarantine?"
        a.informativeText = "The item (and any startup entries Sentinel linked to it) will be moved to ~/.Sentinel/Quarantine. Nothing is deleted — you can restore it from the menu bar or with `sentinel restore \(id)`."
        a.alertStyle = .warning
        a.addButton(withTitle: "Move to Quarantine")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        scanQueue.async {
            let r = Engine.run(["remove", id, "--yes"])
            DispatchQueue.main.async {
                let done = NSAlert()
                done.messageText = r.status == 0 ? "Moved to quarantine" : "Removal needs attention"
                done.informativeText = (r.stdout + r.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
                done.runModal()
            }
        }
    }
}

let app = NSApplication.shared
let delegate = AgentDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
