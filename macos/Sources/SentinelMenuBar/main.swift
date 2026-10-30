// Sentinel menu-bar app (plain AppKit, builds with Command Line Tools): shield status, the newest events, shortcuts
// to the Reports and Quarantine folders. Read-only: it never changes, moves or deletes files,
// makes no network calls and holds no secrets. Sentinel keeps working without this app.

import AppKit
import Foundation
import SentinelShared

/// One ~/.Sentinel/events/<id>.json record, read loosely so missing or null fields are fine.
struct EventSummary {
    let id: String
    let verdict: String
    let fileName: String
    let seen: Date?
    let reportPath: String?
    let allowlisted: Bool

    init?(url: URL) {
        guard let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        func str(_ key: String) -> String? {
            guard let s = obj[key] as? String, !s.isEmpty else { return nil }
            return s
        }
        id = str("id") ?? url.deletingPathExtension().lastPathComponent
        verdict = str("verdict") ?? "unknown"
        fileName = str("name")
            ?? str("path").map { ($0 as NSString).lastPathComponent }
            ?? str("title")
            ?? id
        seen = str("first_seen").flatMap(EventSummary.parseDate)
        reportPath = str("report_path")
        allowlisted = (obj["allowlisted"] as? Bool) ?? false
    }

    var hasReport: Bool {
        guard let r = reportPath else { return false }
        return FileManager.default.fileExists(atPath: r)
    }

    private static func parseDate(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: s)
    }
}

enum EventStore {
    static let dir = SentinelPaths.dataDir.appendingPathComponent("events", isDirectory: true)

    /// Event files newest-first (ids start with a YYYYMMDD-HHMMSS stamp, so names sort by time).
    static func files() -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return names.filter { $0.hasSuffix(".json") }
            .sorted(by: >)
            .map { dir.appendingPathComponent($0) }
    }

    static func newest(_ limit: Int) -> [EventSummary] {
        var out: [EventSummary] = []
        for url in files() {
            if let e = EventSummary(url: url) { out.append(e) }
            if out.count >= limit { break }
        }
        return out
    }

    /// True if a non-allowlisted "dangerous" event was first seen in the last 24 hours.
    static func recentDanger(within seconds: TimeInterval = 24 * 3600) -> Bool {
        let cutoff = Date().addingTimeInterval(-seconds)
        for url in files().prefix(500) {
            guard let e = EventSummary(url: url) else { continue }
            guard let seen = e.seen else { continue }
            if seen < cutoff { break }
            if e.verdict == "dangerous" && !e.allowlisted { return true }
        }
        return false
    }
}

enum ShieldState {
    case ok, danger, offline

    var symbolName: String {
        switch self {
        case .ok: return "checkmark.shield"
        case .danger: return "exclamationmark.shield"
        case .offline: return "shield.slash"
        }
    }

    var fallbackTitle: String {
        switch self {
        case .ok: return "🛡✓"
        case .danger: return "🛡!"
        case .offline: return "🛡✕"
        }
    }

    var accessibilityText: String {
        switch self {
        case .ok: return "Sentinel: no recent dangerous events"
        case .danger: return "Sentinel: dangerous event in the last 24 hours"
        case .offline: return "Sentinel: agent not running"
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem?
    private let menu = NSMenu()
    private var eventsWatcher: DispatchSourceFileSystemObject?

    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem = item
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        updateIcon()
        watchEventsFolder()
    }

    // MARK: status

    private func agentRunning() -> Bool {
        AgentStatus.load()?.isAlive ?? false
    }

    private func currentState() -> ShieldState {
        if !agentRunning() { return .offline }
        return EventStore.recentDanger() ? .danger : .ok
    }

    private func statusLine() -> String {
        guard let s = AgentStatus.load(), s.isAlive else {
            return "Agent not running"
        }
        if !s.watching { return "Agent running, paused" }
        let n = s.folders.count
        return "Watching \(n) folder\(n == 1 ? "" : "s")"
    }

    private func updateIcon() {
        guard let button = statusItem?.button else { return }
        let state = currentState()
        if let img = NSImage(systemSymbolName: state.symbolName, accessibilityDescription: state.accessibilityText) {
            img.isTemplate = true
            button.image = img
            button.title = ""
        } else {
            button.image = nil
            button.title = state.fallbackTitle
        }
        button.toolTip = state.accessibilityText
    }

    /// Refreshes the icon when the events folder changes (kernel notification, not polling).
    /// If the folder doesn't exist yet, the icon still refreshes every time the menu opens.
    private func watchEventsFolder() {
        let fd = open(EventStore.dir.path, O_EVTONLY)
        guard fd >= 0 else { return }
        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete], queue: .main)
        src.setEventHandler { [weak self] in self?.updateIcon() }
        src.setCancelHandler { close(fd) }
        src.resume()
        eventsWatcher = src
    }

    // MARK: menu (rebuilt every time it opens)

    func menuNeedsUpdate(_ menu: NSMenu) {
        updateIcon()
        menu.removeAllItems()

        menu.addItem(disabledItem("Sentinel — \(statusLine())"))
        menu.addItem(.separator())

        let events = EventStore.newest(10)
        menu.addItem(disabledItem(events.isEmpty ? "No events yet" : "Recent events"))
        for e in events {
            let when = e.seen.map { dateFormatter.string(from: $0) } ?? "unknown time"
            let item = NSMenuItem(title: "\(e.verdict.uppercased()) · \(e.fileName) · \(when)",
                                  action: nil, keyEquivalent: "")
            if e.hasReport, let r = e.reportPath {
                item.action = #selector(openReport(_:))
                item.target = self
                item.representedObject = r
                item.isEnabled = true
                item.toolTip = r
            } else {
                item.isEnabled = false
                item.toolTip = "No report for this event"
            }
            menu.addItem(item)
        }

        menu.addItem(.separator())
        menu.addItem(actionItem("Open Reports Folder", #selector(openReportsFolder), enabledIfExists: SentinelPaths.reportsDir))
        menu.addItem(actionItem("Open Quarantine", #selector(openQuarantine), enabledIfExists: SentinelPaths.quarantineDir))
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Menu Bar", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        quit.toolTip = "Closes this menu-bar icon only. The Sentinel agent keeps running."
        menu.addItem(quit)
    }

    private func disabledItem(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func actionItem(_ title: String, _ action: Selector, enabledIfExists url: URL) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        let exists = FileManager.default.fileExists(atPath: url.path)
        item.isEnabled = exists
        item.toolTip = exists ? url.path : "\(url.path) doesn't exist yet"
        return item
    }

    // MARK: actions (open with the default app; nothing is modified)

    @objc private func openReport(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    @objc private func openReportsFolder() {
        NSWorkspace.shared.open(SentinelPaths.reportsDir)
    }

    @objc private func openQuarantine() {
        NSWorkspace.shared.open(SentinelPaths.quarantineDir)
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
