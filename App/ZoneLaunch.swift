import AppKit
import Foundation

// Only launches completed by this controller receive a receipt. A PID alone can be reused.
@MainActor enum ZoneLaunch {
  struct Receipt: Codable, Equatable {
    let pid: Int32
    let date: Date
    let zone: String
    func matches(_ app: NSRunningApplication, _ target: String) -> Bool {
      app.processIdentifier == pid && app.launchDate == date && zone == target
    }
  }
  static var file = BackgroundRelay.folder.appendingPathComponent("ApplicationZones.json")
  private static var selected = Set<String>()
  private static var target = ""
  private static var tasks = Set<String>()
  private static var attempted: [String: Receipt] = [:]
  private static var observer: NSObjectProtocol?

  static func receipts() -> [String: Receipt] {
    guard let data = try? Data(contentsOf: file) else { return [:] }
    return (try? JSONDecoder().decode([String: Receipt].self, from: data)) ?? [:]
  }
  static func ready(_ id: String, _ zone: String) -> Bool {
    let running = NSRunningApplication.runningApplications(withBundleIdentifier: id)
    guard let record = receipts()[id], !running.isEmpty else { return false }
    return running.allSatisfy { record.matches($0, zone) }
  }
  static func permits(_ id: String, _ zone: String) -> Bool {
    selected.contains(id) && target == zone && ready(id, zone)
  }
  static func configure(_ ids: Set<String>, _ zone: String) {
    selected = ids
    target = zone
    if observer == nil {
      observer = NSWorkspace.shared.notificationCenter.addObserver(
        forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main
      ) { _ in
        Task { @MainActor in reconcile() }
      }
    }
    reconcile()
  }
  private static func reconcile() {
    for id in selected where !tasks.contains(id) {
      let running = NSRunningApplication.runningApplications(withBundleIdentifier: id)
      guard running.count == 1, let app = running.first, app.isFinishedLaunching,
        let url = app.bundleURL, let date = app.launchDate,
        let zone = TimeZone(identifier: target)?.identifier,
        !ready(id, zone)
      else { continue }
      let attempt = Receipt(pid: app.processIdentifier, date: date, zone: zone)
      guard attempted[id] != attempt else { continue }
      tasks.insert(id)
      attempted[id] = attempt
      Task { @MainActor in
        defer { tasks.remove(id) }
        guard selected.contains(id), target == zone else { return }
        let wasActive = app.isActive
        guard app.terminate() else { return }
        let end = ContinuousClock.now.advanced(by: .seconds(30))
        while !app.isTerminated && ContinuousClock.now < end {
          try? await Task.sleep(for: .milliseconds(120))
        }
        guard app.isTerminated, selected.contains(id), target == zone,
          NSRunningApplication.runningApplications(withBundleIdentifier: id).isEmpty
        else { return }
        let config = NSWorkspace.OpenConfiguration()
        config.environment = ["TZ": zone]
        // The desktop adapter reads egressProxyUrl from the managed profile and rejects network switches.
        if let app = FilterCatalog.shared.apps.first(where: { $0.id == id }),
          app.adapter == "chromium"
        {
          config.arguments = [
            "--proxy-server=http://127.0.0.1:" + String(app.port),
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost", "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
          ]
        }
        config.activates = wasActive
        config.createsNewApplicationInstance = true
        guard
          let opened = try? await NSWorkspace.shared.openApplication(
            at: url, configuration: config),
          opened.bundleIdentifier == id, let started = opened.launchDate
        else { return }
        let launch = Receipt(pid: opened.processIdentifier, date: started, zone: zone)
        attempted[id] = launch
        var records = receipts()
        records[id] = launch
        if let data = try? JSONEncoder().encode(records) {
          try? data.write(to: file, options: .atomic)
        }
      }
    }
  }
}
