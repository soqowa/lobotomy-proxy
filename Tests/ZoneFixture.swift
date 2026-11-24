import AppKit

@main struct ZoneFixture {
  @MainActor static func main() async throws {
    let child = URL(fileURLWithPath: CommandLine.arguments[1])
    let dir = child.deletingLastPathComponent()
    let id = Bundle(url: child)!.bundleIdentifier!
    let target = "Pacific/Honolulu"
    let adapter = CommandLine.arguments[2]
    guard FilterCatalog.shared.apps.first?.adapter == adapter else {
      throw GuardError.message("fixture catalog missing")
    }
    let expectedSwitches = adapter == "desktop" ? [] : [
      "--proxy-server=http://127.0.0.1:17747", "--proxy-bypass-list=<-loopback>",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost", "--disable-quic",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ]
    ZoneLaunch.file = dir.appendingPathComponent("receipts.json")
    _ = NSApplication.shared
    let app = try await NSWorkspace.shared.openApplication(
      at: child, configuration: NSWorkspace.OpenConfiguration())
    defer {
      for p in NSRunningApplication.runningApplications(withBundleIdentifier: id) {
        _ = p.terminate()
      }
    }
    guard !ZoneLaunch.permits(id, target) else {
      throw GuardError.message("unprepared process admitted")
    }
    let end = ContinuousClock.now.advanced(by: .seconds(35))
    let record = dir.appendingPathComponent("result")
    var allowed = false
    while ContinuousClock.now < end {
      ZoneLaunch.configure([id], target)
      if ZoneLaunch.permits(id, target),
        let data = try? Data(contentsOf: record),
        let seen = try? JSONDecoder().decode([String: [String]].self, from: data),
        seen["zone"] == [target], seen["switches"] == expectedSwitches
      {
        allowed = true
        break
      }
      try await Task.sleep(for: .milliseconds(150))
    }
    guard allowed, app.isTerminated else {
      throw GuardError.message("ordinary launch did not acquire requested zone")
    }
    ZoneLaunch.configure([], "")
    guard !ZoneLaunch.permits(id, target) else { throw GuardError.message("removed app admitted") }
    print("PASS", adapter, "ordinary launch, process TZ, launch switches, admission and removal")
  }
}
