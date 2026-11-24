import AppKit

@main struct ZoneFixture {
  @MainActor static func main() async throws {
    let child = URL(fileURLWithPath: CommandLine.arguments[1])
    let dir = child.deletingLastPathComponent()
    let id = Bundle(url: child)!.bundleIdentifier!
    let target = "Pacific/Honolulu"
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
        let seen = try? String(contentsOf: record, encoding: .utf8), seen == target
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
    print("PASS ordinary macOS launch, initial denial, new process TZ, admission and removal")
  }
}
