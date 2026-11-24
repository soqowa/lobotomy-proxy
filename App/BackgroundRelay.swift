import AppKit
import Foundation

// launchd owns the relay between ordinary launches and across logins. The GUI only controls its job.
enum BackgroundRelay {
  static let label = "local.proxyguard.relay"
  static let domain = "gui/" + String(getuid())
  static let ctl = URL(fileURLWithPath: "/bin/launchctl")
  static let plist = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
    "Library/LaunchAgents/" + label + ".plist")
  static let folder: URL = {
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    let previous = support.appendingPathComponent("Proxy Guard", isDirectory: true)
    // Reuse launch receipts and profile exports from existing installations.
    return FileManager.default.fileExists(atPath: previous.path)
      ? previous : support.appendingPathComponent("Lobotomy Proxy", isDirectory: true)
  }()
  static let statusURL = folder.appendingPathComponent("RelayStatus.json")
  struct Snapshot: Codable {
    let event: Event
    let at: Date
    var build: String?
  }

  private static let relayPath = "Contents/Library/LoginItems/Lobotomy Proxy Relay.app/Contents/MacOS/LobotomyProxyRelay"
  static func jobHost(_ arguments: [String]) -> URL? {
    guard arguments.count == 2, arguments[1] == "--background-relay",
      arguments[0].hasPrefix("/") else { return nil }
    let suffixes = [
      "/" + relayPath, "/Contents/MacOS/ProxyGuard",
      "/Contents/Library/LoginItems/Proxy Guard Relay.app/Contents/MacOS/ProxyGuardRelay",
    ]
    guard let suffix = suffixes.first(where: { arguments[0].hasSuffix($0) }) else { return nil }
    let host = URL(fileURLWithPath: String(arguments[0].dropLast(suffix.count)), isDirectory: true)
    return host.pathExtension == "app" ? host.standardizedFileURL : nil
  }
  static func owned() throws -> Bool {
    guard FileManager.default.fileExists(atPath: plist.path) else { return false }
    let data = try Data(contentsOf: plist)
    guard
      let spec = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        as? [String: Any],
      spec["Label"] as? String == label, let args = spec["ProgramArguments"] as? [String],
      jobHost(args) != nil
    else { throw GuardError.message("Файл фоновой службы занят другой настройкой.") }
    return true
  }
  static func loaded() -> Bool {
    (try? Tools.run(ctl, ["print", domain + "/" + label])) != nil
  }
  static func disable() throws {
    let exists = try owned()
    if loaded() {
      guard exists else {
        throw GuardError.message("Найден одноимённый фоновый процесс без файла Lobotomy Proxy.")
      }
      _ = try Tools.run(ctl, ["bootout", domain + "/" + label])
    }
    if exists { try FileManager.default.removeItem(at: plist) }
    try? FileManager.default.removeItem(at: statusURL)
  }
  private static var executable: URL {
    Tools.host.bundleURL.appendingPathComponent(relayPath)
  }
  static func refreshInstalledJob() throws {
    guard try owned(),
      let spec = try PropertyListSerialization.propertyList(
        from: Data(contentsOf: plist), options: [], format: nil) as? [String: Any],
      let args = spec["ProgramArguments"] as? [String],
      let registered = jobHost(args)
    else { return }
    let host = Tools.host.bundleURL.standardizedFileURL
    let previous = host.deletingLastPathComponent().appendingPathComponent("Proxy Guard.app", isDirectory: true)
    guard registered == host || registered == previous || !FileManager.default.fileExists(atPath: args[0])
    else { return }
    let environment = spec["EnvironmentVariables"] as? [String: String]
    if args[0] != executable.path || environment?["PROXYGUARD_RELAY_BUILD"] != buildID || !loaded() {
      try enable()
    }
  }
  static func enable() throws {
    let exe = executable
    guard FileManager.default.isExecutableFile(atPath: exe.path) else {
      throw GuardError.message("Фоновая служба отсутствует в сборке.")
    }
    let spec: [String: Any] = [
      "Label": label, "ProgramArguments": [exe.path, "--background-relay"],
      "EnvironmentVariables": ["PROXYGUARD_RELAY_BUILD": buildID],
      "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 5, "ProcessType": "Background",
    ]
    let data = try PropertyListSerialization.data(fromPropertyList: spec, format: .xml, options: 0)
    try FileManager.default.createDirectory(
      at: plist.deletingLastPathComponent(), withIntermediateDirectories: true)
    let exists = try owned()
    let previous = exists ? try Data(contentsOf: plist) : nil
    let running = loaded()
    if running && !exists {
      throw GuardError.message("Найден одноимённый фоновый процесс без файла Lobotomy Proxy.")
    }
    if let previous, previous != data {
      // Keep a valid job on disk throughout the upgrade, including across a logout.
      try data.write(to: plist, options: .atomic)
      do {
        if running { _ = try Tools.run(ctl, ["bootout", domain + "/" + label]) }
        _ = try Tools.run(ctl, ["bootstrap", domain, plist.path])
      } catch {
        try previous.write(to: plist, options: .atomic)
        if running && !loaded() { _ = try Tools.run(ctl, ["bootstrap", domain, plist.path]) }
        throw error
      }
      return
    }
    if !exists {
      try data.write(to: plist, options: .withoutOverwriting)
    }
    if !running {
      _ = try Tools.run(ctl, ["bootstrap", domain, plist.path])
    } else if snapshot() == nil {
      _ = try Tools.run(ctl, ["kickstart", "-k", domain + "/" + label])
    }
  }
  static var buildID: String {
    Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
  }
  static func snapshot() -> Event? {
    guard let data = try? Data(contentsOf: statusURL),
      let s = try? JSONDecoder().decode(Snapshot.self, from: data),
      s.build == buildID, (0..<12).contains(Date().timeIntervalSince(s.at))
    else { return nil }
    return s.event
  }
  private static func publish(_ e: Event) {
    if let d = try? JSONEncoder().encode(Snapshot(event: e, at: Date(), build: buildID)) {
      try? d.write(to: statusURL, options: .atomic)
    }
  }
  private final class Worker {
    let process = Process()
    let source = Pipe()
    let output = Pipe()
    let lock = NSLock()
    var event = Event(state: "checking", message: "Проверяем маршрут.", report: nil)
    init(zone: String) throws {
      process.executableURL = Tools.host.executableURL
      process.arguments = ["--relay-worker"]
      process.standardInput = source
      process.standardOutput = output
      process.standardError = FileHandle.nullDevice
      try process.run()
      Task.detached { [weak self, output] in
        do {
          for try await line in output.fileHandleForReading.bytes.lines {
            struct Request: Decodable {
              let zoneRequest: UInt64
              let app: String
            }
            struct Reply: Encodable {
              let zoneRequest: UInt64
              let ok: Bool
            }
            if let q = try? JSONDecoder().decode(Request.self, from: Data(line.utf8)) {
              let allowed = await ZoneLaunch.permits(q.app, zone)
              let reply =
                try JSONEncoder().encode(Reply(zoneRequest: q.zoneRequest, ok: allowed))
                + Data([10])
              try self?.source.fileHandleForWriting.write(contentsOf: reply)
            } else if let e = try? JSONDecoder().decode(Event.self, from: Data(line.utf8)) {
              self?.update(e)
            }
          }
        } catch {}
      }
    }
    func update(_ e: Event) { lock.withLock { event = e } }
    var latest: Event { lock.withLock { event } }
    func stop() {
      try? source.fileHandleForWriting.close()
      if process.isRunning { process.terminate() }
      process.waitUntilExit()
    }
  }
  // The existing GUI signature owns the Keychain item. Hand it straight to the Go
  // worker over an anonymous descriptor, then replace this process with that worker.
  static func execWorker() throws -> Never {
    let value = try JSONEncoder().encode(Vault.read())
    guard value.count < 4096 else { throw GuardError.message("Слишком длинные параметры прокси.") }
    var fds: [Int32] = [-1, -1]
    guard pipe(&fds) == 0 else { throw GuardError.message("Канал передачи недоступен.") }
    let output = FileHandle(fileDescriptor: fds[1], closeOnDealloc: false)
    defer { close(fds[0]) }
    try output.write(contentsOf: value)
    try output.close()
    let path = Tools.engine.path
    let argv = [path, "relay-worker", String(fds[0])].map { strdup($0) } + [nil]
    defer { for item in argv { free(item) } }
    _ = argv.withUnsafeBufferPointer { execv(path, $0.baseAddress!) }
    throw GuardError.message("Не удалось запустить обработчик прокси.")
  }
  static func supervise() {
    try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    var worker: Worker?
    var fingerprint: String?
    while true {
      autoreleasepool {
        do {
          let system = try JSONDecoder().decode(
            SystemState.self, from: Tools.run(Tools.engine, ["system"]))
          guard
            Tools.supportsInstalledFilter(system.installedDigest), system.installed,
            system.files, system.dns, system.filter, !system.legacyFilter,
            let policy = system.policy
          else { throw GuardError.message("Системные правила не подтверждены.") }
          let report = Profile.report(policy)
          guard report.condition == .current else { throw GuardError.message(report.detail) }
          let ids = Set(policy.applications.map(\.id))
          DispatchQueue.main.sync { ZoneLaunch.configure(ids, system.proxyZone) }
          let stamp = try Profile.signature(policy) + system.proxyZone
          if let ended = worker, !ended.process.isRunning {
            let last = ended.latest
            publish(
              Event(
                state: "blocked",
                message: last.state == "checking"
                  ? "Обработчик завершился до проверки соединения." : last.message, report: nil))
            ended.stop()
            worker = nil
            return
          }
          if worker == nil || fingerprint != stamp {
            worker?.stop()
            worker = nil
            worker = try Worker(zone: system.proxyZone)
            fingerprint = stamp
          }
          if let worker { publish(worker.latest) }
        } catch {
          DispatchQueue.main.sync { ZoneLaunch.configure([], "") }
          worker?.stop()
          worker = nil
          publish(Event(state: "blocked", message: error.localizedDescription, report: nil))
        }
      }
      Thread.sleep(forTimeInterval: 2)
    }
  }
}
