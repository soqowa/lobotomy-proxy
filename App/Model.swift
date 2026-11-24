import AppKit
import Foundation
import Security
import SwiftUI
import UniformTypeIdentifiers

struct Settings: Codable, Equatable {
  var kind = "socks5"
  var host = ""
  var port = 3072
  var user = ""
  var password = ""
  var address = ""
  var dnsMode: String?
}
struct DNSObservation: Codable {
  let ip, country_code, city: String
  var label: String { [ip, city, country_code.uppercased()].filter { !$0.isEmpty }.joined(separator: " · ") }
}
extension Settings {
  func observedDNS(requireBerlin: Bool) throws -> [DNSObservation] {
    let output = try Tools.run(Tools.engine, ["dns-check"], input: JSONEncoder().encode(self))
    let results = try JSONDecoder().decode([DNSObservation].self, from: output)
    guard !results.isEmpty else { throw GuardError.message(localized("Net.Coffee didn’t detect a DNS resolver.")) }
    if requireBerlin && !results.allSatisfy({ $0.country_code.lowercased() == "de" && $0.city.lowercased() == "berlin" }) {
      throw GuardError.message(localized("Net.Coffee couldn’t verify Berlin. %@", results.map(\.label).joined(separator: ", ")))
    }
    return results
  }
}
struct Route: Codable, Equatable { let ip, country, zone: String }
struct Event: Codable {
  let state, message: String
  let report: Route?
}
struct SystemState: Codable {
  var installed = false, filter = false, files = false, dns = false
  var needsAdmin = false
  var systemWide = false
  var proxyZone = ""
  var previousZone = ""
  var ownsZone: Bool?
  var installedDigest: String?
  var rulesReady: Bool?
  var clockReady: Bool?
  var ready: Bool?
  var policy: FilterPolicy?
  var legacyFilter = false
  var zone = TimeZone.current.identifier
}

enum GuardError: LocalizedError {
  case message(String)
  var errorDescription: String? {
    switch self {
    case .message(let s): return s
    }
  }
}
enum Vault {
  static let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "local.proxyguard.connection", kSecAttrAccount as String: "primary",
  ]
  static func read() throws -> Settings {
    var q = query
    q[kSecReturnData as String] = true
    var item: CFTypeRef?
    let rc = SecItemCopyMatching(q as CFDictionary, &item)
    if rc == errSecItemNotFound { return Settings() }
    guard rc == errSecSuccess, let data = item as? Data else {
      throw GuardError.message(localized("Keychain is unavailable (%d).", rc))
    }
    return try JSONDecoder().decode(Settings.self, from: data)
  }
  static func save(_ s: Settings) throws {
    let value: [String: Any] = [kSecValueData as String: try JSONEncoder().encode(s)]
    var rc = SecItemUpdate(query as CFDictionary, value as CFDictionary)
    if rc == errSecItemNotFound {
      var q = query.merging(value) { _, v in v }
      q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      rc = SecItemAdd(q as CFDictionary, nil)
    }
    guard rc == errSecSuccess else {
      throw GuardError.message(localized("Keychain rejected the update (%d).", rc))
    }
  }
}
enum Tools {
  static var host: Bundle {
    if Bundle.main.bundleIdentifier == "local.proxyguard.relay-agent" {
      var url = Bundle.main.bundleURL
      for _ in 0..<4 { url.deleteLastPathComponent() }
      if let app = Bundle(url: url), app.bundleIdentifier == "local.proxyguard.app" { return app }
    }
    return Bundle.main
  }
  static func supportsInstalledFilter(_ digest: String?) -> Bool {
    guard let digest, !digest.isEmpty else { return false }
    let compatible = host.object(forInfoDictionaryKey: "LobotomyProxyCompatibleHelperHashes") as? [String] ?? []
    return digest == host.object(forInfoDictionaryKey: "LobotomyProxyHelperSHA256") as? String
      || compatible.contains(digest)
  }
  static var engine: URL {
    host.bundleURL.appendingPathComponent("Contents/Helpers/lobotomy-proxy")
  }
  static func run(_ url: URL, _ args: [String], input: Data? = nil) throws -> Data {
    let p = Process()
    let output = Pipe()
    let source = Pipe()
    p.executableURL = url
    p.arguments = args
    if url == engine {
      var environment = ProcessInfo.processInfo.environment
      environment[AppLanguage.environmentKey] = AppLanguage.current
      p.environment = environment
    }
    p.standardOutput = output
    p.standardError = output
    p.standardInput = source
    try p.run()
    if var data = input {
      data.append(10)
      source.fileHandleForWriting.write(data)
    }
    source.fileHandleForWriting.closeFile()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0 else {
      if let start = data.firstIndex(of: 123), let end = data.lastIndex(of: 125), start <= end,
        let event = try? JSONDecoder().decode(Event.self, from: data[start...end])
      {
        throw GuardError.message(event.message)
      }
      let msg = String(decoding: data.prefix(1200), as: UTF8.self).trimmingCharacters(
        in: .whitespacesAndNewlines)
      throw GuardError.message(
        msg.isEmpty ? localized("The command exited with code %d.", p.terminationStatus) : msg)
    }
    return data
  }
  static func admin(_ args: [String]) throws {
    guard
      let digest = Bundle.main.object(forInfoDictionaryKey: "LobotomyProxyHelperSHA256") as? String,
      digest.count == 64, digest.allSatisfy({ $0.isHexDigit })
    else { throw GuardError.message(localized("The service checksum is missing from this build.")) }
    let stage = #"""
      set -eu
      umask 077
      stage=$(/usr/bin/mktemp -d /private/var/tmp/local.proxyguard.XXXXXX)
      trap '/bin/unlink "$stage/helper" 2>/dev/null || true; /bin/rmdir "$stage" 2>/dev/null || true' EXIT
      /bin/cp "$1" "$stage/helper"
      actual=$(/usr/bin/shasum -a 256 "$stage/helper")
      test "${actual%% *}" = "$2"
      /usr/bin/codesign --verify --strict "$stage/helper"
      /bin/chmod 0700 "$stage/helper"
      export LOBOTOMY_PROXY_LANGUAGE="$3"
      shift 3
      "$stage/helper" "$@"
      """#
    let script = """
      on run argv
        set cmd to "/bin/sh -c " & quoted form of item 1 of argv & " proxyguard"
        repeat with i from 2 to count of argv
          set cmd to cmd & " " & quoted form of item i of argv
        end repeat
        return do shell script cmd with administrator privileges
      end run
      """
    _ = try run(
      URL(fileURLWithPath: "/usr/bin/osascript"), ["-e", script, stage, engine.path, digest, AppLanguage.current] + args)
  }
}
enum Page: String, CaseIterable, Identifiable {
  case overview, connection, filter
  var title: String {
    switch self {
    case .overview: localized("Overview")
    case .connection: localized("Connection")
    case .filter: localized("Filter")
    }
  }
  var id: Self { self }
  var icon: String {
    switch self {
    case .overview: "shield.lefthalf.filled"
    case .connection: "point.3.connected.trianglepath.dotted"
    case .filter: "slider.horizontal.3"
    }
  }
}

@MainActor final class Control: ObservableObject {
  @Published var page: Page = .overview
  @Published var settings = Settings() {
    didSet {
      if oldValue != settings {
        dnsObservations = []
        probeFailed = ""
        route = nil
        if active { stop() }
      }
    }
  }
  @Published var dnsObservations: [DNSObservation] = []
  @Published var route: Route?
  @Published var system = SystemState()
  @Published var browserRules = false
  @Published var phase = "idle"
  @Published var notice = ""
  @Published var busy = false
  @Published private(set) var isTestingProxy = false
  @Published var profileReport = ProfileReport(condition: .unknown)
  @Published var draft = FilterPolicy()
  @Published var draftLoaded = false
  @Published var inspected = false
  @Published var issuesForApps: [String] = []
  @Published var probeFailed = ""
  private static let draftKey = "FilterDraftWithPresets"
  @Published private var selections: [String: DomainSelection] = [:]
  var selection: DomainSelection {
    if let saved = selections[""], saved.domains == draft.domains.sorted() { return saved }
    return DomainSelection(draft.domains)
  }
  func updateSelection(_ mutation: (inout DomainSelection) throws -> Void) throws {
    var next = selection
    try mutation(&next)
    draft.domains = try FilterPolicy(domains: next.domains).normalized().domains
    selections[""] = next
    edited()
  }
  func removeApp(_ id: String) {
    draft.applications.removeAll { $0.id == id }
    selections.removeValue(forKey: id)
    edited()
  }
  func edited() {
    draftLoaded = true
    if let d = try? JSONEncoder().encode(SavedFilterDraft(policy: draft, selections: selections)) {
      UserDefaults.standard.set(d, forKey: Self.draftKey)
    }
  }
  func addApp(_ app: ManagedApp) {
    if !draft.applications.contains(where: { $0.id == app.id }) {
      draft.applications.append(.init(id: app.id, all: true, domains: []))
      edited()
    }
  }
  func chooseFilterApp() {
    let panel = NSOpenPanel()
    panel.allowedContentTypes = [.applicationBundle]
    panel.directoryURL = URL(fileURLWithPath: "/Applications")
    panel.prompt = localized("Add")
    guard panel.runModal() == .OK, let url = panel.url else { return }
    guard let id = Bundle(url: url)?.bundleIdentifier,
      let app = FilterCatalog.shared.apps.first(where: { $0.id == id })
    else {
      notice =
        localized("This app has no supported managed proxy setting. Its traffic still follows the shared domain rules.")
      return
    }
    addApp(app)
  }
  @Published private(set) var active = false
  @Published var relayMessage = ""
  private var timer: Timer?
  private var refreshing = false

  init() {
    do { settings = try Vault.read() } catch { notice = error.localizedDescription }
    if let data = UserDefaults.standard.data(forKey: Self.draftKey),
      let saved = try? JSONDecoder().decode(SavedFilterDraft.self, from: data)
    {
      draft = saved.policy
      selections = saved.selections.filter { $0.key.isEmpty }
      draftLoaded = true
    } else if let d = UserDefaults.standard.data(forKey: "FilterDraftV3"),
      let saved = try? JSONDecoder().decode(FilterPolicy.self, from: d)
    {
      draft = saved
      draftLoaded = true
    }
    draft = draft.fullApplications
    do { try BackgroundRelay.refreshInstalledJob() } catch { notice = error.localizedDescription }
    refresh()
    let poll = Timer(timeInterval: 4, repeats: true) { [weak self] _ in
      Task { @MainActor in self?.refresh() }
    }
    timer = poll
    RunLoop.main.add(poll, forMode: .common)
  }
  func refresh() {
    guard !refreshing, !busy else { return }
    refreshing = true
    Task {
      let (result, profile, enabled, event) = await Task.detached {
        let state = try? JSONDecoder().decode(
          SystemState.self, from: Tools.run(Tools.engine, ["system"]))
        return (
          state, Profile.report(state?.policy), (try? BackgroundRelay.owned()) == true,
          BackgroundRelay.snapshot()
        )
      }.value
      guard !busy else {
        refreshing = false
        return
      }
      profileReport = profile
      system = result ?? SystemState()
      if let result, !draftLoaded, !result.needsAdmin {
        draft = result.policy ?? FilterPolicy()
        draft.domains.removeAll { $0 == FilterPolicy.diagnosticDomain }
        if result.legacyFilter {
          draft.applications = Profile.legacyApps(domains: draft.domains, report: profileReport)
          let migrated = DomainSelection(
            draft.domains, migratePresets: FilterCatalog.shared.presets)
          selections[""] = migrated

        }
        draft = draft.fullApplications
        draftLoaded = true
      }
      inspected = result != nil
      browserRules = !system.legacyFilter && profile.condition == .current
      active = enabled
      phase =
        enabled && browserRules && system.filter && system.files && system.dns
        ? (event?.state ?? "blocked") : "blocked"
      relayMessage = enabled ? event?.message ?? localized("Waiting for the background service.") : ""
      if phase == "passing", let r = event?.report { route = r }
      if enabled, Tools.supportsInstalledFilter(system.installedDigest), browserRules,
        let p = system.policy
      {
        issuesForApps = p.applications.compactMap { rule in
          guard !NSRunningApplication.runningApplications(withBundleIdentifier: rule.id).isEmpty,
            !ZoneLaunch.ready(rule.id, system.proxyZone)
          else { return nil }
          return FilterCatalog.shared.apps.first { $0.id == rule.id }?.name
        }
      } else {
        issuesForApps = []
      }
      refreshing = false
    }
  }
  var status: String {
    if !inspected { return localized("Checking settings") }
    if system.installed, !Tools.supportsInstalledFilter(system.installedDigest) {
      return localized("An older filter is installed")
    }
    if phase == "passing" {
      return issuesForApps.isEmpty ? localized("Forwarding active") : localized("Some apps are waiting to start")
    }
    if phase == "checking" { return localized("Checking route") }
    if system.legacyFilter { return localized("Apply the filter") }
    if system.needsAdmin { return localized("Installation needs attention") }
    if system.installed && !system.filter { return localized("System service unavailable") }
    if system.installed {
      return phase == "blocked" || !active ? localized("Forwarding blocked") : localized("Waiting for verification")
    }
    return localized("Rules aren’t installed")
  }
  var menuShield: (symbol: String, title: String, detail: String?) {
    if busy || !inspected { return ("shield", localized("Checking settings"), nil) }
    if !active {
      return ("shield.slash", localized("Forwarding off"), system.installed ? nil : localized("Rules aren’t installed"))
    }
    if phase == "checking" { return ("shield", status, nil) }
    if phase == "passing", system.installed, Tools.supportsInstalledFilter(system.installedDigest) {
      if issuesForApps.isEmpty { return ("checkmark.shield.fill", status, nil) }
      return ("exclamationmark.shield", status, issuesForApps.joined(separator: ", "))
    }
    return ("xmark.shield", localized("Route unverified"), issues.first?.detail ?? relayMessage)
  }
  var updateNeeded: Bool {
    guard draftLoaded else { return false }
    return !system.installed || system.legacyFilter
      || !Tools.supportsInstalledFilter(system.installedDigest)
      || (route != nil && route?.zone != system.proxyZone) || system.policy != draft.systemRules
      || !system.filter || !(system.rulesReady ?? system.files) || !system.dns
      || [.missing, .previous, .changed, .unknown].contains(profileReport.condition)
  }
  var diagnosticRuleInstalled: Bool {
    system.policy?.domains.contains(FilterPolicy.diagnosticDomain) == true && browserRules && system.dns && system.files && system.filter
  }
  var defaultManagedBrowser: URL? {
    guard let url = NSWorkspace.shared.urlForApplication(toOpen: URL(string: "https://ip.net.coffee/dns/")!),
      let id = Bundle(url: url)?.bundleIdentifier,
      FilterCatalog.shared.apps.contains(where: { $0.id == id && $0.adapter != "desktop" })
    else { return nil }
    return url
  }
  func openDNSPage() {
    guard !busy, phase == "passing", diagnosticRuleInstalled, let url = defaultManagedBrowser else { return }
    Task {
      do {
        _ = try await NSWorkspace.shared.open([URL(string: "https://ip.net.coffee/dns/")!],
          withApplicationAt: url, configuration: NSWorkspace.OpenConfiguration())
      } catch { notice = error.localizedDescription }
    }
  }
  var diagnosticsBrowsers: [ManagedApp] {
    FilterCatalog.shared.apps.filter { a in
      a.adapter != "desktop" && system.policy?.applications.contains { $0.id == a.id } == true
        && NSWorkspace.shared.urlForApplication(withBundleIdentifier: a.id) != nil
    }
  }
  struct Issue: Identifiable {
    let title: String, detail: String
    let page: Page
    var id: String { title }
  }
  var issues: [Issue] {
    var items: [Issue] = []
    if settings.host.isEmpty {
      items.append(
        .init(
          title: localized("Set up your proxy"), detail: localized("Enter the proxy address and connection details."), page: .connection)
      )
    } else if !probeFailed.isEmpty {
      items.append(
        .init(title: localized("Proxy check failed"), detail: probeFailed, page: .connection))
    }
    if !inspected {
      items.append(
        .init(
          title: localized("Checking Mac settings"), detail: localized("Reading the system service status."),
          page: .filter))
      return items
    }
    if !system.installed || system.legacyFilter
      || !Tools.supportsInstalledFilter(system.installedDigest)
    {
      items.append(
        .init(
          title: system.installed ? localized("Update the system filter") : localized("Install the filter"),
          detail: localized("Open Filter and update the profile."), page: .filter))
    } else if !(system.rulesReady ?? system.files) || !system.filter || !system.dns {
      let missing = [
        !system.filter ? localized("system service") : nil, !(system.rulesReady ?? system.files) ? localized("rule files") : nil,
        !system.dns ? localized("local DNS") : nil,
      ].compactMap { $0 }.joined(separator: ", ")
      items.append(
        .init(title: localized("Route unverified"), detail: localized("Check the following: %@.", missing), page: .filter)
      )
    }
    if system.clockReady == false {
      items.append(.init(title: localized("The system time zone changed to %@", system.zone),
        detail: localized("Open Connection to reapply the proxy time zone or restore the Mac’s previous setting."), page: .connection))
    }
    if system.installed && system.policy?.domains.contains(FilterPolicy.diagnosticDomain) != true {
      items.append(.init(title: localized("Browser DNS test is outside the filter"),
        detail: localized("Update the profile to route Net.Coffee and its test subdomains through the proxy."), page: .filter))
    }
    if profileReport.condition != .current {
      items.append(
        .init(
          title: profileReport.detail,
          detail: profileReport.condition == .pending
            ? localized("Restart the listed apps. You can reload their settings in Filter.")
            : localized("Open Filter to install the profile."), page: .filter))
    }
    if !issuesForApps.isEmpty {
      items.append(
        .init(
          title: localized("Apps are waiting for the time zone"),
          detail:
            localized("Save your documents and confirm if an app asks to quit. %@", issuesForApps.joined(separator: ", ")), page: .filter))
    }
    if system.installed && !active {
      items.append(
        .init(
          title: localized("Background forwarding is off"),
          detail: localized("Once setup is complete, turn on forwarding here."), page: .overview))
    } else if active && phase != "passing" && items.isEmpty {
      items.append(
        .init(
          title: phase == "checking" ? localized("Checking the proxy exit") : localized("Forwarding is waiting for verification"),
          detail: relayMessage.isEmpty ? localized("Waiting for the proxy check.") : relayMessage,
          page: .connection))
    }
    return items
  }
  private func checkedRoute(checkDNS: Bool = false) async throws -> Route {
    let config = settings
    let (verified, dns) = try await Task.detached {
      let data = try Tools.run(Tools.engine, ["probe"], input: JSONEncoder().encode(config))
      guard let report = try JSONDecoder().decode(Event.self, from: data).report else {
        throw GuardError.message(localized("Couldn’t verify the proxy exit."))
      }
      let observations = checkDNS ? try config.observedDNS(requireBerlin: config.dnsMode == "berlin") : []
      return (report, observations)
    }.value
    guard config == settings else {
      throw GuardError.message(localized("Proxy settings changed. Run the check again."))
    }
    if checkDNS { dnsObservations = dns }
    let previous = try Vault.read()
    try Vault.save(config)
    if previous != config, try BackgroundRelay.owned(), BackgroundRelay.loaded() {
      _ = try Tools.run(BackgroundRelay.ctl, ["kickstart", "-k", BackgroundRelay.domain + "/" + BackgroundRelay.label])
    }
    probeFailed = ""
    route = verified
    return verified
  }
  func test() {
    guard !busy else { return }
    busy = true
    isTestingProxy = true
    route = nil
    dnsObservations = []
    notice = localized("Checking the exit IP and DNS through the proxy…")
    Task {
      defer {
        isTestingProxy = false
        busy = false
      }
      do {
        _ = try await checkedRoute(checkDNS: true)
        notice = localized("Exit IP and DNS verified.")
      } catch {
        probeFailed = error.localizedDescription
        notice = probeFailed
      }
    }
  }
  func updateProfile() {
    guard !busy, draftLoaded else { return }
    let desired: FilterPolicy
    do { desired = try draft.systemRules.normalized() } catch {
      notice = error.localizedDescription
      return
    }
    busy = true
    notice = localized("Preparing the profile…")
    Task {
      defer {
        busy = false
        refresh()
      }
      do {
        let r = try await checkedRoute()
        if system.policy != desired || !Tools.supportsInstalledFilter(system.installedDigest)
          || !system.filter
          || !(system.rulesReady ?? system.files) || !system.dns || system.proxyZone != r.zone
        {
          try await Task.detached {
            try Tools.admin([
              "install", String(getuid()), r.zone, "keep",
              String(decoding: try desired.json(), as: UTF8.self),
            ])
          }.value
        }
        let state = try await Task.detached {
          try JSONDecoder().decode(SystemState.self, from: Tools.run(Tools.engine, ["system"]))
        }.value
        guard state.installed, state.policy == desired, state.filter, state.rulesReady ?? state.files else {
          throw GuardError.message(localized("macOS hasn’t confirmed the system rules yet."))
        }
        system = state
        let report = await Task.detached { Profile.report(desired) }.value
        profileReport = report
        try BackgroundRelay.enable()
        active = true
        if report.condition == .current {
          try Profile.openSettings()
          notice = localized("Filter updated and profile verified.")
        } else {
          try Profile.open(desired)
          notice =
            localized("Confirm installation in Device Management. The filter will start automatically.")
        }
      } catch { notice = error.localizedDescription }
    }
  }
  func applySystemZone() {
    guard !busy else { return }
    busy = true
    Task {
      defer {
        busy = false
        refresh()
      }
      do {
        let r = try await checkedRoute()
        try await Task.detached { try Tools.admin(["set-zone", String(getuid()), r.zone]) }.value
        notice = localized("Mac time zone set to %@.", r.zone)
      } catch { notice = error.localizedDescription }
    }
  }
  func openDiagnostics(_ app: ManagedApp) {
    guard !busy, phase == "passing", browserRules,
      let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.id)
    else { return }
    busy = true
    Task {
      defer {
        busy = false
        refresh()
      }
      do {
        if NSRunningApplication.runningApplications(withBundleIdentifier: app.id).isEmpty {
          _ = try await NSWorkspace.shared.openApplication(
            at: url, configuration: NSWorkspace.OpenConfiguration())
        }
        let limit = ContinuousClock.now.advanced(by: .seconds(35))
        while !ZoneLaunch.ready(app.id, system.proxyZone) && ContinuousClock.now < limit {
          try await Task.sleep(for: .milliseconds(200))
        }
        guard ZoneLaunch.ready(app.id, system.proxyZone) else {
          throw GuardError.message(
            localized("The browser time zone hasn’t been verified. Quit the app and run the check again."))
        }
        _ = try await NSWorkspace.shared.open(
          [URL(string: "https://ip.net.coffee/claude/")!], withApplicationAt: url,
          configuration: NSWorkspace.OpenConfiguration())
      } catch { notice = error.localizedDescription }
    }
  }
  func restoreZone() {
    guard !busy else { return }
    busy = true
    Task {
      do {
        try await Task.detached { try Tools.admin(["restore-zone", String(getuid())]) }.value
        let status = try await Task.detached {
          try JSONDecoder().decode(SystemState.self, from: Tools.run(Tools.engine, ["system"]))
        }.value
        system = status
        notice = localized("Current Mac time zone: %@.", status.zone)
      } catch { notice = error.localizedDescription }
      busy = false
      refresh()
    }
  }
  func refreshManagedPreferences() {
    guard !busy else { return }
    busy = true
    Task {
      defer {
        busy = false
        refresh()
      }
      do {
        try await Task.detached { try Tools.admin(["refresh-preferences", String(getuid())]) }.value
        notice =
          localized("macOS settings reloaded. Quit and reopen the apps listed in the profile status.")
      } catch { notice = error.localizedDescription }
    }
  }
  func rollback() {
    guard !busy else { return }
    busy = true
    Task {
      do {
        try BackgroundRelay.disable()
        active = false
        if system.installed {
          try await Task.detached { try Tools.admin(["rollback-filter"]) }.value
        }
        try await Task.detached { try Profile.remove() }.value
        notice = localized("Rollback complete. Restart the selected apps.")
      } catch { notice = error.localizedDescription }
      busy = false
      refresh()
    }
  }
  func stop() {
    do {
      try BackgroundRelay.disable()
      active = false
      phase = "blocked"
      relayMessage = ""
    } catch { notice = error.localizedDescription }
  }
  func start() {
    guard !busy, system.installed, !system.legacyFilter else { return }
    do {
      try Vault.save(settings)
      try BackgroundRelay.enable()
      active = true
      phase = "checking"
      refresh()
    } catch { notice = error.localizedDescription }
  }
}
