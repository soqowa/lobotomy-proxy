import AppKit
import SwiftUI

let accent = Color(
  nsColor: NSColor(name: nil) { look in
    look.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
      ? NSColor(srgbRed: 1.0, green: 0.66, blue: 0.80, alpha: 1)
      : NSColor(srgbRed: 0.62, green: 0.16, blue: 0.36, alpha: 1)
  })

struct SidebarStatus: Equatable {
  enum Tone { case idle, working, good, warning }
  var title: String
  var detail: String?
  var tone: Tone
}

/// The brand artwork, inked to match the connection state.
private struct SidebarIllustration: View {
  let tone: SidebarStatus.Tone
  @Environment(\.colorScheme) private var scheme

  private struct Inks { let light: NSImage?, dark: NSImage? }

  private static let source = Bundle.main.url(forResource: BrandArtwork.resource, withExtension: "svg")
  private static func inks(light: (String, String), dark: (String, String)) -> Inks {
    Inks(
      light: source.flatMap { try? BrandArtwork.image(from: $0, ink: light.0, paper: light.1) },
      dark: source.flatMap { try? BrandArtwork.image(from: $0, ink: dark.0, paper: dark.1) })
  }
  private static let active = inks(light: ("#8b405d", "#fff4f7"), dark: ("#4b283a", "#e6b5c8"))
  private static let off = inks(light: ("#8d8790", "#f6f4f6"), dark: ("#2e2b2f", "#8f8a91"))
  private static let alert = inks(light: ("#a8582a", "#fff3ea"), dark: ("#4a2a17", "#eab48a"))

  var body: some View {
    let set: Inks = switch tone {
    case .good, .working: Self.active
    case .idle: Self.off
    case .warning: Self.alert
    }
    if let mark = scheme == .dark ? set.dark : set.light {
      Image(nsImage: mark).resizable().interpolation(.high).scaledToFit()
        .opacity(tone == .idle ? 0.8 : 1)
        .id(tone).transition(.opacity)
        .accessibilityHidden(true).allowsHitTesting(false)
    }
  }
}

private struct SidebarHeader: View {
  let status: SidebarStatus

  private static let version = Bundle.main.object(
    forInfoDictionaryKey: "CFBundleShortVersionString") as? String

  private var statusColor: AnyShapeStyle {
    switch status.tone {
    case .good: AnyShapeStyle(accent)
    case .warning: AnyShapeStyle(.orange)
    case .idle, .working: AnyShapeStyle(.secondary)
    }
  }

  var body: some View {
    VStack(spacing: 12) {
      SidebarIllustration(tone: status.tone)
        .frame(maxWidth: .infinity, maxHeight: 132)
        .padding(.horizontal, 22)
      VStack(spacing: 5) {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
          Text(verbatim: "Lobotomy Proxy").font(.system(size: 14, weight: .bold))
            .lineLimit(1).fixedSize()
          if let version = Self.version {
            Text(verbatim: version).font(.system(size: 11).monospacedDigit())
              .foregroundStyle(.tertiary)
          }
        }
        .accessibilityAddTraits(.isHeader)
        HStack(spacing: 4) {
          Text(status.title).lineLimit(1).truncationMode(.tail)
          if let detail = status.detail, !detail.isEmpty {
            Text(verbatim: "· " + detail).lineLimit(1).fixedSize().foregroundStyle(.tertiary)
          }
        }
        .font(.system(size: 11.5, weight: .medium))
        .foregroundStyle(statusColor)
        .help(status.title)
      }
    }
    .frame(maxWidth: .infinity)
    .accessibilityElement(children: .combine)
  }
}

enum SidebarStyle: String, CaseIterable {
  /// Navigation on top, artwork in the bottom corner.
  case classic
  /// Artwork, name and connection state above the navigation.
  case portrait

  var title: String {
    switch self {
    case .classic: localized("Classic")
    case .portrait: localized("Logo on Top")
    }
  }
}

private struct Sidebar: View {
  @Binding var page: Page
  let status: SidebarStatus
  let style: SidebarStyle
  let motion: InterfaceMotion
  @ScaledMetric(relativeTo: .body) private var width: CGFloat = 210
  @Namespace private var navigation

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      if style == .portrait {
        SidebarHeader(status: status).padding(.bottom, 22)
      }
      ForEach(Page.allCases) { item in
        Button {
          page = item
        } label: {
          HStack(spacing: 11) {
            Image(systemName: item.icon).frame(width: 20).accessibilityHidden(true)
            Text(item.title).lineLimit(1).fixedSize(horizontal: true, vertical: false)
            Spacer(minLength: 0)
          }
          .font(.title3)
          .padding(.horizontal, 12).padding(.vertical, 10)
          .frame(minHeight: 42).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background {
          if page == item {
            RoundedRectangle(cornerRadius: 8).fill(accent.opacity(0.13))
              .matchedGeometryEffect(id: "selection", in: navigation)
              .accessibilityHidden(true).allowsHitTesting(false)
          }
        }
        .foregroundStyle(page == item ? accent : .primary)
        .accessibilityAddTraits(page == item ? .isSelected : [])
      }
      if style == .classic {
        Spacer(minLength: 24)
        SidebarIllustration(tone: .good)
          .frame(maxWidth: .infinity, maxHeight: 150)
          .padding(.horizontal, 10)
      } else {
        Spacer(minLength: 0)
      }
    }
    .animation(motion.animation, value: page)
    .animation(motion.animation, value: status)
    .padding(.horizontal, 12).padding(.top, style == .portrait ? 44 : 40).padding(.bottom, 23)
    .frame(width: width)
    .frame(maxHeight: .infinity)
    .background {
      LinearGradient(stops: [
        .init(color: .clear, location: 0.65),
        .init(color: accent.opacity(0.08), location: 1)
      ], startPoint: .top, endPoint: .bottom)
        .background(.regularMaterial)
    }
  }
}

struct InterfaceMotion {
  let reduced: Bool

  var animation: Animation? { reduced ? nil : .smooth(duration: 0.24) }
  var page: AnyTransition {
    reduced ? .identity : .asymmetric(
      insertion: .opacity.combined(with: .offset(y: 6)), removal: .opacity)
  }
  var item: AnyTransition {
    reduced ? .identity : .opacity.combined(with: .scale(scale: 0.96))
  }
}

private struct ConnectionSignal: View {
  enum State {
    case idle, connecting, verified, failed

    var symbol: String {
      switch self {
      case .idle, .connecting: "shield"
      case .verified: "checkmark.shield.fill"
      case .failed: "xmark.shield"
      }
    }

    var tint: Color {
      switch self {
      case .verified: accent
      case .failed: .orange
      case .idle, .connecting: .secondary
      }
    }
  }

  let state: State
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  var body: some View {
    HStack(spacing: 4) {
      Image(systemName: "laptopcomputer")
      ZStack {
        Capsule().fill(.secondary.opacity(0.25)).frame(height: 2)
        switch state {
        case .connecting:
          if reduceMotion {
            Image(systemName: "ellipsis").font(.caption.bold())
          } else {
            TimelineView(.animation(minimumInterval: 1.0 / 30)) { frame in
              let progress = frame.date.timeIntervalSinceReferenceDate
                .truncatingRemainder(dividingBy: 1.2) / 1.2
              Capsule().fill(accent).frame(width: 8, height: 4)
                .opacity(min(1, min(progress, 1 - progress) * 8))
                .offset(x: CGFloat(progress - 0.5) * 24)
            }
          }
        case .verified:
          Capsule().fill(accent).frame(height: 2)
            .transition(.scale(scale: 0, anchor: .leading))
        case .idle, .failed:
          EmptyView()
        }
      }.frame(width: 32, height: 10)
      Image(systemName: state.symbol).frame(width: 17)
        .foregroundStyle(state.tint)
    }
    .font(.system(size: 14, weight: .medium)).foregroundStyle(.secondary)
    .animation(state == .verified && !reduceMotion ? .smooth(duration: 0.22) : nil, value: state)
    .accessibilityHidden(true)
  }
}

struct Surface<Content: View>: View {
  @ViewBuilder let content: () -> Content
  var body: some View {
    VStack(alignment: .leading, spacing: 16, content: content)
      .frame(maxWidth: .infinity, alignment: .leading).padding(20)
      .background(.background, in: RoundedRectangle(cornerRadius: 14))
      .overlay(RoundedRectangle(cornerRadius: 14).stroke(.primary.opacity(0.085), lineWidth: 1))
  }
}

struct Dashboard: View {
  @ObservedObject var c: Control
  private var signal: ConnectionSignal.State {
    guard c.active else { return .idle }
    switch c.phase {
    case "checking": return .connecting
    case "passing": return .verified
    case "blocked": return .failed
    default: return .idle
    }
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 26) {
      Text(localized("Overview")).font(.largeTitle.bold())
      Surface {
        HStack(spacing: 14) {
          ConnectionSignal(state: signal)
          Text(c.status).font(.title2.weight(.semibold))
          Spacer()
          if c.active {
            Button(localized("Pause")) { c.stop() }.disabled(c.busy)
          } else if c.browserRules && c.system.filter && c.system.files && c.system.dns {
            Button(localized("Enable Forwarding")) { c.start() }.disabled(c.busy)
          }
        }
        if let r = c.route {
          Divider()
          HStack(spacing: 24) {
            metric(localized("Exit IP"), r.ip)
            metric(localized("Country"), r.country)
            metric(localized("Exit time zone"), r.zone)
          }
        }
      }
      if !c.issues.isEmpty {
        VStack(alignment: .leading, spacing: 12) {
          Text(localized("Needs attention")).font(.headline)
          Surface {
            ForEach(Array(c.issues.enumerated()), id: \.element.id) { i, issue in
              if i > 0 { Divider() }
              Button {
                if issue.page == .overview { c.start() } else { c.page = issue.page }
              } label: {
                HStack(spacing: 12) {
                  VStack(alignment: .leading, spacing: 4) {
                    Text(issue.title).fontWeight(.medium)
                    Text(issue.detail).font(.callout).foregroundStyle(.secondary)
                  }
                  Spacer()
                  Image(systemName: "chevron.right").font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                }.contentShape(Rectangle())
              }.buttonStyle(.plain)
            }
          }
        }
      }
      Divider()
      VStack(alignment: .leading, spacing: 9) {
        Text(localized("Leak check")).font(.headline)
        if c.diagnosticsBrowsers.isEmpty {
          if c.defaultManagedBrowser != nil {
            Button(localized("Check DNS in Browser")) { c.openDNSPage() }
              .disabled(c.busy || c.phase != "passing" || !c.diagnosticRuleInstalled)
          } else {
            Text(localized("For the full leak check, select All requests for a supported browser in Filter."))
              .font(.callout).foregroundStyle(.secondary)
          }
        } else if c.diagnosticsBrowsers.count == 1, let browser = c.diagnosticsBrowsers.first {
          Button(localized("Open Net.Coffee in %@", browser.name)) { c.openDiagnostics(browser) }.disabled(
            c.busy || c.phase != "passing" || !c.browserRules)
        } else {
          Menu(localized("Open Net.Coffee")) {
            ForEach(c.diagnosticsBrowsers) { a in Button(a.name) { c.openDiagnostics(a) } }
          }
          .fixedSize().disabled(c.busy || c.phase != "passing" || !c.browserRules)
        }
      }
    }
  }
  func metric(_ label: String, _ value: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(label).font(.caption).foregroundStyle(.secondary)
      Text(value).font(.body.monospacedDigit()).textSelection(.enabled)
    }
  }
}

struct Connection: View {
  @ObservedObject var c: Control
  @State private var extra = false
  @State private var restore = false
  private var probeSignal: ConnectionSignal.State {
    if c.isTestingProxy { return .connecting }
    if !c.probeFailed.isEmpty { return .failed }
    return c.dnsObservations.isEmpty ? .idle : .verified
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 24) {
      Text(localized("Connection")).font(.largeTitle.bold())
      Surface {
        HStack {
          Text(localized("Proxy server")).font(.headline)
          Spacer()
          Picker(localized("Protocol"), selection: $c.settings.kind) {
            Text("SOCKS5").tag("socks5")
            Text("HTTP").tag("http")
            Text("HTTPS").tag("https")
          }.labelsHidden().pickerStyle(.segmented).frame(width: 210)
        }
        HStack(spacing: 14) {
          field(localized("Server")) { TextField("proxy.example.com", text: $c.settings.host) }
          field(localized("Port")) {
            TextField("1080", value: $c.settings.port, format: .number.grouping(.never))
          }.frame(width: 86)
        }
        HStack(spacing: 14) {
          field(localized("Username")) { TextField(localized("Optional"), text: $c.settings.user) }
          field(localized("Password")) { SecureField(localized("Optional"), text: $c.settings.password) }
        }
        Picker(localized("DNS for protected requests"), selection: Binding(
          get: { c.settings.dnsMode ?? "upstream" }, set: { c.settings.dnsMode = $0 }
        )) {
          Text(localized("Proxy resolver")).tag("upstream")
          Text(localized("Berlin · CryptoStorm")).tag("berlin")
        }
        if !c.dnsObservations.isEmpty {
          LabeledContent(localized("DNS reported by Net.Coffee"),
            value: c.dnsObservations.map(\.label).joined(separator: "\n"))
            .font(.callout).textSelection(.enabled)
        }
        DisclosureGroup(localized("Connect by IP without a DNS lookup"), isExpanded: $extra) {
          TextField(localized("Numeric server IP"), text: $c.settings.address).padding(.top, 6)
        }.font(.callout).foregroundStyle(.secondary)
        HStack(spacing: 14) {
          Button(localized("Test and Save")) { c.test() }.buttonStyle(.borderedProminent).disabled(
            c.busy || c.settings.host.isEmpty)
          ConnectionSignal(state: probeSignal)
        }
      }.textFieldStyle(.roundedBorder)
      Text(localized("Time zone")).font(.title3.weight(.semibold))
      Surface {
        LabeledContent(localized("On this Mac"), value: c.system.zone).monospacedDigit()
        LabeledContent(
          localized("At the proxy exit"),
          value: c.route?.zone
            ?? (c.system.proxyZone.isEmpty ? localized("Not verified yet") : c.system.proxyZone)
        ).monospacedDigit()
        Divider()
        Text(
          localized("Filtered apps use the proxy time zone at launch. You can also apply it to your entire Mac.")
        ).font(.callout).foregroundStyle(.secondary)
        HStack {
          Button(localized("Apply to Mac")) { c.applySystemZone() }.disabled(
            c.busy || c.settings.host.isEmpty)
          Spacer()
          Button(localized("Restore Time Zone…")) { restore = true }.buttonStyle(.link).disabled(
            c.busy || !(c.system.ownsZone ?? c.system.systemWide))
        }
      }
    }.alert(localized("Restore the Mac’s time zone?"), isPresented: $restore) {
      Button(localized("Cancel"), role: .cancel) {}
      Button(localized("Roll Back")) { c.restoreZone() }
    } message: {
      Text(localized("The app will restore the saved time zone if it still manages this setting."))
    }
  }
  func field<V: View>(_ label: String, @ViewBuilder _ content: () -> V) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Text(label).font(.caption).foregroundStyle(.secondary)
      content().labelsHidden().accessibilityLabel(label)
    }
  }
}

struct MainWindow: View {
  @ObservedObject var c: Control
  @AppStorage("sidebarStyle") private var sidebarStyle: SidebarStyle = .portrait
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  private var sidebarStatus: SidebarStatus {
    let shield = c.menuShield
    let tone: SidebarStatus.Tone
    switch shield.symbol {
    case "checkmark.shield.fill": tone = .good
    case "xmark.shield", "exclamationmark.shield": tone = .warning
    default: tone = c.busy || c.phase == "checking" ? .working : .idle
    }
    let country = tone == .good ? c.route?.country : nil
    return SidebarStatus(title: shield.title, detail: country, tone: tone)
  }

  var body: some View {
    let motion = InterfaceMotion(reduced: reduceMotion)
    HStack(spacing: 0) {
      Sidebar(page: $c.page, status: sidebarStatus, style: sidebarStyle, motion: motion)
      Divider()
      VStack(spacing: 0) {
        ZStack(alignment: .top) {
          ScrollView {
            Group {
              switch c.page {
              case .overview: Dashboard(c: c)
              case .connection: Connection(c: c)
              case .filter: FilterView(c: c, motion: motion)
              }
            }
            .frame(maxWidth: 720, alignment: .leading).padding(32).frame(
              maxWidth: .infinity, alignment: .center)
          }.id(c.page).transition(motion.page)
        }.clipped().animation(motion.animation, value: c.page)
        if c.busy || !c.notice.isEmpty {
          Divider()
          HStack(spacing: 10) {
            if c.busy {
              ProgressView().controlSize(.small)
            } else {
              Image(systemName: "info.circle").foregroundStyle(accent)
            }
            Text(c.notice).font(.callout).textSelection(.enabled)
            Spacer()
            if !c.busy {
              Button {
                c.notice = ""
              } label: {
                Image(systemName: "xmark")
              }.buttonStyle(.plain).accessibilityLabel(localized("Dismiss message"))
            }
          }.padding(.vertical, 10).padding(.horizontal, 22).background(.bar)
        }
      }.frame(maxWidth: .infinity, maxHeight: .infinity).background(
        Color(nsColor: .windowBackgroundColor))
    }.ignoresSafeArea(.container, edges: .top).tint(accent).frame(minWidth: 790, minHeight: 600)
  }
}
@main enum LobotomyProxyEntry {
  @MainActor static func main() {
    if CommandLine.arguments.dropFirst().elementsEqual(["--relay-worker"]) {
      do { try BackgroundRelay.execWorker() } catch {
        if let data = try? JSONEncoder().encode(
          Event(state: "blocked", message: error.localizedDescription, report: nil))
        {
          FileHandle.standardOutput.write(data + Data([10]))
        }
        exit(1)
      }
    }
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--background-relay"] {
      NSApplication.shared.setActivationPolicy(.prohibited)
      DispatchQueue.global(qos: .utility).async { BackgroundRelay.supervise() }
      RunLoop.main.run()
      exit(0)
    }
    if args == ["--check-dns"] || args == ["--set-berlin-dns"] {
      do {
        var config = try Vault.read()
        if args == ["--set-berlin-dns"] { config.dnsMode = "berlin" }
        let observations = try config.observedDNS(requireBerlin: config.dnsMode == "berlin")
        FileHandle.standardOutput.write(try JSONEncoder().encode(observations) + Data([10]))
        if args == ["--set-berlin-dns"] {
          try Vault.save(config)
          if try BackgroundRelay.owned(), BackgroundRelay.loaded() {
            _ = try Tools.run(BackgroundRelay.ctl, ["kickstart", "-k", BackgroundRelay.domain + "/" + BackgroundRelay.label])
          }
        }
        exit(0)
      } catch {
        FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
        exit(1)
      }
    }
    if args == ["--profile-status"] {
      let system = try? JSONDecoder().decode(
        SystemState.self, from: Tools.run(Tools.engine, ["system"]))
      let report = Profile.report(system?.policy)
      print(report.condition.rawValue + " · " + report.detail)
      exit(0)
    }
    if args == ["--export-profile"] {
      do {
        let policy = try JSONDecoder().decode(
          FilterPolicy.self, from: FileHandle.standardInput.readDataToEndOfFile()
        ).systemRules.normalized()
        FileHandle.standardOutput.write(try Profile.data(policy))
        exit(0)
      } catch {
        FileHandle.standardError.write(Data(error.localizedDescription.utf8))
        exit(1)
      }
    }
    if CommandLine.arguments.contains("--import-stdin") {
      do {
        let config = try JSONDecoder().decode(
          Settings.self, from: FileHandle.standardInput.readDataToEndOfFile())
        try Vault.save(config)
        exit(0)
      } catch {
        FileHandle.standardError.write(Data("Keychain import failed\n".utf8))
        exit(1)
      }
    }
    AppLanguage.configureInterface()
    LobotomyProxyApp.main()
  }
}

private enum AppTheme: String, CaseIterable {
  case system, light, dark

  var title: String {
    switch self {
    case .system: localized("System")
    case .light: localized("Light")
    case .dark: localized("Dark")
    }
  }

  var appearance: NSAppearance? {
    switch self {
    case .system: nil
    case .light: NSAppearance(named: .aqua)
    case .dark: NSAppearance(named: .darkAqua)
    }
  }
}

struct LobotomyProxyApp: App {
  @StateObject private var control = Control()
  @AppStorage("appTheme") private var theme: AppTheme = .system
  @AppStorage("sidebarStyle") private var sidebarStyle: SidebarStyle = .portrait
  @Environment(\.openWindow) private var openWindow
  var body: some Scene {
    Window("Lobotomy Proxy", id: "main") {
      MainWindow(c: control).onAppear {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
      }
    }.windowStyle(.hiddenTitleBar).defaultSize(width: 960, height: 746)
      .onChange(of: theme, initial: true) { NSApp.appearance = theme.appearance }

    let shield = control.menuShield
    MenuBarExtra {
      Text(shield.title)
      if let detail = shield.detail, !detail.isEmpty { Text(detail) }
      Divider()
      Button(localized("Open Overview")) {
        control.page = .overview
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
      }
      Picker(localized("Theme"), selection: $theme) {
        ForEach(AppTheme.allCases, id: \.self) { option in
          Text(option.title).tag(option)
        }
      }.pickerStyle(.menu)
      Picker(localized("Sidebar"), selection: $sidebarStyle) {
        ForEach(SidebarStyle.allCases, id: \.self) { option in
          Text(option.title).tag(option)
        }
      }.pickerStyle(.menu)
    } label: {
      let description = "Lobotomy Proxy — " + shield.title
      Image(nsImage: NSImage(systemSymbolName: shield.symbol, accessibilityDescription: description)!)
        .renderingMode(.template)
        .accessibilityLabel(Text(verbatim: description))
        .help(description)
    }.menuBarExtraStyle(.menu)
  }
}
