import AppKit
import SwiftUI

private struct Wrap: Layout {
  func arrange(_ width: CGFloat, _ views: Subviews) -> ([CGPoint], CGSize) {
    var x: CGFloat = 0
    var y: CGFloat = 0
    var line: CGFloat = 0
    var maxX: CGFloat = 0
    var points: [CGPoint] = []
    for v in views {
      let size = v.sizeThatFits(.unspecified)
      if x > 0 && x + size.width > width {
        x = 0
        y += line + 7
        line = 0
      }
      points.append(CGPoint(x: x, y: y))
      x += size.width + 7
      maxX = max(maxX, x - 7)
      line = max(line, size.height)
    }
    return (points, CGSize(width: maxX, height: y + line))
  }
  func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
    arrange(proposal.width ?? .infinity, subviews).1
  }
  func placeSubviews(
    in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
  ) {
    for (view, pt) in zip(subviews, arrange(bounds.width, subviews).0) {
      view.place(
        at: CGPoint(x: bounds.minX + pt.x, y: bounds.minY + pt.y), anchor: .topLeading,
        proposal: .unspecified)
    }
  }
}
private struct DomainEditor: View {
  @ObservedObject var c: Control
  let appID: String?
  let motion: InterfaceMotion
  @State private var entry = ""
  @State private var error = ""

  private var selection: DomainSelection { c.selection(for: appID) }
  private func edit(_ change: (inout DomainSelection) throws -> Void) {
    do {
      try c.updateSelection(for: appID, change)
      error = ""
    } catch { self.error = error.localizedDescription }
  }
  private func add() {
    let names = FilterPolicy.words(entry)
    guard !names.isEmpty else { return }
    edit { $0.manual.formUnion(try FilterPolicy(domains: names).normalized().domains) }
    if error.isEmpty { entry = "" }
  }
  private func presetBinding(_ preset: FilterPreset) -> Binding<Bool> {
    Binding(get: { selection.sources[preset.id] != nil }, set: { _ in edit { $0.toggle(preset) } })
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      if appID == nil {
        Wrap {
          ForEach(FilterCatalog.shared.presets) { p in
            Toggle(isOn: presetBinding(p)) {
              Label(p.name, systemImage: selection.sources[p.id] == nil ? "plus" : "checkmark")
            }.toggleStyle(.button).controlSize(.small)
          }
        }
      }
      HStack {
        TextField(appID == nil ? localized("Add a domain or enter several separated by commas") : "example.com", text: $entry).textFieldStyle(
          .roundedBorder
        ).onSubmit { add() }
        Button(localized("Add")) { add() }.disabled(FilterPolicy.words(entry).isEmpty)
        if appID != nil {
          Menu(localized("Presets")) {
            ForEach(FilterCatalog.shared.presets) { p in
              Toggle(p.name, isOn: presetBinding(p))
            }
          }.fixedSize()
        }
      }
      if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
      if !selection.domains.isEmpty {
        Wrap {
          ForEach(selection.domains, id: \.self) { d in
            HStack(spacing: 6) {
              Text(d).font(.callout)
              Button {
                edit { $0.remove(d) }
              } label: {
                Image(systemName: "xmark").font(.system(size: 9, weight: .semibold))
              }.buttonStyle(.plain).foregroundStyle(.secondary).accessibilityLabel(localized("Remove %@", d))
            }
            .padding(.horizontal, 9).padding(.vertical, 5).background(
              .quaternary.opacity(0.6), in: Capsule())
            .transition(motion.item)
          }
        }
      }
    }
  }
}

private struct ApplicationRoutingRow: View {
  @ObservedObject var c: Control
  let app: ManagedApp
  let rule: ApplicationRule
  let motion: InterfaceMotion

  private var scopePicker: some View {
    Picker(localized("Proxy routing for %@", app.name), selection: Binding(
      get: { rule.all }, set: { c.setAllRequests($0, for: app.id) }
    )) {
      Text(localized("All requests")).tag(true)
      Text(localized("Only domains")).tag(false)
    }.pickerStyle(.segmented).labelsHidden().fixedSize()
  }
  private var title: some View {
    HStack(spacing: 8) {
      if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.id) {
        Image(nsImage: NSWorkspace.shared.icon(forFile: url.path)).resizable()
          .frame(width: 23, height: 23).accessibilityHidden(true)
      }
      Text(app.name).fontWeight(.medium).fixedSize()
    }
  }
  private var remove: some View {
    Button { c.removeApp(app.id) } label: { Image(systemName: "minus.circle") }
      .buttonStyle(.plain).foregroundStyle(.secondary)
      .accessibilityLabel(localized("Remove %@", app.name))
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      ViewThatFits(in: .horizontal) {
        HStack(spacing: 12) {
          title.frame(minWidth: 148, alignment: .leading)
          Spacer(minLength: 0)
          scopePicker
          remove
        }
        VStack(alignment: .leading, spacing: 10) {
          HStack { title; Spacer(); remove }
          scopePicker
        }
      }
      if !rule.all {
        DomainEditor(c: c, appID: app.id, motion: motion)
        Text(localized("App and shared domains use the proxy. Other sites connect directly.")).font(.caption).foregroundStyle(.secondary)
      }
    }.padding(.vertical, 3)
  }
}

struct FilterView: View {
  @ObservedObject var c: Control
  let motion: InterfaceMotion
  @State private var guide = false
  @State private var rollback = false
  var body: some View {
    VStack(alignment: .leading, spacing: 24) {
      HStack {
        Text(localized("Filter")).font(.largeTitle.bold())
        Spacer()
        Button(localized("Update Profile…")) { guide = true }.buttonStyle(.borderedProminent).disabled(
          c.busy || !c.updateNeeded)
      }
      Surface {
        Text(localized("Domains")).font(.headline)
        DomainEditor(c: c, appID: nil, motion: motion)
      }.disabled(!c.draftLoaded || c.busy)
      Surface {
        HStack {
          Text(localized("Applications")).font(.headline)
          Spacer()
          Menu {
            ForEach(FilterCatalog.shared.apps) { a in
              Button(a.name) { c.addApp(a) }.disabled(
                c.draft.applications.contains { $0.id == a.id })
            }
            Divider()
            Button(localized("Choose an .app file…")) { c.chooseFilterApp() }
          } label: {
            Label(localized("Add"), systemImage: "plus")
          }.fixedSize()
        }
        Text(
          localized("Selected apps use the proxy time zone.")
        ).font(.callout).foregroundStyle(.secondary)
        if FilterCatalog.shared.apps.contains(where: {
          $0.disableWebRTC == true && NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0.id) != nil
        }) {
          Text(localized("The profile turns off WebRTC throughout Zen, including voice and video calls."))
            .font(.callout).foregroundStyle(.secondary)
        }
        ForEach(c.draft.applications) { rule in
          if let a = FilterCatalog.shared.apps.first(where: { $0.id == rule.id }) {
            Divider()
            ApplicationRoutingRow(c: c, app: a, rule: rule, motion: motion).transition(motion.item)
          }
        }
      }.disabled(!c.draftLoaded || c.busy)
      HStack(alignment: .top, spacing: 12) {
        VStack(alignment: .leading, spacing: 5) {
          Text(localized("macOS profile")).fontWeight(.medium)
          Text(c.profileReport.detail).font(.callout).foregroundStyle(.secondary)
          if c.system.policy != c.draft.systemRules && c.draftLoaded {
            Text(localized("Changes saved. Update the profile to apply them.")).font(.caption)
              .foregroundStyle(.secondary)
          }
          if c.profileReport.condition == .pending {
            Button(localized("Reload Settings…")) { c.refreshManagedPreferences() }.buttonStyle(.link)
              .disabled(c.busy)
          }
        }
        Spacer()
        Button(localized("Roll Back Profile…")) { rollback = true }.buttonStyle(.link).disabled(
          c.busy || !(c.system.installed || c.profileReport.condition.installed))
      }.padding(.horizontal, 2)
    }
    .animation(c.draftLoaded ? motion.animation : nil, value: c.draft.domains)
    .animation(c.draftLoaded ? motion.animation : nil, value: c.draft.applications)
    .sheet(isPresented: $guide) {
      VStack(alignment: .leading, spacing: 18) {
        Image(systemName: "doc.badge.gearshape").font(.title)
          .foregroundStyle(accent)
        Text(localized("Install profile")).font(.title.bold())
        Text(
          localized("In System Settings, open General → Device Management, select “Lobotomy Proxy · Filter”, and confirm the installation or replacement.")
        )
        Text(
          localized("The filter starts automatically after approval. Save your documents first. Selected apps may restart to apply the time zone.")
        ).font(.callout).foregroundStyle(.secondary)
        HStack {
          Spacer()
          Button(localized("Cancel")) { guide = false }.keyboardShortcut(.cancelAction)
          Button(localized("Open System Settings")) {
            guide = false
            c.updateProfile()
          }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
        }
      }.padding(28).frame(width: 480)
    }.alert(localized("Roll back the profile and filter?"), isPresented: $rollback) {
      Button(localized("Cancel"), role: .cancel) {}
      Button(localized("Roll Back"), role: .destructive) { c.rollback() }
    } message: {
      Text(
        localized("This removes the proxy rules. Quit and reopen the selected apps to start them normally. You can restore the system time zone separately in Connection.")
      )
    }
  }
}
