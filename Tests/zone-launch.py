"""Run the ordinary Launch Services path with an isolated, disposable app."""
import pathlib
import plistlib
import json
import subprocess
import tempfile
import uuid

project = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    folder = pathlib.Path(tmp)
    child = folder / "Sample.app"
    exe = child / "Contents/MacOS/Sample"
    exe.parent.mkdir(parents=True)
    (child / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "local.proxyguard.test." + uuid.uuid4().hex,
        "CFBundleName": "Proxy Guard Test", "CFBundlePackageType": "APPL", "CFBundleExecutable": "Sample",
        "LSUIElement": True,
    }))
    source = folder / "Sample.swift"
    source.write_text('''import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let url = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("result")
let record = ["zone": [ProcessInfo.processInfo.environment["TZ"] ?? "default"],
              "switches": CommandLine.arguments.dropFirst().filter { $0.hasPrefix("--") }]
try JSONEncoder().encode(record).write(to: url, options: .atomic)
app.run()
''')
    subprocess.run(["swiftc", source, "-o", exe], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", child], check=True, capture_output=True)
    sources = ["Model", "ZoneLaunch", "FilterPolicy", "DomainSelection", "ProfileStatus", "BackgroundRelay"]
    bundle = folder / "Controller.app/Contents"
    for name in ("MacOS", "Resources"):
        (bundle / name).mkdir(parents=True)
    control = bundle / "MacOS/test"
    (bundle / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "local.proxyguard.test.controller", "CFBundlePackageType": "APPL",
        "CFBundleExecutable": control.name,
    }))
    subprocess.run(["swiftc", "-parse-as-library", *[project / "App" / (n + ".swift") for n in sources],
                    project / "Tests/ZoneFixture.swift", "-o", control], check=True)
    child_id = plistlib.loads((child / "Contents/Info.plist").read_bytes())["CFBundleIdentifier"]
    for adapter in ("desktop", "chromium"):
        catalog = {"presets": [], "apps": [{"id": child_id, "name": "Sample", "adapter": adapter, "port": 17747}]}
        (bundle / "Resources/catalog.json").write_text(json.dumps(catalog))
        subprocess.run([control, child, adapter], check=True, timeout=50)
