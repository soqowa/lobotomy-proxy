"""Run the ordinary Launch Services path with an isolated, disposable app."""
import pathlib
import plistlib
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
try (ProcessInfo.processInfo.environment["TZ"] ?? "default").write(to:url,atomically:true,encoding:.utf8)
app.run()
''')
    subprocess.run(["swiftc", source, "-o", exe], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", child], check=True, capture_output=True)
    sources = ["Model", "ZoneLaunch", "FilterPolicy", "DomainSelection", "ProfileStatus", "BackgroundRelay"]
    control = folder / "test"
    subprocess.run(["swiftc", "-parse-as-library", *[project / "App" / (n + ".swift") for n in sources],
                    project / "Tests/ZoneFixture.swift", "-o", control], check=True)
    subprocess.run([control, child], check=True, timeout=50)
