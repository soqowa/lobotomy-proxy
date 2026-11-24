"""Exercise the Swift model and real profile serializer in an isolated macOS bundle."""
import pathlib
import plistlib
import shutil
import subprocess
import tempfile

project = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    bundle = pathlib.Path(tmp) / "Fixture.app" / "Contents"
    for directory in ("Resources", "MacOS"):
        (bundle / directory).mkdir(parents=True)
    exe = bundle / "MacOS" / "Fixture"
    (bundle / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "local.proxyguard.fixture",
        "CFBundleExecutable": exe.name,
        "CFBundlePackageType": "APPL",
    }))
    shutil.copy(project / "engine/catalog.json", bundle / "Resources")
    shutil.copytree(project / "App/Resources/ru.lproj", bundle / "Resources/ru.lproj")
    sources = ["Localization", "Model", "ZoneLaunch", "FilterPolicy", "DomainSelection", "ProfileStatus", "BackgroundRelay"]
    subprocess.run(["swiftc", "-parse-as-library", *[project / "App" / (name + ".swift") for name in sources],
                    project / "Tests/PolicyFixture.swift", "-o", exe], check=True)
    for languages, expected in [("(ru-RU,en)", "ru"), ("(en-US,ru)", "en"), ("(hy-AM,ru)", "en")]:
        subprocess.run([exe, "-AppleLanguages", languages, expected], check=True)
