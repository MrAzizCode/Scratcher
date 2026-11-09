"""Package the tested 0.5 build and verify every ZIP entry against its manifest."""
import datetime
import hashlib
import json
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "dist-v0.5"
REPORTS = ROOT / "reports/v0.5"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    for filename in ("Scratcher.exe", "ScratcherMCP.exe"):
        if digest(PACKAGE / filename) != digest(ROOT / "build/Release" / filename):
            raise RuntimeError(f"Installed binary differs from tested build: {filename}")
    for filename in ("live-mcp.json", "stdio-mcp.json", "final-verification.json"):
        data = json.loads((REPORTS / filename).read_text(encoding="utf-8-sig"))
        if filename != "stdio-mcp.json" and not data.get("passed"):
            raise RuntimeError(f"Verification has not passed: {filename}")

    destination = PACKAGE / "reports"
    destination.mkdir(exist_ok=True)
    names = ["upgrade-report.md", "analysis-comparison.md", "performance-v0.5-initial.json",
        "performance-v0.5-0.5.json", "roblox-expanded.json", "roblox-import-functions.json",
        "fixture-0.4.json", "fixture-0.5.json", "fixture-samples.json", "tool-schemas.json", "mcp-tools.json",
        "tests.log", "live-mcp.json", "stdio-mcp.json", "final-verification.json"]
    for name in names:
        shutil.copy2(REPORTS / name, destination / name)
    ghidra = destination / "ghidra-fixture"
    ghidra.mkdir(exist_ok=True)
    for name in ("command.json", "ghidra-pre.json", "ghidra-post.json", "ghidra-samples.json",
        "ghidra-functions-pre.json", "ghidra-functions-post.json", "console.log", "ghidra.log"):
        shutil.copy2(REPORTS / "ghidra-fixture" / name, ghidra / name)
    for name in ("README.md", "THIRD_PARTY.md"):
        shutil.copy2(ROOT / name, PACKAGE / name)

    files = sorted(p for p in PACKAGE.rglob("*") if p.is_file() and
        p.name != "package-manifest.json" and "sessions" not in p.relative_to(PACKAGE).parts)
    manifest = {"version": "0.5.0", "created": datetime.datetime.now().astimezone().isoformat(),
        "files": [{"path": p.relative_to(PACKAGE).as_posix(), "bytes": p.stat().st_size,
            "sha256": digest(p)} for p in files]}
    manifest_path = PACKAGE / "package-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    archive = ROOT / "Scratcher-v0.5.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in files + [manifest_path]:
            bundle.write(path, path.relative_to(PACKAGE).as_posix())
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("ZIP CRC verification failed")
        for item in manifest["files"]:
            data = bundle.read(item["path"])
            if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise RuntimeError(f"ZIP manifest mismatch: {item['path']}")
    result = {"passed": True, "archive": str(archive), "bytes": archive.stat().st_size,
        "sha256": digest(archive), "manifest_files": len(files), "zip_crc_verified": True,
        "all_entry_hashes_verified": True}
    (REPORTS / "package-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
