"""Package verified 0.6 artifacts, preserving earlier releases."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "dist-v0.6"
REPORTS = ROOT / "reports/hyperdecomp"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    archive = ROOT / "Scratcher-v0.6.zip"
    if archive.exists():
        raise RuntimeError("Release archive already exists; preserve it and choose a new version")
    names = ["Scratcher.exe", "ScratcherMCP.exe", "HyperDecompCLI.exe", "HyperDecompBench.exe"]
    for name in names:
        if digest(PACKAGE / name) != digest(ROOT / "build/Release" / name):
            raise RuntimeError("Installed executable differs from build: " + name)
    for name in ("tests-final.log", "tests-cpu-final.log"):
        if not re.search(r"100% tests passed.*out of 40", (REPORTS / name).read_text(encoding="utf-8-sig")):
            raise RuntimeError("Test evidence is incomplete: " + name)
    integration = load(REPORTS / "integration.json")
    if not integration["passed"]:
        raise RuntimeError("Integration checks failed")
    for key in ("cli", "mcp"):
        if integration[key]["sha256"] != digest(ROOT / "build/Release" / pathlib.Path(integration[key]["path"]).name):
            raise RuntimeError("Integration executable changed: " + key)
    if not load(REPORTS / "integration-cpu-only.json")["passed"]:
        raise RuntimeError("CPU-only integration checks failed")
    for name in ("integration-installed.json", "integration-runtime-fallback.json"):
        if not load(REPORTS / name)["passed"]:
            raise RuntimeError("Installed package check failed: " + name)
    performance = load(REPORTS / "performance.json")
    if performance["executable"]["sha256"] != digest(PACKAGE / "HyperDecompBench.exe"):
        raise RuntimeError("Benchmark executable differs from package")
    for source in performance["sources"]:
        if digest(pathlib.Path(source["path"])) != source["sha256"]:
            raise RuntimeError("Benchmark source changed after measurement: " + source["path"])
    if not all(case["summary"]["every_process_exact"] and case["summary"]["actual_cuda_processes"] == 3
               for case in performance["cases"]):
        raise RuntimeError("Primary benchmark lacks exact actual-CUDA evidence")

    selected = ["environment.json", "research-source-snapshot.json", "dependency-inventory.json",
        "performance.json", "performance.md", "performance-fixture-fingerprints.json", "performance-cpu-only.json", "performance-cpu-only.md",
        "performance-chrome.json", "performance-chrome.md", "large-dll-index-summary.json", "delivery.md",
        "performance-chrome-export-limit.json", "performance-chrome-export-limit.md",
        "integration.json", "integration-cpu-only.json", "integration-installed.json", "integration-runtime-fallback.json",
        "tests-final.log", "tests-cpu-final.log", "accelerator-final-details.log", "accelerator-cpu-final-details.log",
        "build-final.log", "build-cpu-final.log", "setup-validation.log"]
    destination = PACKAGE / "reports/hyperdecomp"
    destination.mkdir(parents=True, exist_ok=True)
    for name in selected:
        source = REPORTS / name
        if source.exists():
            shutil.copy2(source, destination / name)
    initial = destination / "initial"
    initial.mkdir(exist_ok=True)
    for source in (REPORTS / "initial").glob("performance*.md"):
        shutil.copy2(source, initial / source.name)
    for name in ("benchmark-hyperdecomp.py", "verify-hyperdecomp.py", "mcp_client.py"):
        target = PACKAGE / "benchmarks" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copy2(ROOT / "scripts" / name, target)

    files = sorted(path for path in PACKAGE.rglob("*") if path.is_file()
        and path.name != "package-manifest.json" and "sessions" not in path.relative_to(PACKAGE).parts)
    manifest = {"version": "0.6.0", "created": datetime.datetime.now().astimezone().isoformat(),
        "gpu_scope": "Exact top-k comparison of heuristic function-prefix fingerprints",
        "full_application_speedup_established": False, "full_analysis_parity_established": False,
        "files": [{"path": path.relative_to(PACKAGE).as_posix(), "bytes": path.stat().st_size,
            "sha256": digest(path)} for path in files]}
    manifest_path = PACKAGE / "package-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in files + [manifest_path]:
            bundle.write(path, path.relative_to(PACKAGE).as_posix())
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("Archive CRC failed")
        for item in manifest["files"]:
            data = bundle.read(item["path"])
            if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise RuntimeError("Archive manifest mismatch: " + item["path"])
    verification = {"passed": True, "archive": str(archive), "bytes": archive.stat().st_size,
        "sha256": digest(archive), "manifest_files": len(files), "zip_crc_verified": True,
        "all_entry_hashes_verified": True, "computer_use": False}
    (REPORTS / "package-verification.json").write_text(json.dumps(verification, indent=2), encoding="utf-8")
    print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
