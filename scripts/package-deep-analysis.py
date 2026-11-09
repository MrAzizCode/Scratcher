"""Package verified Scratcher 0.7 artifacts without replacing earlier releases."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "dist-v0.7"
REPORTS = ROOT / "reports/deep-analysis"
VERSION = "0.7.0"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def integration(name, directory, backend):
    report = load(REPORTS / name)
    require(report["passed"], "Integration checks failed: " + name)
    require(report["computer_use"] is False and report["input_executed"] is False,
            "Unexpected verification method: " + name)
    for key in ("cli", "mcp"):
        executable = directory / pathlib.Path(report[key]["path"]).name
        require(report[key]["sha256"] == digest(executable),
                "Integration executable changed: " + str(executable))
    require(report["evidence"]["search"]["backend_used"] == backend,
            "Unexpected execution backend: " + name)
    return {"file": name, "checks": len(report["checks"]), "backend": backend}


def main():
    archive = ROOT / "Scratcher-v0.7.zip"
    require(not archive.exists(), "Preserve the existing archive; select a new release version")
    for name in ("Scratcher.exe", "ScratcherMCP.exe", "HyperDecompCLI.exe", "HyperDecompBench.exe"):
        require(digest(PACKAGE / name) == digest(ROOT / "build/Release" / name),
                "Installed executable differs from build: " + name)
    for name in ("tests-final.log", "tests-cpu.log"):
        require(re.search(r"100% tests passed[^\r\n]*out of 42",
                          (REPORTS / name).read_text(encoding="utf-8-sig")),
                "Expected 42 passing suites: " + name)
    integrations = [
        integration("integration-cuda.json", ROOT / "build/Release", "cuda"),
        integration("integration-cpu.json", ROOT / "build-cpu/Release", "cpu"),
        integration("integration-installed.json", PACKAGE, "cuda"),
        integration("integration-runtime-fallback.json", PACKAGE, "cpu"),
    ]

    comparison = load(REPORTS / "comparison.json")
    require(comparison["validation_status"] == "passed" and
            comparison["completed_fresh_processes"] == 24,
            "Expected completed 24-process deep-analysis comparison")
    require(all(item["available"] for item in comparison["independent_decode"].values()),
            "Independent decoder validation was unavailable")
    for source in comparison["source_hashes"]:
        require(digest(pathlib.Path(source["path"])) == source["sha256"],
                "Measured source changed: " + source["path"])
    for case in comparison["cases"] + comparison["heavy_cases"]:
        require(digest(pathlib.Path(case["input"]["path"])) == case["input"]["sha256"],
                "Measured input changed: " + case["input"]["path"])
        require(digest(pathlib.Path(case["executable"]["path"])) == case["executable"]["sha256"],
                "Measured executable changed: " + case["executable"]["path"])
        if case["variant"] == "current":
            require(case["executable"]["sha256"] == digest(PACKAGE / "ScratcherMCP.exe"),
                    "Package differs from measured current executable")

    selected = ["comparison.json", "comparison.md", "delivery.md", "tests-final.log", "tests-cpu.log",
                "build-final.log", "build-cpu.log", "integration-cuda.json", "integration-cpu.json",
                "integration-installed.json", "integration-runtime-fallback.json"]
    destination = PACKAGE / "reports/deep-analysis"
    destination.mkdir(parents=True, exist_ok=True)
    for name in selected:
        shutil.copy2(REPORTS / name, destination / name)
    benchmarks = PACKAGE / "benchmarks"
    benchmarks.mkdir(exist_ok=True)
    for name in ("benchmark-deep-analysis.py", "verify-hyperdecomp.py", "mcp_client.py"):
        shutil.copy2(ROOT / "scripts" / name, benchmarks / name)
    (benchmarks / "README.md").write_text(
        "# Reproducing validation\n\n"
        "Run these scripts from the source checkout as described in docs/deep-analysis.md. "
        "The benchmark defaults require its build/Release, examples and .tmp directories, "
        "a preserved 0.6 installation, Python 3.11+ and the independent iced-x86 Python module. "
        "The optional third-party heavy inputs are identified by SHA-256 in the report and are "
        "not redistributed. No analyzed input is executed.\n\n"
        "For this extracted package, verify CLI/MCP using:\n\n"
        "```powershell\npython benchmarks/verify-hyperdecomp.py --directory . "
        "--input samples/ScratcherAnalysisFixture.exe --require-cuda "
        "--output reports/local-verification.json\n```\n\n"
        "Omit --require-cuda to permit automatic CPU fallback. The verifier creates temporary "
        "files under .tmp; create that directory first.\n", encoding="utf-8")

    files = sorted(path for path in PACKAGE.rglob("*") if path.is_file()
                   and path.name != "package-manifest.json"
                   and not ({"sessions", ".tmp", "__pycache__"} & set(path.relative_to(PACKAGE).parts)))
    manifest = {
        "version": VERSION, "created": datetime.datetime.now().astimezone().isoformat(),
        "analysis_scope": "Conservative CPU register-transfer candidates, CFGs and references",
        "register_candidates_retain_residual_unknown": True,
        "gpu_scope": "Unchanged exact fingerprint top-k matcher",
        "full_application_speedup_established": False,
        "full_analysis_parity_established": False,
        "original_roblox_coverage_improved": False,
        "validation": {"cuda_build_test_suites": 42, "cpu_build_test_suites": 42,
                       "fresh_comparison_processes": 24, "integrations": integrations},
        "files": [{"path": path.relative_to(PACKAGE).as_posix(), "bytes": path.stat().st_size,
                   "sha256": digest(path)} for path in files],
    }
    manifest_path = PACKAGE / "package-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in files + [manifest_path]:
            bundle.write(path, path.relative_to(PACKAGE).as_posix())
    with zipfile.ZipFile(archive) as bundle:
        require(bundle.testzip() is None, "Archive CRC failed")
        require(set(bundle.namelist()) == {row["path"] for row in manifest["files"]} |
                {"package-manifest.json"}, "Archive entry set mismatch")
        for row in manifest["files"]:
            data = bundle.read(row["path"])
            require(len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"],
                    "Archive manifest mismatch: " + row["path"])
        require(bundle.read("package-manifest.json") == manifest_path.read_bytes(),
                "Manifest was not archived exactly")
    verification = {"passed": True, "archive": str(archive), "bytes": archive.stat().st_size,
                    "sha256": digest(archive), "manifest_files": len(files),
                    "zip_crc_verified": True, "all_entry_hashes_verified": True,
                    "computer_use": False, "input_executed": False}
    (REPORTS / "package-verification.json").write_text(json.dumps(verification, indent=2), encoding="utf-8")
    print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
