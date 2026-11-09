"""Cross-check frozen benchmark binaries, installed files and verification evidence."""
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports/v0.5"


def load(name):
    return json.loads((OUT / name).read_text(encoding="utf-8-sig"))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    tests = (OUT / "tests.log").read_text(encoding="utf-8-sig")
    assert re.search(r"100% tests passed.*out of 38", tests)
    live, stdio = load("live-mcp.json"), load("stdio-mcp.json")
    assert live["passed"] and stdio["tool_count"] == 146
    tools = load("mcp-tools.json")["tools"]
    assert len(tools) == len({tool["name"] for tool in tools}) == 146
    rows = load("performance-v0.5-0.5.json")["results"]
    assert len(rows) == 8 and all(len(row["runs"]) == 3 for row in rows)
    binary_hashes = {}
    for name in ("Scratcher.exe", "ScratcherMCP.exe"):
        shipped = digest(ROOT / "dist-v0.5" / name)
        assert shipped == digest(ROOT / "build/Release" / name)
        binary_hashes[name] = shipped
    for row in rows:
        assert row["executable"]["sha256"].lower() == binary_hashes["ScratcherMCP.exe"]
        assert row["variant"] == "0.5"
    fixture_hash = digest(ROOT / "dist-v0.5/samples/ScratcherAnalysisFixture.exe")
    fixture = next(row for row in rows if row["name"] == "Readable analysis fixture")
    assert fixture_hash == fixture["input"]["sha256"]
    report = {"passed": True, "test_suites_passed": 38,
        "live_checks_passed": len(live["checks"]), "standalone_mcp_passed": True,
        "advertised_tools": len(tools), "benchmarked_inputs": len(rows),
        "fresh_process_repetitions_per_input": 3,
        "all_benchmarks_match_shipped_binary": True, "binary_sha256": binary_hashes,
        "sample_sha256": fixture_hash, "computer_use": False,
        "full_analysis_parity_established": False}
    (OUT / "final-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
