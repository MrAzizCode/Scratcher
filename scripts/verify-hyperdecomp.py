"""Read-only CLI/MCP integration checks. Never launch an analyzed input."""
import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import tempfile

from mcp_client import Client

ROOT = pathlib.Path(__file__).resolve().parent.parent


def identity(path):
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--directory", type=pathlib.Path, default=ROOT / "build/Release")
    parser.add_argument("--input", type=pathlib.Path, default=ROOT / "build/Release/ScratcherAnalysisFixture.exe")
    parser.add_argument("--expected-version", default="0.8.0")
    parser.add_argument("--require-cuda", action="store_true")
    parser.add_argument("--expect-cpu-fallback", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "reports/hyperdecomp/integration.json")
    args = parser.parse_args()
    if args.require_cuda and args.expect_cpu_fallback:
        parser.error("Choose one accelerator expectation")
    cli, mcp = args.directory / "HyperDecompCLI.exe", args.directory / "ScratcherMCP.exe"
    checks, evidence = [], {}

    def check(condition, label):
        if not condition:
            raise RuntimeError(label)
        checks.append(label)

    def run(*arguments, expected=0):
        completed = subprocess.run([str(cli), *map(str, arguments)], capture_output=True,
            text=True, encoding="utf-8", timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
        check(completed.returncode == expected, "CLI exit: " + str(arguments[0]))
        return json.loads(completed.stdout if expected == 0 else completed.stderr)

    try:
        with Client(mcp) as client:
            check(client.initialization["serverInfo"]["version"] == args.expected_version, "MCP version")
            tools = client.rpc("tools/list")["tools"]
            names = {tool["name"] for tool in tools}
            check(len(names) == len(tools) == 150, "150 unique tools")
            check({"get_acceleration_info", "build_function_similarity_index",
                "get_function_similarity_index", "find_similar_functions"} <= names, "Four accelerator schemas")
            evidence["device"] = client.tool("get_acceleration_info")["gpu"]
            opened = client.tool("open_binary", {"path": str(args.input)})
            check(opened["format"] == "PE" and opened["bits"] == 64, "Real PE x64 input")
            evidence["index"] = client.tool("build_function_similarity_index",
                {"workers": 4, "max_functions": 10000, "per_function_instruction_budget": 256})
            rows = client.tool("get_function_similarity_index", {"limit": 5000})["items"]
            check(len(rows) > 1 and all(len(row["fingerprint_256"]) == 64 for row in rows), "Actual 256-bit index")
            selected = next((row for row in rows if row["name"] == "fixture_switch"), rows[0])
            at = selected["address"]
            query = {"addresses": [row["address"] for row in rows[:32]], "top_k": 16}
            cpu = client.tool("find_similar_functions", dict(query, mode="cpu"))
            gpu = client.tool("find_similar_functions", dict(query, mode="cuda"))
            check(cpu["backend_used"] == "cpu", "Explicit CPU execution")
            check(cpu["queries"] == gpu["queries"], "MCP exact neighbor and tie-order parity")
            check(gpu["semantic_equivalence_proven"] is False, "Heuristic scope remains explicit")
            if args.require_cuda:
                check(gpu["backend_used"] == "cuda" and not gpu["fallback_reason"], "Actual CUDA execution required")
            if args.expect_cpu_fallback:
                check(gpu["backend_used"] == "cpu" and bool(gpu["fallback_reason"]), "Explicit CPU fallback required")
            auto = client.tool("find_similar_functions", dict(query, mode="auto"))
            check(cpu["queries"] == auto["queries"], "Auto result parity")
            check(auto["selection_policy"] == "retained_corpus_warm_cuda" and auto["auto_minimum_gain_percent"] == 10,
                "Auto policy and margin exposed")
            repeated = client.tool("find_similar_functions", dict(query, mode="auto"))
            check(repeated["queries"] == cpu["queries"], "Repeated Auto parity")
            if args.require_cuda:
                check(repeated["cache_hit"] and not repeated["calibration_performed"], "Auto cached measured policy")
            evidence["search"] = {key: gpu[key] for key in ("backend_used", "fallback_reason", "timings", "device_bytes")}
            evidence["auto"] = {key: auto[key] for key in ("backend_used", "fallback_reason", "calibration_performed", "calibration_equal",
                "selection_policy", "auto_cpu_baseline_ms", "auto_cuda_warm_baseline_ms", "auto_minimum_gain_percent", "timings")}
            evidence["peak_mcp_memory"] = client.memory()

        info = run("--gpu-info")
        check(info["input_executed"] is False, "Device info executes no input")
        metadata = run("--inspect", args.input)
        check(metadata["function_count"] > 0, "CLI function candidates")
        listing = run("--disassemble", args.input, "--address", at, "--count", 8)
        check(len(listing["instructions"]) == 8 and listing["listing_only"], "CLI real instruction listing")
        code = run("--decompile", args.input, "--address", at)
        check(code["decompilation_completed"] and len(code["code"]) > 40, "CLI functional pseudocode backend")
        evidence["pseudocode"] = code
        similarity = run("--similarity", args.input, "--address", at, "--mode", "cpu", "--top-k", 4)
        check(len(similarity["queries"][0]["matches"]) == 4, "CLI similarity workflow")
        analysis = run("--analyze", args.input, "--time-budget-ms", 1000)
        check(analysis["input_executed"] is False, "CLI bounded analysis executes no input")
        evidence["bounded_analysis"] = analysis
        with tempfile.TemporaryDirectory(prefix="hyperdecomp-verify-", dir=ROOT / ".tmp") as folder:
            output = pathlib.Path(folder) / "fingerprints.json"
            completed = subprocess.run([str(cli), "--export-fingerprints", str(args.input), "--output", str(output)],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            check(completed.returncode == 0 and not completed.stdout.strip(), "CLI new-file export")
            exported = json.loads(output.read_text(encoding="utf-8"))
            check(len(exported["items"]) > 1, "CLI fingerprint artifact")
            before = output.read_bytes()
            failure = run("--inspect", args.input, "--output", output, expected=1)
            check("error" in failure and output.read_bytes() == before, "Existing output is preserved")
        check("error" in run("--disassemble", args.input, "--count", 10001, expected=1), "CLI instruction bound")
        check("error" in run("--inspect", args.input, "--unknown", 1, expected=1), "CLI unknown option rejected")
        report = {"passed": True, "date": datetime.datetime.now().astimezone().isoformat(),
            "checks": checks, "computer_use": False, "input_executed": False,
            "cli": identity(cli), "mcp": identity(mcp), "input": identity(args.input), "evidence": evidence}
    except Exception as error:
        report = {"passed": False, "error": str(error), "checks": checks, "evidence": evidence}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "checks": len(checks), "report": str(args.output),
        "error": report.get("error")}, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
