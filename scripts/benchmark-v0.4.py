"""Read-only large input benchmarks and persistent-cache checks, through stdio MCP."""
import datetime
import json
import pathlib
import statistics
from benchmark import ROOT, INPUTS, synthetic_dump, run_one
from mcp_client import Client, timed


def main():
    executable = ROOT / "dist-v0.4/ScratcherMCP.exe"
    directory = ROOT / "reports/v0.4"
    directory.mkdir(exist_ok=True)
    workloads = INPUTS + [("Synthetic 1 GiB memory dump", synthetic_dump(), True)]
    dumps = sorted((ROOT / "benchmark-inputs").rglob("UEMinidump.dmp"))
    if dumps:
        workloads.append(("Real Unreal crash dump", dumps[0], False))
    report = {"date": datetime.datetime.now().astimezone().isoformat(), "version": "0.4.0",
        "method": "Three fresh MCP processes per input, no OS file-cache flush. Wall timings include stdio JSON-RPC, schema validation, job dispatch and workspace snapshots; process startup and initialize are excluded. Linear full scans measure executable-byte coverage, not whole-program semantic analysis or decompilation. Deep analysis and persistence checks are separate fresh sessions. Input EXEs/DLLs/dumps are read, never executed. Synthetic dump has 16 MiB executable code and 1008 MiB data. No Computer Use. No IDA comparison.", "results": []}
    for index, (name, path, synthetic) in enumerate(workloads):
        if not path.exists():
            continue
        row = {"name": name, "path": str(path), "size_bytes": path.stat().st_size,
            "synthetic": synthetic, "runs": []}
        for repetition in range(3):
            print(f"{name}: repetition {repetition + 1}", flush=True)
            row["runs"].append(run_one(executable, path, 1_000_000, True))
        with Client(executable) as client:
            client.tool("open_binary", {"path": str(path)})
            functions = client.tool("list_functions", {"limit": 1000})["items"]
            bounded = [f for f in functions if f.get("end") and 0 < int(f["end"], 16) - int(f["address"], 16) <= 128]
            chosen = (bounded or functions)[:3]
            row["deep_analysis"] = []
            for function in chosen:
                address = function["address"]
                try:
                    analysis, wall = timed(client, "analyze_reachable", {"address": address, "instruction_budget": 512, "byte_budget": 65536})
                    cached, cached_wall = timed(client, "analyze_reachable", {"address": address, "instruction_budget": 512, "byte_budget": 65536})
                    row["deep_analysis"].append({"address": address, "name": function["name"], "wall_ms": wall,
                        "repeat_wall_ms": cached_wall, "cache_hit": cached["cache_hit"], "instructions": analysis["instruction_count"],
                        "reachable_bytes": analysis["reachable_bytes"], "issues": analysis["issues"], "truncated": analysis["truncated"],
                        "semantic_analysis_complete": analysis["semantic_analysis_complete"]})
                except Exception as error:
                    row["deep_analysis"].append({"address": address, "error": str(error)})
            # Retain a real pseudocode result and scan report before saving.
            client.tool("analyze", {"full_scan": True}, timeout=90)
            target = chosen[0]["address"] if chosen else None
            if target:
                try:
                    client.tool("decompile", {"address": target}, timeout=45)
                    client.tool("get_control_flow", {"address": target, "instruction_budget": 512})
                except Exception as error:
                    row["cache_population_error"] = str(error)
            project = directory / f"input-{index + 1}.scratcher"
            saved, save_wall = timed(client, "save_analysis_database", {"path": str(project)}, timeout=90)
            row["persistence"] = {"project_path": str(project), "size_bytes": project.stat().st_size,
                "save_wall_ms": save_wall, "memory_after_save": client.memory()}
        with Client(executable) as restored:
            _, load_wall = timed(restored, "load_analysis_database", {"path": str(project)}, timeout=90)
            row["persistence"]["restore_wall_ms"] = load_wall
            cached, repeat_wall = timed(restored, "analyze", {"full_scan": True}, timeout=90)
            row["persistence"]["restored_scan_cached"] = cached["cached"]
            row["persistence"]["restored_scan_wall_ms"] = repeat_wall
            if target and "cache_population_error" not in row:
                code, code_wall = timed(restored, "decompile", {"address": target}, timeout=45)
                row["persistence"]["restored_pseudocode_cached"] = code["cached"]
                row["persistence"]["restored_pseudocode_wall_ms"] = code_wall
            row["persistence"]["memory_after_restore"] = restored.memory()
        row["medians"] = {key: statistics.median(r["phases"][key]["wall_ms"] for r in row["runs"])
            for key in ["open", "analyze", "full_scan", "full_scan_repeat"]}
        report["results"].append(row)
        (directory / "performance.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"name": name, "medians": row["medians"], "persistence": row["persistence"]}), flush=True)
    print(directory / "performance.json", flush=True)


if __name__ == "__main__":
    main()
