"""Read-only real EXE/DLL benchmarks through MCP; explicit synthetic dump workload."""
import argparse
import datetime
import hashlib
import json
import pathlib
import statistics
import struct
import time
from mcp_client import Client, timed

ROOT = pathlib.Path(__file__).resolve().parent.parent
INPUTS = [
    ("Call of Duty executable", (ROOT / "benchmark-inputs" / "cod23-cod.exe"), False),
    ("Ride executable", (ROOT / "benchmark-inputs" / "Ride-Win64-Shipping.exe"), False),
    ("Chromium DLL", (ROOT / "benchmark-inputs" / "libcef.dll"), False),
    ("Qt browser DLL", (ROOT / "benchmark-inputs" / "Qt5WebEngineCore.dll"), False),
]


def synthetic_dump():
    path = ROOT / "benchmark-inputs/synthetic-1GiB.dmp"
    path.parent.mkdir(exist_ok=True)
    if path.exists() and path.stat().st_size == 2**30 + 4096:
        return path
    # A valid AMD64 Memory64 minidump with RX code and RW data. Most data is sparse.
    header = bytearray(4096)
    struct.pack_into("<IIIIIIQ", header, 0, 0x504d444d, 0xa793, 3, 32, 0, 0, 2)
    struct.pack_into("<III", header, 32, 7, 56, 128)
    struct.pack_into("<H", header, 128, 9)
    struct.pack_into("<III", header, 44, 9, 48, 256)
    struct.pack_into("<QQQQQQ", header, 256, 2, 4096, 0x140001000, 2**24, 0x150000000, 2**30-2**24)
    struct.pack_into("<III", header, 56, 16, 16+96, 320)
    struct.pack_into("<IIQ", header, 320, 16, 48, 2)
    struct.pack_into("<QQIIQIIII", header, 336, 0x140001000, 0x140001000, 0x20, 0, 2**24, 0x1000, 0x20, 0x1000000, 0)
    struct.pack_into("<QQIIQIIII", header, 384, 0x150000000, 0x150000000, 4, 0, 2**30-2**24, 0x1000, 4, 0x20000, 0)
    # Repeated 64-byte functions: fixed constant, direct call to adjacent return.
    function = b"\xb8\x2a\0\0\0\xe8\x01\0\0\0\xc3\xc3" + b"\x90" * 52
    chunk = function * (2**20 // len(function))
    with path.open("wb") as output:
        output.write(header)
        for _ in range(16):
            output.write(chunk)
        output.seek(2**30+4096-1)
        output.write(b"\0")
    return path


def cold_pseudocode(executable, path):
    with Client(executable) as client:
        metadata = client.tool("open_binary", {"path": str(path)})
        sections = [s for s in metadata["sections"] if s["executable"] and s["file_size"]]
        if not sections:
            return {"unavailable": "No captured executable memory"}
        functions = client.tool("list_functions", {"limit": 1000})["items"]
        candidates = [f for f in functions if f.get("end") and 0 < int(f["end"],16)-int(f["address"],16) <= 128]
        target = candidates[0]["address"] if candidates else sections[0]["address"]
        result, wall = timed(client, "decompile", {"address": target}, timeout=45)
        return {"address": target, "wall_ms": wall, "elapsed_ms": result.get("elapsed_ms"),
            "code_chars": len(result.get("code", "")), "memory": client.memory(),
            "method": "Fresh process; metadata and function listing only before first pseudocode request"}


def run_one(executable, path, budget, full_scan=False):
    record = {"path": str(path), "budget": budget, "phases": {}}
    with Client(executable) as client:
        record["version"] = client.initialization["serverInfo"]["version"]
        for name, args, key in [("open_binary", {"path": str(path)}, "open"),
                              ("get_binary_info", {}, "metadata_repeat")]:
            result, wall = timed(client, name, args)
            record["phases"][key] = {"wall_ms": wall, "memory": client.memory(), "result": result}
        metadata = record["phases"]["open"]["result"]
        executable_sections = [s for s in metadata["sections"] if s["executable"] and s["file_size"]]
        if not executable_sections:
            record["analysis_unavailable"] = "No captured executable memory"
            return record
        start_address = executable_sections[0]["address"]
        instructions, wall = timed(client, "disassemble", {"address": start_address, "count": 10000})
        record["phases"]["listing_10000"] = {"wall_ms": wall, "rows": len(instructions["instructions"]), "memory": client.memory()}
        for key in ["analyze", "analyze_repeat"]:
            result, wall = timed(client, "analyze", {"instruction_budget": budget}, timeout=90)
            record["phases"][key] = {"wall_ms": wall, "result": result, "memory": client.memory()}
        if full_scan:
            for key in ["full_scan", "full_scan_repeat"]:
                result, wall = timed(client, "analyze", {"full_scan": True}, timeout=90)
                record["phases"][key] = {"wall_ms": wall, "result": result, "memory": client.memory()}
        functions = client.tool("list_functions", {"limit": 1000})["items"]
        # Choose a bounded metadata function, not a potentially huge startup routine.
        candidates = [f for f in functions if f.get("end") and 0 < int(f["end"], 16)-int(f["address"], 16) <= 128]
        target = candidates[0]["address"] if candidates else start_address
        record["pseudocode_address"] = target
        for key in ["pseudocode_first", "pseudocode_repeat"]:
            try:
                result, wall = timed(client, "decompile", {"address": target}, timeout=45)
                record["phases"][key] = {"wall_ms": wall, "elapsed_ms": result.get("elapsed_ms"),
                    "cached": result.get("cached"), "code_chars": len(result.get("code", "")), "memory": client.memory()}
            except Exception as error:
                record["phases"][key] = {"error": str(error)}
                break
    try:
        record["cold_pseudocode"] = cold_pseudocode(executable, path)
    except Exception as error:
        record["cold_pseudocode"] = {"error": repr(error)}
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    workloads = INPUTS + [("Synthetic 1 GiB memory dump", synthetic_dump(), True)]
    crash_dumps = sorted((ROOT / "benchmark-inputs").rglob("UEMinidump.dmp"))
    if crash_dumps:
        workloads.append(("Real Unreal crash dump", crash_dumps[0], False))
    report = {"date": datetime.datetime.now().astimezone().isoformat(),
        "method": "Fresh MCP process for each repetition; no OS cache flush. Wall times include stdio JSON, dispatch and state snapshots. Input binaries are read, never executed. Analysis discovers direct calls linearly; it does not decompile every function. Synthetic dump is explicitly generated, not a real process capture.",
        "results": []}
    report_dir = ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    output = report_dir / "performance.json"
    variants = [("0.3", ROOT / "dist-v0.3/ScratcherMCP.exe", 1000000, args.runs)]
    if args.baseline:
        variants.insert(0, ("0.2 baseline", ROOT / "dist-v0.2/ScratcherMCP.exe", 100000, 1))
        variants.append(("0.3 comparable", ROOT / "dist-v0.3/ScratcherMCP.exe", 100000, 1))
    for variant, executable, budget, runs in variants:
        for name, path, synthetic in workloads:
            if not path.exists() or (variant == "0.2 baseline" and path.suffix == ".dmp"):
                continue
            row = {"name": name, "variant": variant, "size_bytes": path.stat().st_size,
                "synthetic": synthetic, "runs": []}
            for index in range(runs):
                print(f"{variant}: {name} repetition {index+1}", flush=True)
                try:
                    row["runs"].append(run_one(executable, path, budget, variant == "0.3"))
                except Exception as error:
                    row["runs"].append({"error": repr(error)})
            report["results"].append(row)
            output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(output, flush=True)


if __name__ == "__main__":
    main()
