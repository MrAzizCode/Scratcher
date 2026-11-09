"""Measure provenance-backed Roblox code-path coverage against an unchanged scope."""
import argparse
import bisect
import hashlib
import json
import pathlib
import struct
from mcp_client import Client, timed

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
EXPECTED = "11a30ada177d15a9ec1c1dc30957b28b46839c9c6407e53be6138d2f12f6f2fe"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def union(ranges):
    merged = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def scope(info):
    # Read original PE section flags and file-backed virtual extents independently.
    data = TARGET.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    section_count, optional_bytes = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    section_table = pe + 24 + optional_bytes
    base = int(info["base"], 16)
    candidates = [(int(row["start"], 16), int(row["end"], 16)) for row in info["analysis_candidate_ranges"]]
    ranges = []
    for index in range(section_count):
        off = section_table + index * 40
        virtual_bytes, rva, file_bytes, file_offset = struct.unpack_from("<IIII", data, off + 8)
        flags = struct.unpack_from("<I", data, off + 36)[0]
        start = base + rva
        # The loader maps max(VirtualSize, SizeOfRawData), including file alignment.
        end = start + min(max(virtual_bytes, file_bytes), file_bytes, max(0, len(data) - file_offset))
        if flags & 0x20000000:
            ranges.append((start, end))
        for low, high in candidates:
            if max(start, low) < min(end, high):
                ranges.append((max(start, low), min(end, high)))
    return union(ranges)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=pathlib.Path, default=ROOT / "build/Release/ScratcherMCP.exe")
    parser.add_argument("--policy", default="baseline", choices=["baseline", "next_seed", "control_flow"])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--discovery-rounds", type=int, default=8, choices=range(1, 33))
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--audit-spans", action="store_true", help="Independently sum and bound every coverage span on the first repetition")
    args = parser.parse_args()
    assert digest(TARGET) == EXPECTED, "Benchmark target changed"
    output = args.output or ROOT / f"reports/coverage-70/{args.policy}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"input_sha256": EXPECTED, "executable_sha256": digest(args.executable),
        "policy": args.policy, "target_percent": 70, "method": f"Static original bytes; {args.runs} fresh MCP processes; OS cache not flushed; no byte resynchronization or execution", "runs": []}
    for index in range(args.runs):
        with Client(args.executable) as client:
            info, opening = timed(client, "open_binary", {"path": str(TARGET)})
            ranges = scope(info)
            denominator = sum(end - start for start, end in ranges)
            options = {"instruction_budget": 100000000, "byte_budget": 536870912,
                "time_budget_ms": 60000, "per_function_instruction_budget": 100000,
                "function_budget": 1000000, "coverage_span_budget": 4000000,
                "workers": 8, "discovery_rounds": args.discovery_rounds, "use_cache": False}
            if args.policy != "baseline":
                options["boundary_policy"] = args.policy
            result, wall = timed(client, "analyze_code_paths", options, timeout=180)
            covered = result["covered_bytes"]
            if "candidate_code_bytes" in result:
                assert result["candidate_code_bytes"] == denominator, "Native denominator differs from independent PE scope"
            percent = 100 * covered / denominator if denominator else 0
            report["runs"].append({"open_ms": opening, "analysis_wall_ms": wall,
                "scope_ranges": [{"start": hex(a), "end": hex(b)} for a, b in ranges],
                "scope_bytes": denominator, "covered_bytes": covered,
                "coverage_percent": percent, "target_met": percent >= 70,
                "result": result, "memory": client.memory()})
            if args.audit_spans and index == 0:
                audited, offset, previous_end = 0, 0, -1
                coverage_hash = hashlib.sha256()
                starts = [a for a, _ in ranges]
                while True:
                    page = client.tool("get_code_analysis", {"view": "coverage", "offset": offset, "limit": 5000})
                    assert not page["cache_stale"], "Coverage cache became stale"
                    for span in page["items"]:
                        a, b = int(span["start"], 16), int(span["end"], 16)
                        pos = bisect.bisect_right(starts, a) - 1
                        assert pos >= 0 and ranges[pos][0] <= a < b <= ranges[pos][1]
                        assert a > previous_end, "Span union overlaps or was not compacted"
                        previous_end = b
                        audited += b - a
                        coverage_hash.update(struct.pack("<QQ", a, b))
                    offset += len(page["items"])
                    if offset >= page["total"]:
                        break
                    assert page["items"], "Coverage pagination stopped early"
                assert audited == covered, "Coverage counter differs from independent union"
                report["runs"][-1]["span_audit"] = {"passed": True,
                    "unique_bytes": audited, "span_count": offset,
                    "ordered_ranges_sha256": coverage_hash.hexdigest(),
                    "all_spans_inside_unchanged_scope": True}
            output.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"{args.policy} run {index+1}: {covered:,}/{denominator:,} bytes ({percent:.3f}%) in {wall:.2f} ms", flush=True)


if __name__ == "__main__":
    main()
