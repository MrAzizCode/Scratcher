"""Reanalyze the pinned conditional code image with a larger discovery allowance.

Preserves the original scope and all source limitations. Never executes inputs.
"""
import argparse
import copy
import hashlib
import importlib
import json
from pathlib import Path
import struct

from mcp_client import Client, timed

diagnostic = importlib.import_module("replay-existing-code-image")
benchmark = importlib.import_module("benchmark-coverage-target")
ROOT = Path("D:/Scratcher")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=32, choices=range(1, 33))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ack-unverified-source", action="store_true")
    args = parser.parse_args()
    if not args.ack_unverified_source:
        parser.error("--ack-unverified-source is required; this remains a conditional diagnostic")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT.resolve()) or output.exists() or output.suffix != ".json":
        raise ValueError("Output must be a new JSON report under D:/Scratcher")
    previous_path = ROOT / "reports/coverage-70/existing-code-image-replay.json"
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    image = Path(previous["analysis_image"])
    if (previous["status"] != "conditional_diagnostic_unverified_source"
            or previous["target_70_verified"] is not False
            or not previous["coverage_span_audit_passed"]
            or not previous["original_source_files_unchanged"]):
        raise ValueError("Previous diagnostic evidence is incomplete")
    if image.resolve() != diagnostic.OUTPUT.resolve():
        raise ValueError("Unrecognized derived analysis image")
    before = {str(path): benchmark.digest(path) for path in
              (diagnostic.ORIGINAL, diagnostic.SOURCE, image)}
    if (before[str(diagnostic.ORIGINAL)] != diagnostic.ORIGINAL_SHA
            or before[str(diagnostic.SOURCE)] != diagnostic.SOURCE_SHA
            or before[str(image)] != previous["analysis_image_sha256"]):
        raise ValueError("Pinned diagnostic inputs changed")
    allowed = previous["scan_rva_ranges"]
    report = copy.deepcopy(previous)
    report["previous_diagnostic_report"] = str(previous_path)
    report["previous_diagnostic_report_sha256"] = benchmark.digest(previous_path)
    report["previous_analysis_result"] = previous["result"]
    report["requested_discovery_rounds"] = args.rounds
    executable = ROOT / "build/Release/ScratcherMCP.exe"
    try:
        with Client(executable) as client:
            original_info = client.tool("open_binary", {"path": str(diagnostic.ORIGINAL)})
            full_scope = benchmark.scope(original_info)
            base = int(original_info["base"], 16)
            full = [[a-base, b-base] for a, b in full_scope]
            if (sum(b-a for a, b in full) != diagnostic.DENOMINATOR
                    or full != previous["original_candidate_rva_ranges"]
                    or any(not diagnostic.contains(full, a, b) for a, b in allowed)):
                raise ValueError("Original scope or captured allowlist changed")
            client.tool("open_binary", {"path": str(image)})
            options = copy.deepcopy(previous["result"]["options"])
            options.update(discovery_rounds=args.rounds, use_cache=False,
                           scan_ranges=[{"start": hex(base+a), "end": hex(base+b)}
                                        for a, b in allowed])
            result, wall = timed(client, "analyze_code_paths", options, timeout=180)
            report.update(result=result, analysis_wall_ms=wall,
                          analyzer_sha256=benchmark.digest(executable))
            if (result["candidate_code_bytes"] != diagnostic.DENOMINATOR
                    or result["scan_scope_bytes"] != previous["scan_allowed_bytes"]):
                raise ValueError("Native scope counters changed")
            offset, total, prior_end = 0, 0, -1
            audit_hash = hashlib.sha256()
            while True:
                page = client.tool("get_code_analysis", {"view": "coverage", "offset": offset, "limit": 5000})
                if page["cache_stale"]:
                    raise ValueError("Coverage became stale")
                for row in page["items"]:
                    a, b = int(row["start"], 16)-base, int(row["end"], 16)-base
                    if (a <= prior_end or not diagnostic.contains(allowed, a, b)
                            or not diagnostic.contains(full, a, b)):
                        raise ValueError("Coverage overlaps or escapes original/captured scope")
                    prior_end = b
                    total += b-a
                    audit_hash.update(struct.pack("<QQ", a, b))
                offset += len(page["items"])
                if offset >= page["total"]:
                    break
                if not page["items"]:
                    raise ValueError("Coverage pagination ended prematurely")
            if total != result["covered_bytes"]:
                raise ValueError("Unique span audit differs from native counter")
            report.update(coverage_span_audit_passed=True, coverage_span_count=offset,
                          ordered_coverage_sha256=audit_hash.hexdigest(),
                          diagnostic_decoded_bytes=total,
                          diagnostic_decoded_percent_of_original_scope=100*total/diagnostic.DENOMINATOR,
                          diagnostic_decoded_percent_of_allowed_source=100*total/report["scan_allowed_bytes"],
                          threshold_crossed_for_unverified_source=total >= (diagnostic.DENOMINATOR*7+9)//10,
                          target_70_verified=False)
    except BaseException as error:
        report["diagnostic_failed"] = str(error)
        report["coverage_span_audit_passed"] = False
        raise
    finally:
        after = {path: benchmark.digest(Path(path)) for path in before}
        report["original_source_files_unchanged"] = before == after
        report["input_sha256_after"] = after
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    if before != after:
        raise ValueError("Input changed during analysis")
    print(json.dumps({key: report[key] for key in
                     ("diagnostic_decoded_bytes", "diagnostic_decoded_percent_of_original_scope",
                      "analysis_wall_ms", "target_70_verified")}, indent=2))
    print(output)


if __name__ == "__main__":
    main()
