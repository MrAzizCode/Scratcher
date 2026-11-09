"""Conditional offline diagnostic for one existing raw .text image.

No build identity, read-success mask or atomic acquisition is verified for the raw
source. The explicit acknowledgement permits a diagnostic, never a verified 70%
claim. Only original metadata and this single raw source are used; inputs are not
executed and no process is opened.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import struct

from mcp_client import Client, timed

reader = importlib.import_module("capture-module-code")
ROOT = Path("D:/Scratcher")
ORIGINAL = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
SOURCE = ROOT / "benchmark-inputs/roblox_text_dump.bin"
SOURCE_SHA = "8a8715d1cf08666a98b438adaad2cf3ca5d838d8f902b3f63b224b1a81037ed5"
ORIGINAL_SHA = "11a30ada177d15a9ec1c1dc30957b28b46839c9c6407e53be6138d2f12f6f2fe"
DENOMINATOR = 102242816
OUTPUT = ROOT / "reports/coverage-70/existing-code-image.analysis.bin"
REPORT = ROOT / "reports/coverage-70/existing-code-image-replay.json"


def contains(ranges, begin, end):
    return any(a <= begin < end <= b for a, b in ranges)


def subtract(ranges, excluded):
    result = []
    excluded = reader.merge_ranges(excluded)
    for begin, end in ranges:
        cursor = begin
        for low, high in excluded:
            if high <= cursor or low >= end:
                continue
            if low > cursor:
                result.append([cursor, low])
            cursor = max(cursor, high)
            if cursor >= end:
                break
        if cursor < end:
            result.append([cursor, end])
    return reader.merge_ranges(result)


def validate_source(data, expected_length, acknowledged, expected_sha=SOURCE_SHA):
    if not acknowledged:
        raise ValueError("Requires --ack-unverified-source; this does not verify source identity or capture success")
    if len(data) != expected_length:
        raise ValueError("Raw .text image length differs from original .text VirtualSize")
    if reader.sha(data) != expected_sha:
        raise ValueError("Existing raw code image SHA256 differs from pinned diagnostic source")


def relocation_holes(pe, begin, end):
    rva, size = pe.directory(5)
    if not rva or not size:
        return []
    if size > 64*1024*1024:
        raise ValueError("Unbounded relocation directory")
    data = pe.rva_bytes(rva, size)
    cursor, slots = 0, []
    while cursor < len(data):
        if len(data)-cursor < 8:
            raise ValueError("Truncated relocation header")
        page, block = struct.unpack_from("<II", data, cursor)
        if block < 8 or block % 2 or block > len(data)-cursor:
            raise ValueError("Malformed relocation block")
        for at in range(cursor+8, cursor+block, 2):
            value = struct.unpack_from("<H", data, at)[0]
            slot = page + (value & 4095)
            if value >> 12 == 10 and slot < end and slot + 8 > begin:
                slots.append([max(begin, slot), min(end, slot+8)])
        cursor += block
    return reader.merge_ranges(slots)


def tests():
    checks = {}
    for name, data, length, ack, digest in (
        ("no_ack_rejected", b"abc", 3, False, reader.sha(b"abc")),
        ("wrong_length_rejected", b"abc", 4, True, reader.sha(b"abc")),
        ("wrong_hash_rejected", b"abc", 3, True, "0"*64)):
        try:
            validate_source(data, length, ack, digest)
        except ValueError:
            checks[name] = True
        else:
            checks[name] = False
    checks["range_holes_subtracted"] = subtract([[100, 200]], [[120, 128], [150, 160]]) == [[100, 120], [128, 150], [160, 200]]
    checks["nested_adjacent_holes_normalized"] = subtract([[100, 200]], [[120, 140], [125, 130], [140, 150]]) == [[100, 120], [150, 200]]
    if not all(checks.values()):
        raise ValueError("Diagnostic importer CLI/range self-tests failed")
    return checks


def run(acknowledged):
    checks = tests()
    original = ORIGINAL.read_bytes()
    if reader.sha(original) != ORIGINAL_SHA:
        raise ValueError("Original benchmark PE changed")
    pe = reader.PE(original)
    sections = [s for s in pe.sections if s["name"] == ".text"]
    if len(sections) != 1:
        raise ValueError("Original has no unique .text section")
    section = sections[0]
    data = SOURCE.read_bytes()
    validate_source(data, section["virtual_size"], acknowledged)
    if section["rva"] != 0x1000 or section["virtual_size"] != 102239452:
        raise ValueError("Pinned original .text layout changed")
    if OUTPUT.exists() or REPORT.exists():
        raise ValueError("Diagnostic output/report exists; never overwrite existing evidence")
    chunks, initial, suffixes = [], [], []
    for at in range(0, len(data), 1024*1024):
        chunk = data[at:at+1024*1024]
        prefix_length = len(chunk.rstrip(b"\0"))
        begin, end = section["rva"]+at, section["rva"]+at+prefix_length
        if prefix_length:
            initial.append([begin, end])
        if prefix_length < len(chunk):
            suffixes.append([end, begin+len(chunk)])
        chunks.append({"source_offset": at, "source_bytes": len(chunk), "included_nonzero_prefix_bytes": prefix_length,
                       "excluded_zero_suffix_bytes": len(chunk)-prefix_length, "all_zero_chunk": prefix_length == 0})
    initial = reader.merge_ranges(initial)
    excluded = relocation_holes(pe, section["rva"], section["rva"]+len(data))
    allowed = subtract(initial, excluded)
    if not allowed or len(allowed) > 4096:
        raise ValueError("Allowlist empty or exceeds native bounded scan range count")
    image = bytearray(original)
    off = section["raw_offset"]
    if off > len(image) or len(data) > len(image)-off:
        raise ValueError("Raw image is not original-file-backed")
    image[off:off+len(data)] = data
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("xb") as stream:
        stream.write(image)
    report = {"status": "conditional_diagnostic_unverified_source", "target_70_verified": False,
              "source_path": str(SOURCE), "source_sha256": SOURCE_SHA, "source_bytes": len(data),
              "original_path": str(ORIGINAL), "original_sha256": ORIGINAL_SHA,
              "analysis_image": str(OUTPUT), "analysis_image_sha256": reader.sha(image),
              "assumed_raw_start_rva": section["rva"], "source_embeds_build_identity": False,
              "source_has_read_success_bitmap": False, "source_capture_identity_verified": False,
              "ack_unverified_source": acknowledged, "module_base": None,
              "code_origin": "Single existing raw .text file at assumed original RVA; original 0.742 metadata is conditional context only",
              "capture_is_atomic": None, "capture_authenticity_verified": False,
              "provenance_limitations": ["No read-success bitmap; nonzero bytes cannot prove successful acquisition and internal zero holes cannot be identified.",
                  "Per-1MiB trailing zero suffixes are withheld conservatively; legitimate trailing zero bytes may also be withheld.",
                  "Raw file contains no embedded module identity or runtime base; code variations against matching snapshots remain unresolved.",
                  "All documented code DIR64 slots are withheld from decode because runtime-to-preferred relocation cannot be proven.",
                  "Readable instruction candidates are not proof of same-build identity, real execution, function ownership or semantics."],
              "one_source_only": True, "snapshots_merged": False, "inputs_executed": False,
              "process_reads_performed": False, "foreign_scripts_executed": False,
              "source_chunks": chunks, "excluded_zero_suffix_rva_ranges": suffixes,
              "excluded_unknown_runtime_dir64_rva_ranges": excluded, "relocation_values_normalized": False,
              "scan_rva_ranges": allowed, "scan_allowed_bytes": sum(b-a for a,b in allowed),
              "original_candidate_scope_bytes": DENOMINATOR, "cli_range_selftests": checks,
              "missing_original_bytes_credited": False, "semantic_analysis_complete": False}
    try:
        with Client(ROOT / "build/Release/ScratcherMCP.exe") as client:
            original_info = client.tool("open_binary", {"path": str(ORIGINAL)})
            candidate_metadata = [(int(row["start"],16)-pe.base, int(row["end"],16)-pe.base) for row in original_info["analysis_candidate_ranges"]]
            full = []
            for s in pe.sections:
                a,b = s["rva"], s["rva"]+s["raw_size"]
                if s["flags"] & 0x20000000 and a<b:
                    full.append([a,b])
                for low,high in candidate_metadata:
                    if max(a,low)<min(b,high):
                        full.append([max(a,low),min(b,high)])
            full = reader.merge_ranges(full)
            if sum(b-a for a,b in full) != DENOMINATOR or any(not contains(full,a,b) for a,b in allowed):
                raise ValueError("Original fixed scope or diagnostic allowlist mismatch")
            report["original_scope_independently_audited"] = True
            report["original_candidate_rva_ranges"] = full
            client.tool("open_binary", {"path": str(OUTPUT)})
            options = {"boundary_policy":"control_flow", "scan_ranges":[{"start":hex(pe.base+a),"end":hex(pe.base+b)} for a,b in allowed],
                "instruction_budget":100000000,"byte_budget":536870912,"time_budget_ms":60000,
                "per_function_instruction_budget":100000,"function_budget":1000000,"coverage_span_budget":4000000,
                "workers":8,"discovery_rounds":8,"use_cache":False}
            result,wall = timed(client,"analyze_code_paths",options,timeout=180)
            report.update(result=result,analysis_wall_ms=wall,analyzer_sha256=reader.file_sha(ROOT/"build/Release/ScratcherMCP.exe"))
            if result["candidate_code_bytes"] != DENOMINATOR:
                raise ValueError("Derived image changed the original coverage denominator")
            offset,total,previous = 0,0,-1
            h=hashlib.sha256()
            while True:
                page=client.tool("get_code_analysis",{"view":"coverage","offset":offset,"limit":5000})
                if page["cache_stale"]:
                    raise ValueError("Coverage cache stale")
                for row in page["items"]:
                    a,b=int(row["start"],16)-pe.base,int(row["end"],16)-pe.base
                    if a<=previous or not contains(allowed,a,b) or not contains(full,a,b):
                        raise ValueError("Coverage is not ordered compact or escapes allowed original code")
                    previous=b
                    total+=b-a
                    h.update(struct.pack("<QQ",a,b))
                offset+=len(page["items"])
                if offset>=page["total"]:
                    break
                if not page["items"]:
                    raise ValueError("Coverage pagination ended early")
            if total!=result["covered_bytes"]:
                raise ValueError("Independent span audit differs from coverage counter")
            report.update(coverage_span_audit_passed=True,ordered_coverage_sha256=h.hexdigest(),coverage_span_count=offset,
                diagnostic_decoded_bytes=total,diagnostic_decoded_percent_of_original_scope=100*total/DENOMINATOR,
                diagnostic_decoded_percent_of_allowed_source=100*total/report["scan_allowed_bytes"],
                threshold_crossed_for_unverified_source=total>=(DENOMINATOR*7+9)//10)
    except BaseException as ex:
        report["diagnostic_failed"]=str(ex)
        raise
    finally:
        report["original_sha256_after"]=reader.file_sha(ORIGINAL)
        report["source_sha256_after"]=reader.file_sha(SOURCE)
        report["original_source_files_unchanged"]=(report["original_sha256_after"]==ORIGINAL_SHA and report["source_sha256_after"]==SOURCE_SHA)
        REPORT.write_text(json.dumps(report,indent=2),encoding="utf-8")
    if not report["original_source_files_unchanged"]:
        raise ValueError("Input changed during diagnostic")
    print(json.dumps({k:report[k] for k in ("diagnostic_decoded_bytes","diagnostic_decoded_percent_of_original_scope","threshold_crossed_for_unverified_source","target_70_verified","analysis_wall_ms")},indent=2))
    print(REPORT)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ack-unverified-source",action="store_true")
    args=parser.parse_args()
    if not args.ack_unverified_source:
        parser.error("--ack-unverified-source is required; this is a conditional diagnostic only")
    run(args.ack_unverified_source)


if __name__=="__main__":
    main()
