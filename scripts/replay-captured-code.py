"""Analyze physically captured Roblox module code with original metadata and full scope.

Creates a non-executable-named analysis copy, never runs either input, and restricts
native coverage to captured code ranges. No private heap or stack bytes are copied.
"""
import argparse
import bisect
import hashlib
import importlib
import json
import mmap
import pathlib
import struct
import time
from mcp_client import Client, timed

helper = importlib.import_module("inspect-roblox-dumps")
ROOT = pathlib.Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
SCOPE = [(0x1000, 0x6181e00), (0x6182000, 0x6182a00), (0x9125000, 0x9125200)]
DENOMINATOR = 102242816


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def contains(ranges, low, high):
    pos = bisect.bisect_right([a for a, _ in ranges], low) - 1
    return pos >= 0 and ranges[pos][0] <= low < high <= ranges[pos][1]


def normalize_code_relocations(pe, image, captured, runtime_base, image_size):
    """Undo only documented DIR64 slots physically copied from this module."""
    rva, size = pe.read("<II", pe.directory_offset + 5 * 8)
    adjusted, external = [], 0
    if not rva or not size:
        return adjusted, external
    off, end = pe.offset(pe.base + rva, size), pe.offset(pe.base + rva, size) + size
    while off < end:
        if end - off < 8:
            raise ValueError("Truncated original relocation header")
        page, block = pe.read("<II", off)
        if block < 8 or block % 2 or block > end - off:
            raise ValueError("Malformed original relocation block")
        for entry_off in range(off + 8, off + block, 2):
            entry, = pe.read("<H", entry_off)
            slot = page + (entry & 0xfff)
            if entry >> 12 != 10 or not contains(captured, slot, slot + 8):
                continue
            target = pe.offset(pe.base + slot, 8)
            value, = struct.unpack_from("<Q", image, target)
            if runtime_base <= value < runtime_base + image_size:
                struct.pack_into("<Q", image, target, value - runtime_base + pe.base)
                adjusted.append(hex(slot))
            else:
                external += 1
        off += block
    return adjusted, external


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True, help="New .analysis.bin path under D:/Scratcher")
    parser.add_argument("--ack-metadata-match", action="store_true", help="Allow matching build GUID/version metadata when dump checksum was omitted")
    parser.add_argument("--executable", type=pathlib.Path, default=ROOT / "build/Release/ScratcherMCP.exe")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT.resolve()) or not output.name.endswith(".analysis.bin"):
        raise ValueError("Output must be a new .analysis.bin under D:/Scratcher")
    if output.exists() or output in (ORIGINAL.resolve(), args.dump.resolve()):
        raise ValueError("Output must not overwrite any existing input or artifact")
    pe = helper.PE(ORIGINAL)
    if pe.digest != helper.EXPECTED:
        raise ValueError("Original benchmark input changed")
    target = helper.original_identity(pe)
    cfg, _ = pe.cfg()
    inventory = helper.analyze_dump(args.dump, pe, target, SCOPE, cfg)
    qualified = [row for row in inventory["module_results"] if row["identity_metadata_qualified"]]
    if len(qualified) != 1:
        raise ValueError("Dump has no unique matching-build Roblox module")
    row = qualified[0]
    if not row["identity_accepted_for_same_build"] and not args.ack_metadata_match:
        raise ValueError("Original-file identity is unproven; review metadata and explicitly acknowledge omitted checksum")
    module = next(module for module in inventory["roblox_modules"] if module["base"] == int(row["base"], 16))
    pieces = row["candidate_pieces_for_code_only_replay"]
    captured = helper.union((int(p["start_rva"], 16), int(p["end_rva"], 16)) for p in pieces)
    if not captured:
        raise ValueError("No physically stored code bytes")
    for a, b in captured:
        if not contains(SCOPE, a, b):
            raise ValueError("Replay range escapes original candidate scope")
    image = bytearray(pe.data)
    dump = helper.Dump(args.dump)
    copied = []
    try:
        for piece in pieces:
            a, b = int(piece["start_rva"], 16), int(piece["end_rva"], 16)
            at = piece["dump_file_offset"]
            if not 0 <= at <= len(dump.data) - (b - a):
                raise ValueError("Replay span exceeds physically stored dump data")
            code = dump.data[at:at + b - a]
            file_off = pe.offset(pe.base + a, b - a)
            image[file_off:file_off + b - a] = code
            copied.append({**piece, "code_sha256": hashlib.sha256(code).hexdigest()})
        adjusted, external = normalize_code_relocations(pe, image, captured, module["base"], module["image_size"])
    finally:
        dump.close()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(image)
    del image
    report = {"original_input_sha256": pe.digest, "dump_sha256": inventory["dump_sha256"],
        "dump_path": str(args.dump), "analysis_image": str(output), "analysis_image_sha256": digest(output),
        "executable_sha256": digest(args.executable), "byte_source": "Original metadata plus captured module code only",
        "module": module, "identity_matches": row["identity_matches"],
        "exact_original_file_identity_verified": row["exact_original_file_hash_verified"],
        "omitted_checksum_acknowledged": args.ack_metadata_match,
        "captured_ranges": copied, "captured_candidate_bytes": sum(b - a for a, b in captured),
        "original_candidate_scope_bytes": DENOMINATOR, "code_relocation_slots_normalized": adjusted,
        "external_code_relocation_slots_left_unknown": external,
        "multiple_snapshots_merged": False, "missing_byte_fill_credited": False,
        "inputs_executed": False, "private_heap_or_stack_copied": False}
    report_path = output.with_name(output.name.replace(".analysis.bin", "-replay.json"))
    try:
        with Client(args.executable) as client:
            info = client.tool("open_binary", {"path": str(output)})
            options = {"boundary_policy": "control_flow", "scan_ranges": [{"start": hex(pe.base + a), "end": hex(pe.base + b)} for a, b in captured],
                "instruction_budget": 100000000, "byte_budget": 536870912, "time_budget_ms": 60000,
                "per_function_instruction_budget": 100000, "coverage_span_budget": 4000000, "workers": 8,
                "discovery_rounds": 8, "use_cache": False}
            result, wall = timed(client, "analyze_code_paths", options, timeout=180)
            report.update(result=result, analysis_wall_ms=wall)
            if result["candidate_code_bytes"] != DENOMINATOR:
                raise ValueError("Derived artifact changed original denominator")
            summed, offset = 0, 0
            while True:
                page = client.tool("get_code_analysis", {"view": "coverage", "offset": offset, "limit": 5000})
                if page["cache_stale"]:
                    raise ValueError("Coverage cache is stale")
                for span in page["items"]:
                    a, b = int(span["start"], 16) - pe.base, int(span["end"], 16) - pe.base
                    if not contains(captured, a, b):
                        raise ValueError("Native coverage escaped captured bytes")
                    summed += b - a
                offset += len(page["items"])
                if offset >= page["total"]:
                    break
            if summed != result["covered_bytes"]:
                raise ValueError("Independent captured span union mismatch")
            report.update(coverage_span_audit_passed=True, decoded_captured_bytes=summed,
                decoded_percent_of_original_scope=100 * summed / DENOMINATOR,
                decoded_percent_of_captured_scope=100 * summed / report["captured_candidate_bytes"],
                target_70_met=summed >= (DENOMINATOR * 7 + 9) // 10)
    finally:
        report["original_input_unchanged"] = digest(ORIGINAL) == pe.digest
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: report.get(key) for key in ("captured_candidate_bytes", "decoded_captured_bytes",
        "decoded_percent_of_original_scope", "decoded_percent_of_captured_scope", "target_70_met", "analysis_wall_ms")}, indent=2))
    print(report_path)


if __name__ == "__main__":
    main()
