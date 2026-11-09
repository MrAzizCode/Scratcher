"""Validate and analyze a code-only module capture offline; never execute inputs.

Manifest identity is corroborated against the exact original file. A JSON manifest
cannot authenticate who acquired bytes or prove an atomic runtime snapshot; that
limitation is reported explicitly rather than treating payload hashes as signatures.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib
import json
from pathlib import Path
import struct
import time

from mcp_client import Client, timed

capture = importlib.import_module("capture-module-code")
ROOT = Path("D:/Scratcher").resolve()


def contains(ranges, begin, end):
    return any(a <= begin < end <= b for a, b in ranges)


def integer(value, what):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a nonnegative integer")
    return value


def strict_ranges(rows):
    if not isinstance(rows, list) or len(rows) > 100000:
        raise ValueError("Invalid range list")
    result = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("Range must contain numeric RVA start/end")
        begin, end = (integer(v, "RVA") for v in row)
        if begin >= end:
            raise ValueError("Empty/reversed range")
        result.append([begin, end])
    result.sort()
    for prev, cur in zip(result, result[1:]):
        if cur[0] < prev[1]:
            raise ValueError("Overlapping ranges")
    return result


def check_manifest(manifest, manifest_path, original):
    """Verify invariants before allocating/writing any derived analysis image."""
    original = Path(original).resolve(strict=True)
    manifest_path = Path(manifest_path).resolve(strict=True)
    image = original.read_bytes()
    original_hash = capture.sha(image)
    pe = capture.PE(image)
    identity = dict(pe.identity(), codeview_records=capture.codeview(pe, pe.rva_bytes),
                    version_records=capture.version_records(pe, pe.rva_bytes))
    for key in ("original_sha256", "source_pe_sha256", "original_sha256_after", "loaded_module_file_sha256_after"):
        if manifest.get(key) != original_hash:
            raise ValueError(f"Missing/mismatched {key}")
    for key in ("original_identity", "loaded_identity"):
        if manifest.get(key) != pe.identity():
            raise ValueError(f"Missing/mismatched {key}")
    if manifest.get("module_identity") != identity or manifest.get("codeview_records") != identity["codeview_records"] or manifest.get("version_records") != identity["version_records"]:
        raise ValueError("Missing/mismatched loaded build GUID/version records")
    for key in ("identity_verified_before_capture", "source_file_unchanged"):
        if manifest.get(key) is not True:
            raise ValueError(f"Required verified invariant {key} is absent")
    for key in ("injection", "debugger_attach", "process_suspended", "capture_is_atomic"):
        if manifest.get(key) is not False:
            raise ValueError(f"Unsupported/missing acquisition invariant {key}")
    for key in ("protection_changes", "non_code_bytes_exported"):
        if manifest.get(key) != 0 or isinstance(manifest.get(key), bool):
            raise ValueError(f"Unsupported/missing acquisition invariant {key}")
    if manifest.get("schema_version") != 1 or manifest.get("byte_source") != "already_running_process_read_only" or manifest.get("semantic_analysis_complete") is not False or "capture_failed" in manifest:
        raise ValueError("Manifest is incomplete, failed, or unsupported")
    runtime_base = integer(manifest.get("module_base"), "module_base")
    if not runtime_base or runtime_base > (1 << pe.bits) - pe.image_size:
        raise ValueError("Module base exceeds image address space")
    candidates, details, _ = capture.candidate_ranges(pe)
    requested = strict_ranges(manifest.get("candidate_ranges"))
    if not requested or any(not contains(candidates, a, b) for a, b in requested):
        raise ValueError("Requested capture escapes independently validated original code scope")
    requested_bytes = sum(b - a for a, b in requested)
    if manifest.get("requested_code_bytes") != requested_bytes:
        raise ValueError("Requested byte accounting mismatch")
    rows = manifest.get("ranges")
    canonical = manifest.get("captured_ranges")
    if not isinstance(rows, list) or not isinstance(canonical, list) or not rows or len(rows) != len(canonical) or len(rows) > 100000:
        raise ValueError("Missing/invalid captured payload rows")
    payloads, spans = [], []
    for row, source in zip(rows, canonical):
        begin, end, size = integer(row.get("start_rva"), "start_rva"), integer(row.get("end_rva"), "end_rva"), integer(row.get("bytes"), "bytes")
        if not contains(requested, begin, end) or size != end - begin:
            raise ValueError("Payload length or RVA scope mismatch")
        path_name = row.get("output_file")
        if not isinstance(path_name, str) or not path_name or Path(path_name).is_absolute():
            raise ValueError("Payload must use a relative contained path")
        path = (manifest_path.parent / path_name).resolve()
        if not path.is_relative_to(manifest_path.parent) or not path.is_file():
            raise ValueError("Payload path escapes capture directory")
        if source.get("rva_start") != begin or source.get("rva_end") != end or source.get("bytes") != size or source.get("file") != path_name or source.get("sha256") != row.get("sha256"):
            raise ValueError("Capture payload aliases disagree")
        protection = integer(source.get("protection"), "protection")
        if source.get("state") != capture.MEM_COMMIT or source.get("type") != capture.MEM_IMAGE or protection & capture.PAGE_GUARD or protection & capture.PAGE_NOACCESS or protection & 255 not in capture.READABLE:
            raise ValueError("Payload claims inaccessible/non-image page")
        data = path.read_bytes()
        if len(data) != size or capture.sha(data) != row.get("sha256"):
            raise ValueError("Payload SHA256/length mismatch")
        pe.rva_bytes(begin, size)  # Must map wholly to one immutable file-backed section.
        spans.append([begin, end])
        payloads.append((begin, end, data))
    captured = strict_ranges(spans)
    missing_rows = manifest.get("missing_ranges")
    if not isinstance(missing_rows, list):
        raise ValueError("Missing inaccessible-page accounting")
    missing = strict_ranges([[r.get("rva_start"), r.get("rva_end")] for r in missing_rows])
    for row, (begin, end) in zip(missing_rows, [[r.get("rva_start"), r.get("rva_end")] for r in missing_rows]):
        if not contains(requested, begin, end) or not isinstance(row.get("reason"), str) or not row["reason"] or not isinstance(row.get("win32_error"), int):
            raise ValueError("Missing range lacks scope/reason/error provenance")
    partition = strict_ranges(captured + missing)
    if capture.merge_ranges(partition) != capture.merge_ranges(requested):
        raise ValueError("Captured/missing ranges do not exactly partition requested scope")
    captured_bytes, missing_bytes = sum(b-a for a,b in captured), sum(b-a for a,b in missing)
    if manifest.get("captured_code_bytes") != captured_bytes or manifest.get("missing_code_bytes") != missing_bytes or manifest.get("complete_requested_code_capture") is not (missing_bytes == 0):
        raise ValueError("Captured/missing totals or completion flag mismatch")
    expected_percent = 100 * captured_bytes / requested_bytes
    if not isinstance(manifest.get("capture_coverage_percent"), (float, int)) or abs(manifest["capture_coverage_percent"] - expected_percent) > 1e-9:
        raise ValueError("Capture percentage mismatch")
    scope = manifest.get("scope", {})
    if scope.get("candidate_ranges") != manifest["candidate_ranges"] or scope.get("requested_code_bytes") != requested_bytes:
        raise ValueError("Capture scope aliases disagree")
    return pe, image, payloads, capture.merge_ranges(captured), candidates, details


def file_offset(pe, rva, length):
    section = pe.section(rva)
    if not section or not contains([[section["rva"], section["rva"] + section["raw_size"]]], rva, rva + length):
        raise ValueError("RVA is not wholly file backed")
    return section["raw_offset"] + rva - section["rva"]


def normalize_code_dir64(pe, image, captured, runtime_base):
    directory_rva, length = pe.directory(5)
    if not directory_rva or not length:
        return [], 0
    if length > 64 * 1024 * 1024:
        raise ValueError("Relocation directory exceeds validation bound")
    relocations = pe.rva_bytes(directory_rva, length)
    cursor, adjusted, external, visited = 0, [], 0, set()
    while cursor < length:
        if length - cursor < 8:
            raise ValueError("Truncated relocation block")
        page, block = struct.unpack_from("<II", relocations, cursor)
        if block < 8 or block % 2 or block > length - cursor:
            raise ValueError("Malformed relocation block")
        for at in range(cursor + 8, cursor + block, 2):
            value = struct.unpack_from("<H", relocations, at)[0]
            slot = page + (value & 4095)
            if value >> 12 != 10 or not contains(captured, slot, slot + 8):
                continue
            if pe.bits != 64 or slot in visited:
                raise ValueError("Duplicate/incompatible captured DIR64 slot")
            visited.add(slot)
            off = file_offset(pe, slot, 8)
            pointer = struct.unpack_from("<Q", image, off)[0]
            if runtime_base <= pointer < runtime_base + pe.image_size:
                preferred = pe.base + pointer - runtime_base
                if preferred != pointer:
                    struct.pack_into("<Q", image, off, preferred)
                    adjusted.append({"slot_rva": slot, "runtime_value": pointer, "preferred_value": preferred})
            else:
                external += 1
        cursor += block
    return adjusted, external


def prepare(manifest_path, original, output, manifest=None):
    manifest_path = Path(manifest_path).resolve(strict=True)
    output = capture.output_path(output)
    if output.exists() or not output.name.endswith(".analysis.bin"):
        raise ValueError("Output must be a new .analysis.bin under D:/Scratcher")
    manifest = manifest if manifest is not None else json.loads(manifest_path.read_text(encoding="utf-8"))
    pe, original_data, payloads, captured, candidates, details = check_manifest(manifest, manifest_path, original)
    image = bytearray(original_data)
    for begin, end, data in payloads:
        off = file_offset(pe, begin, end - begin)
        image[off:off + len(data)] = data
    adjusted, external = normalize_code_dir64(pe, image, captured, manifest["module_base"])
    if capture.file_sha(Path(original)) != manifest["original_sha256"]:
        raise ValueError("Original file changed before derived image write")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(image)
    report = {"source_manifest": str(manifest_path), "source_manifest_sha256": capture.file_sha(manifest_path),
              "source_pe": str(Path(original).resolve()), "original_sha256": manifest["original_sha256"],
              "analysis_image": str(output), "analysis_image_sha256": capture.sha(image),
              "module_identity": manifest["module_identity"], "runtime_module_base": manifest["module_base"],
              "preferred_image_base": pe.base, "captured_rva_ranges": captured,
              "captured_candidate_bytes": sum(b-a for a,b in captured),
              "original_candidate_rva_ranges": candidates, "original_candidate_scope_bytes": sum(b-a for a,b in candidates),
              "captured_scope_missing_bytes": manifest["missing_code_bytes"],
              "code_dir64_normalized": adjusted, "external_dir64_slots_left_unchanged": external,
              "capture_is_atomic": False, "capture_authenticity_cryptographically_verified": False,
              "manifest_identity_correlated_to_exact_original": True,
              "provenance_limitations": ["Manifest acquisition claims are self-reported; unsigned JSON and payload hashes cannot authenticate an acquisition.",
                                        "Source process was unsuspended; bytes may represent different moments.",
                                        "Uncaptured original bytes remain in derived file for metadata mapping but are excluded from decoding by scan_ranges."],
              "missing_byte_fill_credited": False, "private_heap_or_stack_copied": False,
              "inputs_executed": False, "process_reads_performed": False,
              "semantic_analysis_complete": False}
    return pe, report


def analyze(pe, report, executable):
    captured = report["captured_rva_ranges"]
    with Client(executable) as client:
        original_info = client.tool("open_binary", {"path": report["source_pe"]})
        original_base = int(original_info["base"], 16)
        if original_base != pe.base:
            raise ValueError("Original native image base differs from independently parsed PE")
        metadata_ranges = [(int(r["start"], 16)-pe.base, int(r["end"], 16)-pe.base)
                           for r in original_info["analysis_candidate_ranges"]]
        native_scope = []
        for section in pe.sections:
            begin, end = section["rva"], section["rva"] + section["raw_size"]
            if section["flags"] & 0x20000000 and begin < end:
                native_scope.append([begin, end])
            for low, high in metadata_ranges:
                if max(begin, low) < min(end, high):
                    native_scope.append([max(begin, low), min(end, high)])
        native_scope = capture.merge_ranges(native_scope)
        if native_scope != report["original_candidate_rva_ranges"]:
            raise ValueError("Original MCP metadata scope differs from independent original PE scope; review required")
        report["original_scope_crosschecked_with_original_open_binary"] = True
        client.tool("open_binary", {"path": report["analysis_image"]})
        options = {"boundary_policy": "control_flow", "scan_ranges": [{"start": hex(pe.base+a), "end": hex(pe.base+b)} for a,b in captured],
                   "instruction_budget": 100000000, "byte_budget": 536870912, "time_budget_ms": 60000,
                   "per_function_instruction_budget": 100000, "coverage_span_budget": 4000000,
                   "function_budget": 1000000, "workers": 8, "discovery_rounds": 8, "use_cache": False}
        result, wall = timed(client, "analyze_code_paths", options, timeout=180)
        denominator = report["original_candidate_scope_bytes"]
        if result["candidate_code_bytes"] != denominator:
            raise ValueError("Native original denominator differs from independent original PE scope")
        summed, offset, previous_end = 0, 0, -1
        coverage_hash = hashlib.sha256()
        while True:
            page = client.tool("get_code_analysis", {"view": "coverage", "offset": offset, "limit": 5000})
            if page["cache_stale"]:
                raise ValueError("Stale coverage cache")
            for span in page["items"]:
                begin, end = int(span["start"], 16)-pe.base, int(span["end"], 16)-pe.base
                if begin <= previous_end or not contains(captured, begin, end):
                    raise ValueError("Native coverage overlaps or escapes captured bytes")
                previous_end = end
                summed += end - begin
                coverage_hash.update(struct.pack("<QQ", begin, end))
            offset += len(page["items"])
            if offset >= page["total"]:
                break
            if not page["items"]:
                raise ValueError("Coverage pagination ended prematurely")
        if summed != result["covered_bytes"]:
            raise ValueError("Independent span union differs from native coverage count")
        report.update(result=result, analysis_wall_ms=wall, executable_sha256=capture.file_sha(Path(executable)),
                      coverage_span_audit_passed=True, decoded_captured_bytes=summed,
                      ordered_coverage_sha256=coverage_hash.hexdigest(), decoded_percent_of_original_scope=100*summed/denominator,
                      decoded_percent_of_captured_scope=100*summed/report["captured_candidate_bytes"],
                      target_70_met=summed >= (denominator*7+9)//10)


def self_test(manifest_path, report_path, executable):
    doc = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    original = Path(doc["original_path"])
    root = ROOT / ".tmp" / f"replay-module-selftest-{time.time_ns()}"
    root.mkdir(parents=True)
    checks = {}
    def rejects(name, mutate):
        altered = copy.deepcopy(doc)
        mutate(altered)
        try:
            check_manifest(altered, manifest_path, original)
        except (ValueError, OSError, TypeError, KeyError):
            checks[name] = True
        else:
            checks[name] = False
    rejects("wrong_original_hash", lambda d: d.update(source_pe_sha256="0"*64))
    rejects("missing_identity_verified", lambda d: d.pop("identity_verified_before_capture"))
    rejects("forged_loaded_timestamp", lambda d: d["loaded_identity"].update(timestamp=0))
    rejects("forged_codeview_guid", lambda d: d["module_identity"]["codeview_records"][0].update(guid="00000000-0000-0000-0000-000000000000"))
    rejects("forged_version", lambda d: d["module_identity"]["version_records"][0].update(resource_sha256="0"*64))
    rejects("wrong_payload_hash", lambda d: (d["ranges"][0].update(sha256="0"*64), d["captured_ranges"][0].update(sha256="0"*64)))
    rejects("wrong_payload_length", lambda d: d["ranges"][0].update(bytes=1))
    rejects("absolute_payload_path", lambda d: d["ranges"][0].update(output_file=str(original)))
    rejects("payload_directory_escape", lambda d: d["ranges"][0].update(output_file="../../capture-module-code.py"))
    rejects("overlapping_payloads", lambda d: (d["ranges"].append(copy.deepcopy(d["ranges"][0])), d["captured_ranges"].append(copy.deepcopy(d["captured_ranges"][0]))))
    rejects("outside_candidate_scope", lambda d: d.update(candidate_ranges=[[0, 8]]))
    rejects("guard_page_payload", lambda d: d["captured_ranges"][0].update(protection=0x120))
    rejects("false_atomic_capture", lambda d: d.update(capture_is_atomic=True))
    rejects("missing_hole_accounting", lambda d: d.pop("missing_ranges"))
    rejects("overlapping_missing_hole", lambda d: d["missing_ranges"].append({"rva_start": d["ranges"][0]["start_rva"], "rva_end": d["ranges"][0]["end_rva"], "reason": "forged", "win32_error": 299}))
    rejects("forged_capture_total", lambda d: d.update(captured_code_bytes=d["captured_code_bytes"]+1))
    rejects("forged_missing_total", lambda d: d.update(missing_code_bytes=1))
    rejects("unsupported_failed_capture", lambda d: d.update(capture_failed="read failed"))
    pe, report = prepare(manifest_path, original, root / "self.analysis.bin")
    analyze(pe, report, executable)
    checks["known_reader_manifest_accepted"] = True
    checks["independent_coverage_audit"] = report["coverage_span_audit_passed"]
    checks["unchanged_original_denominator"] = report["result"]["candidate_code_bytes"] == report["original_candidate_scope_bytes"]
    checks["capture_bounds_enforced"] = report["decoded_captured_bytes"] <= report["captured_candidate_bytes"]
    checks["source_unchanged"] = capture.file_sha(original) == doc["original_sha256"]
    checks["no_full_coverage_claim"] = report["semantic_analysis_complete"] is False
    partial_dir = root / "partial-capture"
    partial_dir.mkdir()
    partial = copy.deepcopy(doc)
    first = partial["ranges"][0]
    old_end, partial_end = first["end_rva"], first["end_rva"] - 16
    data = (Path(manifest_path).parent / first["output_file"]).read_bytes()[:-16]
    first.update(end_rva=partial_end, bytes=len(data), sha256=capture.sha(data), output_file="partial-code.bin")
    partial["captured_ranges"][0].update(rva_end=partial_end, bytes=len(data), sha256=capture.sha(data), file="partial-code.bin")
    partial["captured_code_bytes"] -= 16
    partial["missing_code_bytes"] += 16
    partial["complete_requested_code_capture"] = False
    partial["capture_coverage_percent"] = 100 * partial["captured_code_bytes"] / partial["requested_code_bytes"]
    partial["missing_ranges"].append({"rva_start": partial_end, "rva_end": old_end, "reason": "fixture_unreadable_gap", "win32_error": 299})
    (partial_dir / "partial-code.bin").write_bytes(data)
    partial_manifest = partial_dir / "manifest.json"
    partial_manifest.write_text(json.dumps(partial), encoding="utf-8")
    partial_pe, partial_report = prepare(partial_manifest, original, root / "partial.analysis.bin")
    analyze(partial_pe, partial_report, executable)
    checks["valid_unreadable_hole_accepted"] = partial_report["captured_scope_missing_bytes"] == 16
    checks["hole_never_counted"] = partial_report["decoded_captured_bytes"] <= partial_report["captured_candidate_bytes"] == doc["captured_code_bytes"] - 16
    checks["hole_keeps_original_denominator"] = partial_report["original_candidate_scope_bytes"] == report["original_candidate_scope_bytes"]
    no_hole = copy.deepcopy(partial)
    no_hole["missing_ranges"] = []
    try:
        check_manifest(no_hole, partial_manifest, original)
    except ValueError:
        checks["unaccounted_hole_rejected"] = True
    else:
        checks["unaccounted_hole_rejected"] = False
    # Unit exercise uses synthetic documented relocation bytes, not process reads.
    class RelocFixture:
        bits, base, image_size = 64, 0x140000000, 0x2000
        duplicate = False
        def directory(self, index):
            return 0x1800, 12
        def rva_bytes(self, rva, size):
            return struct.pack("<IIHH", 0x1000, 12, 0xA000, 0xA000 if self.duplicate else 0)
        def section(self, rva):
            return {"rva": 0x1000, "raw_size": 16, "raw_offset": 0}
    fixture = RelocFixture()
    runtime = 0x180000000
    reloc_image = bytearray(struct.pack("<Q", runtime + 0x1234) + bytes(8))
    adjusted, external = normalize_code_dir64(fixture, reloc_image, [[0x1000, 0x1010]], runtime)
    checks["documented_captured_dir64_normalized"] = len(adjusted) == 1 and struct.unpack_from("<Q", reloc_image)[0] == fixture.base + 0x1234 and external == 0
    untouched = bytearray(struct.pack("<Q", runtime + 0x1234) + bytes(8))
    adjusted, external = normalize_code_dir64(fixture, untouched, [[0x1008, 0x1010]], runtime)
    checks["uncaptured_dir64_not_changed"] = not adjusted and struct.unpack_from("<Q", untouched)[0] == runtime + 0x1234
    external_image = bytearray(struct.pack("<Q", runtime - 0x1000) + bytes(8))
    adjusted, external = normalize_code_dir64(fixture, external_image, [[0x1000, 0x1010]], runtime)
    checks["external_dir64_left_unknown"] = not adjusted and external == 1 and struct.unpack_from("<Q", external_image)[0] == runtime - 0x1000
    fixture.duplicate = True
    try:
        normalize_code_dir64(fixture, bytearray(struct.pack("<Q", runtime + 0x1234) + bytes(8)), [[0x1000, 0x1010]], runtime)
    except ValueError:
        checks["duplicate_dir64_rejected"] = True
    else:
        checks["duplicate_dir64_rejected"] = False
    result = {"passed": all(checks.values()), "checks": checks, "test_capture": str(manifest_path), "replay": report,
              "partial_capture_replay": partial_report,
              "target": "Previously captured self Python module only; no live process read", "roblox_70_percent_established": False}
    output = capture.output_path(report_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if not result["passed"]:
        raise ValueError("Replay importer self-test failed")
    print(json.dumps({"passed": True, "checks": len(checks), "decoded_captured_bytes": report["decoded_captured_bytes"],
                      "original_scope_bytes": report["original_candidate_scope_bytes"], "report": str(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--original-pe", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--executable", type=Path, default=ROOT / "build/Release/ScratcherMCP.exe")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-report", type=Path, default=ROOT / "reports/coverage-70/module-capture-replay-selftest.json")
    args = parser.parse_args()
    if args.self_test:
        self_test(args.manifest, args.self_test_report, args.executable)
        return
    if not args.original_pe or not args.output:
        parser.error("--original-pe and --output are required outside self-test")
    pe, report = prepare(args.manifest, args.original_pe, args.output)
    report_path = capture.output_path(args.output).with_name(args.output.name.replace(".analysis.bin", "-capture-replay.json"))
    try:
        analyze(pe, report, args.executable)
    except BaseException as ex:
        report["analysis_failed"] = str(ex)
        raise
    finally:
        report["source_file_unchanged"] = capture.file_sha(args.original_pe) == report["original_sha256"]
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("decoded_captured_bytes", "decoded_percent_of_original_scope", "target_70_met")}))
    print(report_path)


if __name__ == "__main__":
    main()
