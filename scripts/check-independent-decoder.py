"""Compare independent instruction decoding at unchanged metadata-backed samples.

This diagnostic neither resynchronizes across invalid bytes nor adds coverage.
"""
import hashlib
import importlib
import json
from pathlib import Path
import sys

ROOT = Path("D:/Scratcher")
sys.path.insert(0, str(ROOT / ".tmp/independent-decode"))
from iced_x86 import Code, Decoder
from mcp_client import Client

helper = importlib.import_module("diagnose-roblox-code")
benchmark = importlib.import_module("benchmark-coverage-target")


def compare(path, addresses, provenance):
    pe = helper.PE(path)
    stats = dict(sampled_entries=len(addresses), compared_instructions=0,
                 native_rejected_instructions=0, independently_rejected_native_failures=0,
                 native_failure_accepted_independently=0, validity_disagreements=0,
                 length_disagreements=0, samples_with_native_failure=0,
                 samples_with_independent_failure=0, native_failure_at_first_instruction=0)
    samples = []
    with Client(ROOT / "build/Release/ScratcherMCP.exe") as client:
        client.tool("open_binary", {"path": str(path)})
        for entry in addresses:
            listing = client.tool("disassemble", {"address": hex(entry), "count": 32})["instructions"]
            observations = []
            native_failed = independent_failed = False
            for index, row in enumerate(listing):
                va = int(row["address"], 16)
                code = pe.bytes(va, 15)
                if len(code) < 15:
                    # Avoid attributing a section-end truncation to decoder behavior.
                    break
                native_valid = row["mnemonic"].upper() not in ("DB", "INVALID", "UNDEFINED")
                decoder = Decoder(64, code, ip=va)
                inst = decoder.decode()
                independent_valid = inst.code != Code.INVALID
                stats["compared_instructions"] += 1
                stats["validity_disagreements"] += native_valid != independent_valid
                stats["length_disagreements"] += native_valid and independent_valid and row["length"] != inst.len
                if not native_valid:
                    stats["native_rejected_instructions"] += 1
                    stats["independently_rejected_native_failures"] += not independent_valid
                    stats["native_failure_accepted_independently"] += independent_valid
                    stats["native_failure_at_first_instruction"] += index == 0
                observations.append(dict(address=hex(va), available_original_bytes=code.hex(),
                    native_valid=native_valid, native_length=row["length"], native_mnemonic=row["mnemonic"],
                    independent_valid=independent_valid,
                    independent_length=inst.len if independent_valid else None,
                    independent_instruction=str(inst) if independent_valid else None))
                native_failed |= not native_valid
                independent_failed |= not independent_valid
                if not native_valid or not independent_valid:
                    break  # No invalid-byte skipping or invented instruction alignment.
            stats["samples_with_native_failure"] += native_failed
            stats["samples_with_independent_failure"] += independent_failed
            samples.append(dict(entry=hex(entry), observations=observations))
    return dict(path=str(path), sha256=pe.digest, provenance=provenance, counters=stats, samples=samples)


def main():
    original = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
    image_report = json.loads((ROOT / "reports/coverage-70/existing-code-image-discovery-32.json").read_text())
    image = Path(image_report["analysis_image"])
    if benchmark.digest(original) != benchmark.EXPECTED or benchmark.digest(image) != image_report["analysis_image_sha256"]:
        raise ValueError("Diagnostic input hashes changed")
    pe = helper.PE(original)
    cfg, metadata = pe.cfg()
    entries = [row["va"] for row in helper.evenly(cfg, 256)]
    report = dict(method="256 stratified original Guard CF starts per byte source, at most 32 instructions per start; each decoder gets the same full 15 file-backed bytes. Stop at first rejection by either decoder; never resynchronize.",
        metadata=metadata, original_candidate_scope_bytes=102242816,
        executable_sha256=benchmark.digest(ROOT / "build/Release/ScratcherMCP.exe"),
        independent_decoder=dict(name="iced-x86", version="1.21.0", bits=64, options="default strict decoding",
            documentation="https://github.com/icedland/iced/blob/master/src/rust/iced-x86-py/README.md",
            package="https://pypi.org/project/iced-x86/1.21.0/"),
        target_70_verified=False, coverage_added_bytes=0, inputs_executed=False,
        process_reads_performed=False, sources=[])
    before = {str(path): benchmark.digest(path) for path in (original, image)}
    report["sources"].append(compare(original, entries, "Exact original immutable executable"))
    report["sources"].append(compare(image, entries, "Conditional raw image with unverified acquisition; original metadata unchanged"))
    after = {path: benchmark.digest(Path(path)) for path in before}
    report["inputs_unchanged"] = before == after
    report["limitations"] = ["A stratified sample is not an exhaustive decoder equivalence test.",
        "Agreement on invalid encodings does not establish encryption or its cause.",
        "Valid instruction decoding is not proof of code execution, semantic correctness or raw-source identity.",
        "Native listings use the full decoder; the automatic path pass uses instruction decoding and then branch operand decoding.",
        "The raw image remains conditional; no new code, seeds or recovery percentage is credited by this check."]
    if before != after:
        raise ValueError("Input changed during independent decoder check")
    output = ROOT / "reports/coverage-70/independent-decoder.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps([source["counters"] for source in report["sources"]], indent=2))
    print(output)


if __name__ == "__main__":
    main()
