"""Produce a reproducible release report from the measured verification artifacts."""
import json
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "reports/v0.4"


def main():
    report = json.loads((DIRECTORY / "performance.json").read_text(encoding="utf-8"))
    before = json.loads((DIRECTORY / "performance-before-streaming.json").read_text(encoding="utf-8"))
    live = json.loads((DIRECTORY / "live-mcp.json").read_text(encoding="utf-8"))
    stdio = json.loads((DIRECTORY / "stdio-mcp.json").read_text(encoding="utf-8-sig"))
    cpu = json.loads((ROOT / "reports/hardware-cpu.json").read_text(encoding="utf-8-sig"))
    ram = json.loads((ROOT / "reports/hardware-memory.json").read_text(encoding="utf-8-sig"))
    test_log = (ROOT / "reports/tests-v0.4.log").read_text(encoding="utf-8-sig")
    assert "100% tests passed out of 30" in test_log
    assert live["passed"] and stdio["tool_count"] == 135
    assert len(report["results"]) == 6
    for row in report["results"]:
        assert len(row["runs"]) == 3
        assert row["persistence"]["restored_scan_cached"]
        assert row["persistence"]["restored_pseudocode_cached"]
        for run in row["runs"]:
            scan = run["phases"]["full_scan"]["result"]
            assert scan["complete"] and scan["scanned_bytes"] == scan["executable_bytes"]
    lines = ["# Scratcher 0.4 upgrade and measured performance", "", f"Benchmark date: {report['date']}", "",
        "Package: `D:/Scratcher/dist-v0.4`. Native C++ Windows x64 application and stdio MCP companion. The upgrade adds 135 built-in MCP tools, plus explicitly loaded native extension tools. Full IDA Pro feature parity is still unfinished.", "",
        "## Delivered", "",
        "- Bounded reachable x86/x64 analysis: constants, stack effects, fixed read-only indirect pointers, guarded jump-table candidates, and explicit unresolved paths.",
        "- Manual code/data definitions, function creation/deletion/bounds/split/merge, operand formatting, switch corrections, and segment names/access flags.",
        "- Structures, unions, enums, aliases, pointers and arrays with ABI layout; bounded C declaration import and reusable type libraries.",
        "- Explicit local PDB import with GUID/age verification, embedded uncompressed DWARF 2–4, symbol maps, and persistent source-line lookups.",
        "- Trainable/importable masked function signatures with ambiguity and evidence reporting; two sourced starter patterns.",
        "- ARM64, ARM/Thumb, RISC-V 32/64 and MIPS 32/64 decoding and pseudocode alongside x86/x64. PE, ELF, thin/universal Mach-O, raw inputs, and user-mode minidumps.",
        "- Local Windows x64 debugger: launch/attach, pause/continue, instruction step/trace, software breakpoints, integer registers, live memory, modules/threads, stack unwinding, and sampled watches.",
        "- Pseudocode instruction links, storage-preserving variable renames, call-site prototypes, indirect-call overrides, goto and jump hints, and per-function options.",
        "- Persistent resizable split panes, optional synchronized preview, paginated browsing over the entire function index, cached graphs with clipping/minimap/pan/zoom, and advanced Workbench forms.",
        "- Embedded Lua with validated tool calls, resource limits, cancellation and captured output; native C ABI extensions, events, sample DLL and SDK documentation.",
        "- Compressed atomic analysis databases with SHA-256 validation and bounded persistent caches; session undo/redo for supported edits.", "",
        "## Verification", "",
        f"30/30 C++ suites passed. Live MCP verification passed {len(live['checks'])} checks, including exact-session attachment, navigation, asynchronous jobs, cancellation, annotations, type undo/redo, scripting, extension callbacks and project round trips. Stdio MCP lifecycle/schema/framing checks also passed with {stdio['tool_count']} tools.", "",
        "Debugger verification passed 57 checks using only a self-built fixture. Large input executables and DLLs were never executed. All verification used CLI, stdio MCP and local named pipes; no Computer Use. UI layout/state and graph behavior were tested programmatically; visual appearance was not inspected through desktop automation.", "",
        f"Hardware: {cpu['Name']}, {cpu['NumberOfCores']} cores / {cpu['NumberOfLogicalProcessors']} logical processors, {ram['TotalPhysicalMemory']/2**30:.2f} GiB RAM.", "",
        "## Method", "", report["method"], "",
        "Opening maps a file and indexes metadata; it does not analyze all bytes. Full scans visit file-backed executable sections after instruction listing and a bounded scan. They benefit from those pages already being read. A full linear scan is not whole-program semantic recovery or full-binary decompilation. OS cache stays enabled; these are fresh-process measurements, not cold-disk timings. Each table value below is a median of three runs unless otherwise stated.", "",
        "## Loading and scanning", "",
        "| Input | File MiB | Open + index ms | Full linear scan ms | Cached scan ms | Scan-process peak MiB |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in report["results"]:
        peaks = [phase["memory"]["peak_working_set_mib"] for run in row["runs"] for phase in run["phases"].values() if "memory" in phase]
        m = row["medians"]
        lines.append(f"| {row['name']} | {row['size_bytes']/2**20:.2f} | {m['open']:.2f} | {m['full_scan']:.2f} | {m['full_scan_repeat']:.2f} | {max(peaks):.1f} |")
    lines += ["", "## Exact executable-byte coverage", "",
        "| Input | Executable bytes | Bytes visited | Decoded instructions | Invalid bytes | Workers |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in report["results"]:
        scan = row["runs"][0]["phases"]["full_scan"]["result"]
        lines.append(f"| {row['name']} | {scan['executable_bytes']:,} | {scan['scanned_bytes']:,} | {scan['instructions_decoded']:,} | {scan['invalid_bytes']:,} | {scan['parallel_workers']} |")
    lines += ["", "The synthetic dump contains 16 MiB of executable code and 1008 MiB of sparse data. Its scan timing measures the 16 MiB code region. The real Unreal crash dump is approximately 0.6 MiB and has only 1,792 captured executable bytes. Neither represents scanning 1 GiB of real executable code. Invalid decoding consumes a byte and is counted; call discoveries can include candidates that need manual correction.", "",
        "## First-function pseudocode", "",
        "Each cold result uses another fresh process and one small bounded metadata function (or captured region start). These samples do not establish accuracy or throughput for decompiling every function.", "",
        "| Input | Cold pseudocode ms | Cached pseudocode ms |",
        "| --- | ---: | ---: |"]
    for row in report["results"]:
        cold = [run["cold_pseudocode"]["wall_ms"] for run in row["runs"] if "wall_ms" in run.get("cold_pseudocode", {})]
        repeat = [run["phases"]["pseudocode_repeat"]["wall_ms"] for run in row["runs"] if "wall_ms" in run["phases"].get("pseudocode_repeat", {})]
        lines.append(f"| {row['name']} | {statistics.median(cold):.2f} | {statistics.median(repeat):.2f} |")
    lines += ["", "## Database persistence", "",
        "Save/restore values are single fresh-session measurements and include full-file SHA-256 verification. All six databases restored retained full-scan reports and pseudocode cache entries. Checksums stream through a 1 MiB buffer against the already-open file handle. Databases store bounded derived results and reference the original input; they do not embed the input bytes.", "",
        "| Input | Database MiB | Save ms | Restore ms | Save peak MiB | Restore peak MiB |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in report["results"]:
        p = row["persistence"]
        lines.append(f"| {row['name']} | {p['size_bytes']/2**20:.3f} | {p['save_wall_ms']:.2f} | {p['restore_wall_ms']:.2f} | {p['memory_after_save']['peak_working_set_mib']:.1f} | {p['memory_after_restore']['peak_working_set_mib']:.1f} |")
    old_dump = next(row for row in before["results"] if row["synthetic"])["persistence"]
    new_dump = next(row for row in report["results"] if row["synthetic"])["persistence"]
    lines += ["", f"For the synthetic 1 GiB dump, streaming checksum verification reduced measured save-process peak from {old_dump['memory_after_save']['peak_working_set_mib']:.1f} to {new_dump['memory_after_save']['peak_working_set_mib']:.1f} MiB and restore-process peak from {old_dump['memory_after_restore']['peak_working_set_mib']:.1f} to {new_dump['memory_after_restore']['peak_working_set_mib']:.1f} MiB. These are one run before/after on the same machine, not guaranteed maxima.", "",
        "Database limits: 64 MiB compressed / 256 MiB expanded; pseudocode cache 16 MiB; requested instruction pages and graphs 8 MiB each; reachable-analysis cache 32 entries / 8 MiB. Undo history stays in the current session, up to 128 records / 32 MiB. Batches and scripts are ordered but not transactional.", "",
        "## Deep-analysis samples", "",
        "Up to three small indexed functions per workload were checked separately with a 512-instruction budget. Results distinguish cache hits, truncation, unresolved paths and semantic completeness. Every result still reports semantic_analysis_complete=false: this is bounded local reasoning, not proof of complete program semantics. The chosen functions are tiny; the raw artifact retains instruction counts and issues. This is no substitute for a labeled accuracy corpus.", "",
        "## Remaining gaps", "",
        "- Whole-program dataflow, comprehensive C++ class/RTTI/vtable/exception reconstruction, automatic unpacking, and a broad validated library-signature corpus.",
        "- Variable lifetime splitting/merging, program rebasing and virtual mapping edits, arbitrary window docking, and a mature incremental database.",
        "- Remote/WOW64/kernel debugging, source stepping, step-over/out, conditional/hardware breakpoints, and SIMD register editing. Watches currently sample at debugger stops.",
        "- Linux/macOS application builds, big-endian inputs, mixed ARM/Thumb regions, dyld shared caches, and kernel crash dumps.",
        "- DWARF5/compressed/separate debug information, debug-type import, C preprocessor/C++ header import, bitfields and packed layouts.",
        "- IDAPython compatibility and low-level IR extension hooks. Native extensions are trusted code; callbacks remain cooperative. Attached clients invoke extensions through call_plugin; dynamic names are exposed to independent local workspaces.", "",
        "## Artifacts and reproduction", "",
        "- [Raw measurements](D:/Scratcher/reports/v0.4/performance.json)",
        "- [Live MCP checks](D:/Scratcher/reports/v0.4/live-mcp.json)",
        "- [Stdio MCP checks](D:/Scratcher/reports/v0.4/stdio-mcp.json)",
        "- [C++ test log](D:/Scratcher/reports/tests-v0.4.log)",
        "- [SDK documentation](D:/Scratcher/dist-v0.4/sdk/sdk.md)", "",
        "Run scripts/build.ps1, scripts/verify-mcp.ps1, scripts/verify-live-mcp.py, scripts/benchmark-v0.4.py and scripts/report-v0.4.py from D:/Scratcher. Python scripts need an installed Python interpreter. Benchmarks use the existing local input paths; generated data lives under benchmark-inputs. Earlier packages and reports remain available.", ""]
    (DIRECTORY / "upgrade-report.md").write_text("\n".join(lines), encoding="utf-8")
    print(DIRECTORY / "upgrade-report.md")


if __name__ == "__main__":
    main()
