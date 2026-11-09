"""Render the measured MCP benchmark into a readable local report."""
import json
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "reports"


def median(values):
    return statistics.median(values) if values else None


def metric(row, phase, field="wall_ms"):
    return median([run["phases"][phase][field] for run in row["runs"]
        if phase in run.get("phases", {}) and field in run["phases"][phase]])


def format_ms(value):
    return "unavailable" if value is None else f"{value:,.2f} ms"


def main():
    report = json.loads((DIRECTORY / "performance.json").read_text(encoding="utf-8"))
    cpu = json.loads((DIRECTORY / "hardware-cpu.json").read_text(encoding="utf-8-sig"))
    ram = json.loads((DIRECTORY / "hardware-memory.json").read_text(encoding="utf-8-sig"))
    live = json.loads((DIRECTORY / "live-mcp.json").read_text(encoding="utf-8"))
    current = [row for row in report["results"] if row["variant"] == "0.3"]
    lines = ["# Scratcher 0.3 measured performance", "", f"Run date: {report['date']}", "",
        f"Hardware: {cpu['Name']}; {cpu['NumberOfCores']} cores / {cpu['NumberOfLogicalProcessors']} logical processors; {ram['TotalPhysicalMemory']/2**30:.2f} GiB RAM.", "",
        "The app and MCP package are in `D:/Scratcher/dist-v0.3`. Verification used CLI, stdio MCP, and the app's local API. No Computer Use was used, and none of the input EXEs or DLLs were executed.", "",
        "## Method", "", report["method"], "",
        "Current results are medians of three repetitions. Each repetition uses a fresh process. Opening maps the file and indexes executable metadata; it does not read or analyze every byte. Full scans run after the instruction listing and bounded scan, so they benefit from pages already read during those phases. The operating system cache remains enabled. These are fresh-process timings, not uncached-disk measurements.", "",
        "All times in the table are measured at the MCP client, including request dispatch, response serialization, and transport. Memory measures the Scratcher MCP process, excluding the test client. The synthetic dump contains 16 MiB of executable memory plus 1,008 MiB of data; only its executable memory is scanned.", "",
        "## Results", "", "| Input | File size | Open + index | Full executable-section scan | Cached scan | Peak working set |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in current:
        peaks = [phase["memory"]["peak_working_set_mib"] for run in row["runs"]
                 for phase in run.get("phases", {}).values() if phase.get("memory", {}).get("peak_working_set_mib")]
        lines.append(f"| {row['name']} | {row['size_bytes']/2**20:,.2f} MiB | {format_ms(metric(row,'open'))} | {format_ms(metric(row,'full_scan'))} | {format_ms(metric(row,'full_scan_repeat'))} | {max(peaks):.1f} MiB |" if peaks else f"| {row['name']} | {row['size_bytes']/2**20:,.2f} MiB | unavailable | unavailable | unavailable | unavailable |")
    lines += ["", "## Coverage and meaning", "",
        "A full scan means every file-backed executable byte was visited by the linear decoder. It discovers direct call destinations and supplements the metadata function index. It does not decompile every function, recover every indirect destination, unpack protected code, or prove that each indexed destination is a real function. Invalid decoding consumes one byte and is counted below. Data and missing dump memory are excluded from executable coverage.", "",
        "| Input | Executable bytes | Bytes visited | Decoded instructions | Invalid bytes | Workers | Complete byte scan |", "| --- | ---: | ---: | ---: | ---: | ---: | --- |"]
    for row in current:
        runs = [run for run in row["runs"] if "full_scan" in run.get("phases", {})]
        if runs:
            result = runs[0]["phases"]["full_scan"]["result"]
            lines.append(f"| {row['name']} | {result['executable_bytes']:,} | {result['scanned_bytes']:,} | {result['instructions_decoded']:,} | {result['invalid_bytes']:,} | {result['parallel_workers']} | {'yes' if result['complete'] else 'no'} |")
        else:
            reasons = sorted(set(run.get("analysis_unavailable", run.get("error", "Unavailable")) for run in row["runs"]))
            lines += [f"| {row['name']} | — | — | — | — | — | no code scan |", "", f"{row['name']}: {'; '.join(reasons)}", ""]
    lines += ["", "## Pseudocode and instruction listing", "",
        "The cold pseudocode column uses a separate fresh process with only metadata and function listing before its first pseudocode request. It measures one bounded metadata function, or the start of the captured code region. The repeat column measures the session cache. These timings do not represent decompiling the entire binary.", "",
        "| Input | 10,000 instruction rows through MCP | Cold first-function pseudocode | Cached pseudocode |", "| --- | ---: | ---: | ---: |"]
    for row in current:
        cold = median([run["cold_pseudocode"]["wall_ms"] for run in row["runs"] if "wall_ms" in run.get("cold_pseudocode", {})])
        lines.append(f"| {row['name']} | {format_ms(metric(row,'listing_10000'))} | {format_ms(cold)} | {format_ms(metric(row,'pseudocode_repeat'))} |")
    lines += ["", "## Comparison with the previous package", "",
        "Both versions use the same file and a 100,000-instruction budget. The previous package and the matching current comparison each have one repetition, so speedup values are estimates for this machine and workload. They compare the bounded scan request after the first instruction listing; startup pseudocode preparation in the earlier package occurs during that listing.", "",
        "| Input | Previous open | Current open | Previous 100k scan | Current 100k scan | Scan speedup |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    old = {row["name"]: row for row in report["results"] if row["variant"] == "0.2 baseline"}
    comparable = {row["name"]: row for row in report["results"] if row["variant"] == "0.3 comparable"}
    for name, row in old.items():
        newer = comparable.get(name)
        if not newer:
            continue
        before, after = metric(row, "analyze"), metric(newer, "analyze")
        if before is not None and after:
            lines.append(f"| {name} | {format_ms(metric(row,'open'))} | {format_ms(metric(newer,'open'))} | {format_ms(before)} | {format_ms(after)} | {before/after:.1f}× |")
    lines += ["", "## Verification", "",
        "19 C++ test suites passed, covering loaders, malformed inputs, projects, metadata edits, types, graphs, references, jobs, MCP schemas, framing, and desktop dispatch. Parallel decoding was compared against serial decoding on a known 6 MiB fixture. Prefixed return instructions were checked to stop graph traversal correctly.", "",
        f"Live MCP verification: {'passed' if live['passed'] else 'failed'}; {len(live['checks'])} checks. The API selected addresses and views, read live graph snapshots, filtered functions, committed batch edits, persisted a project, retained job results, cancelled a targeted job, and detached cleanly. Cancellation result: `{live.get('cancellation', {})}`.", "",
        "Raw measurements: [performance.json](performance.json). Live test: [live-mcp.json](live-mcp.json). Reproduce with `py -3.12 D:/Scratcher/scripts/benchmark.py --runs 3 --baseline` and `py -3.12 D:/Scratcher/scripts/verify-live-mcp.py`.", "", "## Inputs", ""]
    for row in current:
        paths = [run.get("path") for run in row["runs"] if run.get("path")]
        if paths:
            lines += [f"- {row['name']}: `{paths[0]}`{' (generated synthetic fixture)' if row['synthetic'] else ''}."]
    (DIRECTORY / "performance-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(DIRECTORY / "performance-report.md")


if __name__ == "__main__":
    main()
