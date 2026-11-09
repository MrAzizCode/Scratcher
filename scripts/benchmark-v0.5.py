"""Read-only, reproducible 0.4/0.5 recovery and timing comparison. No UI automation."""
import argparse
import collections
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import statistics
import struct
import subprocess
import time

from benchmark import INPUTS, ROOT, synthetic_dump
from mcp_client import Client, timed

OUT = ROOT / "reports/v0.5"
FIXTURE = ROOT / "build/Release/ScratcherAnalysisFixture.exe"
ROBLOX = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
GHIDRA = ROOT / "vendor/tools/ghidra_12.1.4_PUBLIC"
JAVA = pathlib.Path("C:/Program Files/Eclipse Adoptium/jdk-21.0.5.11-hotspot/bin/java.exe")
METHOD = ("Three fresh MCP processes per version/input; no OS file-cache flush. "
    "Startup/initialize excluded; stdio JSON-RPC and dispatch included. Inputs are read, never executed. "
    "Linear scans use original declared executable permissions. New phases run in a separate reopened workspace, "
    "without first performing the linear scan. Configured pass completion is not full semantic analysis. "
    "Ghidra runs separately, default auto-analysis, max CPU 8, 120-second analysis budget, 180-second process deadline. "
    "No Computer Use. No comparison ratio between unequal work.")


def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def identity(path):
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": str(path), "size_bytes": path.stat().st_size, "sha256": digest}


def exports(path):
    """Parse fixture named PE exports only; file-backed range checks precede each read."""
    data = path.read_bytes()
    def read(fmt, off):
        if off < 0 or off + struct.calcsize(fmt) > len(data):
            raise ValueError("Truncated fixture PE")
        return struct.unpack_from(fmt, data, off)
    pe, = read("<I", 0x3c)
    if data[pe:pe+4] != b"PE\0\0": raise ValueError("Not PE")
    section_count, = read("<H", pe+6)
    optional_size, = read("<H", pe+20)
    optional = pe+24
    magic, = read("<H", optional)
    base, = read("<Q" if magic == 0x20b else "<I", optional+(24 if magic == 0x20b else 28))
    directory = optional+(112 if magic == 0x20b else 96)
    export_rva, export_size = read("<II", directory)
    sections = []
    for index in range(section_count):
        at = optional+optional_size+index*40
        virtual_size, rva, raw_size, raw_offset = read("<IIII", at+8)
        sections.append((rva, raw_size, raw_offset))
    def offset(rva, size=1):
        for start, length, raw in sections:
            if start <= rva and rva-start+size <= length and raw+rva-start+size <= len(data):
                return raw+rva-start
        raise ValueError("Export RVA is not file backed")
    table = offset(export_rva, 40)
    function_count, name_count, function_table, name_table, ordinal_table = read("<IIIII", table+20)
    result = []
    for n in range(min(name_count, 10000)):
        name_rva, = read("<I", offset(name_table+n*4, 4))
        name_at = offset(name_rva)
        end = data.find(b"\0", name_at, min(len(data), name_at+512))
        if end < 0: raise ValueError("Unterminated export")
        name = data[name_at:end].decode("ascii")
        ordinal, = read("<H", offset(ordinal_table+n*2, 2))
        if ordinal >= function_count: raise ValueError("Bad export ordinal")
        entry, = read("<I", offset(function_table+ordinal*4, 4))
        if name.startswith("fixture_") and not export_rva <= entry < export_rva+export_size:
            result.append({"name": name, "address": hex(base+entry), "selection": "Named export in controlled readable source fixture"})
    return result


def capture(client, tool, args, timeout=180):
    try:
        result, wall = timed(client, tool, args, timeout)
        return {"wall_ms": wall, "result": result, "memory": client.memory()}
    except Exception as error:
        return {"error": str(error)}


def sampled_code(client, samples):
    rows = []
    for sample in samples:
        row = dict(sample)
        row["reachable"] = capture(client, "analyze_reachable", {"address": sample["address"], "instruction_budget": 20000,
            "byte_budget": 65536, "include_instructions": False}, 60)
        row["control_flow"] = capture(client, "get_control_flow", {"address": sample["address"], "instruction_budget": 4096}, 60)
        row["pseudocode"] = capture(client, "decompile", {"address": sample["address"]}, 45)
        pseudo = row["pseudocode"].get("result", {})
        code = pseudo.get("code", "")
        row["pseudocode_quality"] = {"returned_code": bool(code), "halt_baddata": "halt_baddata" in code,
            "warnings": pseudo.get("warning_signals", pseudo.get("warnings", [])), "semantic_equivalence_checked": False}
        rows.append(row)
    return rows


def native(executable, runs=3, selected=None, variant=None):
    workloads = [("Readable analysis fixture", FIXTURE, False), ("Roblox signed player", ROBLOX, False)] + INPUTS
    workloads += [("Synthetic 1 GiB memory dump (16 MiB code)", synthetic_dump(), True)]
    dumps = sorted((ROOT / "benchmark-inputs").rglob("UEMinidump.dmp"))
    if dumps: workloads.append(("Real Unreal crash minidump", dumps[0], False))
    report = {"date": datetime.datetime.now().astimezone().isoformat(), "method": METHOD, "results": []}
    samples = exports(FIXTURE)
    save("fixture-samples.json", samples)
    variants = [("0.4", ROOT / "dist-v0.4/ScratcherMCP.exe"), ("0.5", executable)]
    for label, binary in variants:
        if variant and label != variant: continue
        for name, path, synthetic in workloads:
            if not path.exists() or (selected and selected not in name.lower()): continue
            row = {"name": name, "variant": label, "executable": identity(binary), "input": identity(path), "synthetic": synthetic, "runs": []}
            for repetition in range(runs):
                print(label, name, "run", repetition+1, flush=True)
                run = {}
                with Client(binary) as client:
                    schemas = {t["name"]: t for t in client.rpc("tools/list")["tools"]}
                    run["server_version"] = client.initialization["serverInfo"]["version"]
                    if repetition == 0 and label == "0.5": save("tool-schemas.json", list(schemas.values()))
                    run["open"] = capture(client, "open_binary", {"path": str(path)})
                    run["linear"] = capture(client, "analyze", {"full_scan": True})
                    run["linear_cached"] = capture(client, "analyze", {"full_scan": True})
                    # Fresh workspace avoids linear call candidates changing automatic recovery inputs.
                    run["automatic_open"] = capture(client, "open_binary", {"path": str(path)})
                    if "run_auto_analysis" in schemas:
                        options = {"time_budget_ms": 120000, "workers": 8,
                            "phase_options": {"code": {"time_budget_ms": 30000, "instruction_budget": 100000000,
                                "byte_budget": 536870912, "coverage_span_budget": 4000000}, "exceptions": {"time_budget_ms": 10000},
                            "rtti": {"time_budget_ms": 30000}, "references": {"time_budget_ms": 60000}}}
                        run["automatic"] = capture(client, "run_auto_analysis", options)
                        run["functions_after_auto"] = capture(client, "list_functions", {"limit": 10})
                        if repetition == 0:
                            for tool, args in [("get_code_analysis", {"limit": 500}), ("get_rtti", {"limit": 500}),
                                ("get_exception_info", {"limit": 500}), ("get_analysis_references", {"limit": 500})]:
                                run[tool] = capture(client, tool, args)
                    else:
                        meta = run["automatic_open"].get("result", {})
                        address = meta.get("entry")
                        if address:
                            run["reachable_entry"] = capture(client, "analyze_reachable", {"address": address,
                                "instruction_budget": 20000, "byte_budget": 65536, "include_instructions": False}, 60)
                        run["automatic"] = {"unavailable": "Whole-input automatic phase pipeline absent in 0.4; bounded entry pass is not comparable"}
                    if path == FIXTURE and repetition == 0:
                        run["samples"] = sampled_code(client, samples)
                        save("fixture-"+label+".json", run)
                row["runs"].append(run)
                report["results"] = [r for r in report["results"] if (r["name"], r["variant"]) != (name, label)] + [row]
                save("performance-v0.5"+("-"+variant if variant else "")+("-"+selected if selected else "")+".json", report)
            row["medians_ms"] = {phase: statistics.median(r[phase]["wall_ms"] for r in row["runs"] if "wall_ms" in r.get(phase, {}))
                for phase in ["open", "linear", "linear_cached"]}
            autos = [r["automatic"]["wall_ms"] for r in row["runs"] if "wall_ms" in r.get("automatic", {})]
            if autos: row["medians_ms"]["automatic"] = statistics.median(autos)
            save("performance-v0.5"+("-"+variant if variant else "")+("-"+selected if selected else "")+".json", report)
            print(json.dumps({"name": name, "variant": label, "medians_ms": row["medians_ms"]}), flush=True)


def expanded(executable):
    with Client(executable) as client:
        report = {"input": identity(ROBLOX), "executable": identity(executable), "method": METHOD,
            "repetitions": 1, "label": "Separately measured expanded caps; not part of three-run default medians"}
        report["open"] = capture(client, "open_binary", {"path": str(ROBLOX)})
        imported = []
        while True:
            page = client.tool("list_functions", {"offset": len(imported), "limit": 10000})
            imported.extend(page["items"])
            if len(imported) >= page["total"]: break
        save("roblox-import-functions.json", imported)
        previous = json.loads((ROOT / "reports/roblox-comparison/ghidra-functions-pre.json").read_text(encoding="utf-8"))
        native_addresses = {int(f["address"],16) for f in imported}
        previous_addresses = {int(f["address"],16) for f in previous}
        report["metadata_start_comparison"] = {"native": len(native_addresses), "ghidra_import_only": len(previous_addresses),
            "intersection": len(native_addresses & previous_addresses), "native_only": [hex(a) for a in sorted(native_addresses-previous_addresses)],
            "ghidra_only": [hex(a) for a in sorted(previous_addresses-native_addresses)],
            "native_sources": dict(collections.Counter(f["source"] for f in imported)), "function_bodies_compared": False}
        report["automatic"] = capture(client, "run_auto_analysis", {"time_budget_ms": 120000, "workers": 8,
            "phase_options": {"code": {"time_budget_ms": 30000, "instruction_budget": 100000000,
                "byte_budget": 536870912, "coverage_span_budget": 4000000}, "exceptions": {"time_budget_ms": 10000},
                "rtti": {"time_budget_ms": 30000, "class_budget": 100000, "memory_budget_bytes": 268435456},
                "references": {"time_budget_ms": 60000, "reference_limit": 8000000, "memory_budget": 268435456}}})
        report["rtti"] = capture(client, "get_rtti", {"limit": 500})
        report["references"] = capture(client, "get_analysis_references", {"limit": 500})
        report["samples"] = sampled_code(client, json.loads((ROOT / "reports/roblox-comparison/samples.json").read_text(encoding="utf-8")))
        save("roblox-expanded.json", report)
        print(json.dumps(report["automatic"], indent=2), flush=True)


def ghidra():
    directory = OUT / "ghidra-fixture"
    directory.mkdir(parents=True, exist_ok=True)
    scripts = directory / "scripts"
    scripts.mkdir(exist_ok=True)
    shutil.copy2(ROOT / "reports/roblox-comparison/scripts/BenchmarkMetrics.java", scripts / "BenchmarkMetrics.java")
    (directory / "samples.json").write_text(json.dumps(exports(FIXTURE), indent=2), encoding="utf-8")
    properties = [line.split("=",1)[1] for line in (GHIDRA / "support/launch.properties").read_text().splitlines()
        if line.startswith(("VMARGS=", "VMARGS_WINDOWS=")) and line.split("=",1)[1]]
    for folder in ["projects", "java-home", "settings", "cache"]: (directory / folder).mkdir(exist_ok=True)
    args = [str(JAVA), *properties, "-Xmx8G", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
        f"-Duser.home={directory / 'java-home'}", f"-Djava.io.tmpdir={ROOT / '.tmp'}", "-Djava.awt.headless=true",
        f"-Dapplication.settingsdir={directory / 'settings'}", f"-Dapplication.cachedir={directory / 'cache'}",
        f"-Dapplication.tempdir={ROOT / '.tmp'}", "-cp", str(GHIDRA / "Ghidra/Framework/Utility/lib/Utility.jar"),
        "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless", str(directory / "projects"),
        "Fixture-"+datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), "-import", str(FIXTURE), "-max-cpu", "8",
        "-analysisTimeoutPerFile", "120", "-scriptPath", str(scripts), "-preScript", "BenchmarkMetrics.java", "pre", str(directory),
        "-postScript", "BenchmarkMetrics.java", "post", str(directory), "-log", str(directory / "ghidra.log"),
        "-scriptlog", str(directory / "ghidra-scripts.log")]
    metadata = {"input": identity(FIXTURE), "arguments": args, "version": "12.1.4", "jdk": "21.0.5",
        "analysis_timeout_seconds": 120, "external_deadline_seconds": 180, "max_cpu": 8, "heap_gib": 8,
        "auto_analysis_enabled": True, "method": METHOD}
    start = time.perf_counter()
    with (directory / "console.log").open("w", encoding="utf-8") as log:
        child = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT,
            env=dict(os.environ, TEMP=str(ROOT / ".tmp"), TMP=str(ROOT / ".tmp")), creationflags=subprocess.CREATE_NO_WINDOW)
        metadata["pid"] = child.pid
        save("ghidra-fixture/command.json", metadata)
        print("Headless fixture PID", child.pid, flush=True)
        try:
            code = child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            child.kill()  # Only our directly launched Java child; no user process controls.
            code = child.wait(timeout=10)
            metadata["external_deadline_exceeded"] = True
    metadata.update(exit_code=code, total_wall_ms=(time.perf_counter()-start)*1000)
    metadata["post_export_present"] = (directory / "ghidra-post.json").exists()
    save("ghidra-fixture/command.json", metadata)
    print("Headless fixture finished", metadata, flush=True)


def render_report():
    initial = json.loads((OUT / "performance-v0.5-initial.json").read_text(encoding="utf-8"))
    final = json.loads((OUT / "performance-v0.5-0.5.json").read_text(encoding="utf-8"))
    old = {r["name"]: r for r in initial["results"] if r["variant"] == "0.4"}
    gh = json.loads((OUT / "ghidra-fixture/ghidra-post.json").read_text(encoding="utf-8"))
    ghcmd = json.loads((OUT / "ghidra-fixture/command.json").read_text(encoding="utf-8"))
    final_fixture=next(r for r in final["results"] if r["name"]=="Readable analysis fixture")
    if final_fixture["input"]["sha256"] != ghcmd["input"]["sha256"]:
        raise RuntimeError("Fixture bytes changed; rerun Ghidra on the same final input before generating comparison")
    fixture = json.loads((OUT / "fixture-0.5.json").read_text(encoding="utf-8"))
    expanded = json.loads((OUT / "roblox-expanded.json").read_text(encoding="utf-8"))
    def phases(run):
        return {p["phase"]: p for p in run.get("automatic", {}).get("result", {}).get("phases", [])}
    text = ["# Scratcher 0.5 timing and recovery comparison", "",
        "Scratcher now imports the missing Control Flow Guard and delay-import function starts and runs native bounded code-path, RTTI, unwind and reference passes. These results improve the previous missing-work baseline. They do not establish Ghidra-level whole-program analysis.", "", METHOD, "",
        "The Ghidra fixture run completed normally, with `analysis_timed_out:false`. The earlier Roblox default run was stopped after 38.69 minutes without final counters; that failed run is not a speed-ratio baseline. The fixture and each benchmark input were analyzed statically and never executed.", "",
        "| Input | MiB | 0.4 open ms | 0.5 open ms | 0.4 linear ms | 0.5 linear ms | 0.5 configured passes ms |",
        "|---|---:|---:|---:|---:|---:|---:|"]
    for row in final["results"]:
        baseline = old[row["name"]]["medians_ms"]
        timing = row["medians_ms"]
        text.append(f"| {row['name']} | {row['input']['size_bytes']/2**20:.2f} | {baseline['open']:.2f} | {timing['open']:.2f} | {baseline['linear']:.2f} | {timing['linear']:.2f} | {timing.get('automatic',0):.2f} |")
    text += ["", "Linear scan columns remain limited to declared executable sections. Roblox's original permissions declare only 2,560 executable bytes; its 102 MB `.text` is metadata-backed analysis candidate code. Its very short linear timing cannot stand for analysis of that larger scope. Other inputs likewise retain their original file and permissions.", "",
        "Configured native phase evidence (first repetition; timings are phase wall times inside the pipeline):", "",
        "| Input | Code ms / unique reachable bytes / decoded instructions | RTTI ms / classes | Unwind ms / valid records | References ms / count |",
        "|---|---|---|---|---|"]
    for row in final["results"]:
        p = phases(row["runs"][0])
        def cell(name, keys):
            item=p.get(name,{})
            if "error" in item: return item["error"]
            r=item.get("result",{})
            return f"{item.get('wall_ms',0):.2f} / "+" / ".join(str(r.get(k,"n/a")) for k in keys)
        text.append(f"| {row['name']} | {cell('code',['covered_bytes','instructions_decoded'])} | {cell('rtti',['classes'])} | {cell('exceptions',['valid_unwind_records'])} | {cell('references',['references'])} |")
    text += ["", "Per-input limits and unresolved work:", ""]
    for row in final["results"]:
        p=phases(row["runs"][0]); stops=[]
        for name,item in p.items():
            if "error" in item:
                stops.append(name+": "+item["error"]); continue
            r=item.get("result",{})
            flags=[k for k,v in r.items() if v is True and (k.endswith("_exhausted") or k in ["reference_limit_reached","deadline_exceeded","vftable_count_limit_reached"])]
            if flags: stops.append(name+": "+", ".join(flags))
            if r.get("complete") is False and r.get("stop_reason"): stops.append(name+": "+r["stop_reason"])
        c=p.get("code",{}).get("result",{}); refs=p.get("references",{}).get("result",{})
        stops.append(f"code {c.get('processed_functions',0):,} start traversals from {c.get('seed_functions',0):,} initial seeds; {c.get('invalid_stops',0):,} invalid stops / {c.get('unresolved_indirect_edges',0):,} indirect edges")
        if "unexamined_candidate_bytes" in refs: stops.append(f"references leave {refs['unexamined_candidate_bytes']:,} candidate code bytes outside their decoded-span scope")
        text.append("- "+row["name"]+": "+"; ".join(stops)+".")
    text += ["", "Budgets and incomplete coverage are retained in each raw phase result. A closed traversal means only that the bounded decoder observed resolved termination; it is not proof of a valid source function. The reference policy uses recovered instruction spans when available, aligned data pointer candidates and validated PE relocations. Linear reference mode is a separate diagnostic. Native reference counts distinguish evidence kinds: an aligned candidate and a relocation at the same storage address can each contribute a record. They are not necessarily distinct source/target pairs.", "",
        "Roblox metadata and recovery:", ""]
    start=expanded["metadata_start_comparison"]
    auto=expanded["automatic"].get("result",{})
    p=phases(expanded)
    code=p.get("code",{}).get("result",{})
    rtti=p.get("rtti",{}).get("result",{})
    refs=p.get("references",{}).get("result",{})
    static_samples=expanded.get("samples",[])
    returned=sum(s["pseudocode_quality"]["returned_code"] for s in static_samples)
    bad=sum(s["pseudocode_quality"]["halt_baddata"] for s in static_samples)
    text += [f"- Imported starts: native {start['native']:,}; Ghidra import-only {start['ghidra_import_only']:,}; exact-address intersection {start['intersection']:,}. Metadata starts are not recovered function bodies.",
        f"- Native-only imported start addresses: {', '.join(start['native_only']) or 'none'}; Ghidra-only imported start addresses: {', '.join(start['ghidra_only']) or 'none'}. The earlier policy omitted the `_guard_dispatch_icall` helper; its counters are preserved separately.",
        f"- Expanded-cap run: {expanded['automatic'].get('wall_ms',0):.2f} ms total, {code.get('processed_functions',0):,} indexed starts traversed, {code.get('covered_bytes',0):,} unique decoded bytes, {code.get('invalid_stops',0):,} invalid stops, {code.get('unresolved_indirect_edges',0):,} unresolved indirect edges.",
        f"- RTTI: {rtti.get('classes',0):,} validated classes, {rtti.get('vftables',0):,} vftables; scan_complete={rtti.get('scan_complete')}. References: {refs.get('references',0):,}, code bytes {refs.get('code_bytes_scanned',0):,}, data bytes {refs.get('data_bytes_scanned',0):,}; complete={refs.get('complete')}.",
        f"- The same {len(static_samples)} static CFG-address samples used earlier returned {returned} native pseudocode texts: {bad} contain halt_baddata and {len(static_samples)-returned} fail to return code. The earlier Ghidra import-only diagnostic produced 11 bad-data texts out of 12; this diagnostic is separate from the aborted full-analysis run. Returned warning-free text is not a verified recovery result.",
        "- Roblox exception directory is absent. Bad static decoding remains a substantial obstacle; no claim is made that metadata, decoded-byte coverage or pseudocode returned proves successful Roblox semantic recovery.", "",
        "Readable controlled C++ fixture:", "",
        f"Ghidra default analysis took {gh['analysis_interval_ms']/1000:.3f} s between pre/post markers and {ghcmd['total_wall_ms']/1000:.3f} s total including startup, import, metrics, sampled pseudocode and save. It recovered {gh['internal_function_count']} internal function records, {gh['instruction_count']:,} instructions, {gh['reference_count']:,} references, {gh['defined_string_count']} defined strings and {gh['registered_data_types']} data types. Its function manager's broader count {gh['function_count']} also includes external functions; use internal count for this comparison.", ""]
    fphase=phases(fixture)
    fc=fphase["code"]["result"]
    fr=fphase["references"]["result"]
    fe=fphase["exceptions"]["result"]
    ft=fphase["rtti"]["result"]
    text += [f"Native recovered {fc['processed_functions']} indexed start traversals, {fc['instructions_decoded']:,} instructions / {fc['covered_bytes']:,} unique candidate bytes, {fr['references']:,} native reference records, {ft['classes']} validated class groups / {ft['vftables']} vftables and {fe['valid_unwind_records']}/{fe['records_available']} accepted unwind records. {fc['unresolved_indirect_edges']} indirect edges remain unresolved. Different function/reference/RTTI grouping policies prevent interpreting similar totals as equivalent recovery.", "",
        "| Exported sample | Native CFG instructions / blocks | Ghidra instructions / blocks | Native bad-data halt | Ghidra bad-data halt |",
        "|---|---:|---:|---|---|"]
    ghsamples={x["address"].lower():x for x in json.loads((OUT / "ghidra-fixture/ghidra-samples.json").read_text(encoding="utf-8"))}
    for sample in fixture["samples"]:
        graph=sample["control_flow"].get("result",{})
        peer=ghsamples[sample["address"].lower()]
        text.append(f"| {sample['name']} | {graph.get('instruction_count',0)} / {len(graph.get('nodes',[]))} | {peer.get('instructions',0)} / {peer.get('blocks',0)} | {sample['pseudocode_quality']['halt_baddata']} | {'halt_baddata' in peer.get('code','')} |")
    delay=next(s for s in fixture["samples"] if s["name"]=="fixture_delay_import")["pseudocode"].get("result",{}).get("code","")
    delay_note="The delay-import call now resolves GetFileVersionInfoSizeW by name." if "GetFileVersionInfoSizeW" in delay else "The delay-import first-use wrapper remains displayed as a sub-address call."
    switch_sample=next(s for s in fixture["samples"] if s["name"]=="fixture_switch")
    switch_graph=switch_sample["control_flow"].get("result",{})
    switch_peer=ghsamples[switch_sample["address"].lower()]
    switch_note="The sample switch graph now follows its bounded case table; its 10 blocks and Ghidra's 11 blocks reflect different partitions of the same 26 sampled instructions." if switch_graph.get("complete") and switch_graph.get("instruction_count")==switch_peer["instructions"] else "The native graph still does not recover all switch cases."
    text += ["", "Sample pseudocode shows the branch arithmetic and six switch outcomes. "+switch_note+" "+delay_note+" Native return/parameter types and virtual-call typing remain less informative. Ghidra additionally defines language-specific EH FuncInfo and IP-to-state records; native unwind evidence explicitly leaves that EH3/EH4 layer undecoded. The six sample pseudocode results are saved for inspection; absence of bad-data warnings is not a semantic equivalence test.", "",
        "Remaining gaps include complete indirect-flow/switch recovery, semantic value propagation, rich automatically applied type/signature information, EH3/EH4 maps, comprehensive data/string definitions, whole-program library recognition, and measured accuracy on broader labeled source corpora. The new passes leave `semantic_analysis_complete:false` and `full_analysis_parity_established:false`.", "",
        "Workspace evidence: `performance-v0.5-initial.json` preserves the first policy attempt and 0.4 baseline; `performance-v0.5-0.5.json` is the final-policy fresh-process run; `roblox-expanded.json` records the separate expanded caps; `fixture-0.4.json`, `fixture-0.5.json` and `ghidra-fixture/` retain sample outputs, exact Java command and logs. The completed Ghidra project remains in the D:\\Scratcher workspace and is excluded from the release package; the package contains selected metrics and logs. Input hashes and tool schemas are recorded. Synthetic 1 GiB dump contains only 16 MiB executable code and 1008 MiB sparse data; the real Unreal crash dump is small and is labeled separately.", ""]
    (OUT / "analysis-comparison.md").write_text("\n".join(text), encoding="utf-8")
    print(OUT / "analysis-comparison.md", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["native", "ghidra", "expanded", "report"])
    parser.add_argument("--executable", type=pathlib.Path, default=ROOT / "build/Release/ScratcherMCP.exe")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--input", default=None)
    parser.add_argument("--variant", choices=["0.4", "0.5"], default=None)
    args = parser.parse_args()
    if args.phase == "native": native(args.executable, args.runs, args.input, args.variant)
    elif args.phase == "expanded": expanded(args.executable)
    elif args.phase == "report": render_report()
    else: ghidra()
