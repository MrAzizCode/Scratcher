"""Compare recovered artifacts without treating linear scanning as auto-analysis."""
import collections
import hashlib
import json
import pathlib
import re
import statistics

ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/"reports/roblox-comparison"
def read(name):return json.loads((OUT/name).read_text(encoding="utf-8"))

def partial_report():
    s=read("scratcher.json");pre=read("ghidra-pre.json");stop=read("hard-stop.json")
    a=read("scratcher-assisted.json");g=read("noauto/ghidra-samples.json");pe=read("pe-metadata.json")
    command=read("command.json");nc=read("noauto/command.json")
    assert hashlib.file_digest((ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe").open("rb"),"sha256").hexdigest()==s["sha256"]
    scan=a["full_scan"]["result"]
    summary={"input_sha256":s["sha256"],"input_bytes":s["size_bytes"],
        "scratcher_default_open_median_ms":statistics.median(r["open"]["wall_ms"] for r in s["repetitions"]),
        "scratcher_default_scan_median_ms":statistics.median(r["full_scan"]["wall_ms"] for r in s["repetitions"]),
        "scratcher_default_scanned_bytes":s["repetitions"][0]["full_scan"]["result"]["scanned_bytes"],
        "scratcher_default_functions":s["functions_after_scan"],"ghidra_imported_function_records":pre["internal_function_count"],
        "cfg_entries":pe["cfg_entries"],"ghidra_full_auto_completed":False,"ghidra_post_export_available":False,
        "ghidra_default_process_wall_seconds":command["total_wall_ms"]/1000,"ghidra_default_budget_seconds":1800,
        "ghidra_termination":"Owned process stopped after cooperative-timeout overrun; no completed auto-analysis metrics",
        "assisted_scratcher_scan_ms":a["full_scan"]["wall_ms"],"assisted_scanned_bytes":scan["scanned_bytes"],
        "assisted_decoded_instructions":scan["instructions_decoded"],"assisted_invalid_bytes":scan["invalid_bytes"],
        "assisted_candidate_functions":a["functions_after_scan"],
        "default_scratcher_sample_rejections":sum("error" in r for r in a["default_samples"]),
        "assisted_scratcher_listings":sum("result" in r.get("pseudocode",{}) for r in a["assisted_samples"]),
        "assisted_scratcher_bad_data_listings":sum("halt_baddata" in r.get("pseudocode",{}).get("result",{}).get("code","") for r in a["assisted_samples"]),
        "ghidra_noauto_sample_listings":sum(r.get("decompile_completed",False) for r in g),
        "ghidra_noauto_bad_data_listings":sum("halt_baddata" in r.get("code","") for r in g)}
    lines=["# Roblox Player: Ghidra headless versus Scratcher 0.4", "",
        "**The pipelines are not equivalent. Scratcher currently performs much less automatic recovery. Its fast linear scan is not a substitute for Ghidra auto-analysis. On this Roblox file, even the slower Ghidra trial did not finish, and sampled static pseudocode was mostly unusable in both tools.**", "",
        "## Identical input", "",
        f"Roblox Game Client 0.742.0.7421053, {s['size_bytes']:,} bytes ({s['size_bytes']/2**20:.2f} MiB). SHA-256 `{s['sha256']}`. Windows Authenticode verified the Roblox Corporation signature as Valid.", "",
        "The file was copied from the existing running player's Fishstrap installation into D:/Scratcher/benchmark-inputs. A separate incomplete installation file was rejected. Both tools used the unchanged valid copy. Roblox was not launched, attached to, dumped, or patched. No Computer Use. Existing user processes stayed running; this was not an isolated idle-system benchmark.", "",
        "## Measured defaults", "",
        "| Measurement | Scratcher 0.4 | Ghidra 12.1.4 headless |", "| --- | ---: | ---: |",
        f"| Open/index | {summary['scratcher_default_open_median_ms']:.2f} ms median | Included in process time |",
        f"| Default scan / attempted auto-analysis | {summary['scratcher_default_scan_median_ms']:.2f} ms median | Did not finish; stopped after {summary['ghidra_default_process_wall_seconds']/60:.2f} min total |",
        f"| Function records after import | {s['function_count_at_import']:,} | {pre['internal_function_count']:,} |",
        f"| Default file-backed code bytes visited | {summary['scratcher_default_scanned_bytes']:,} | Final counters unavailable |",
        "| Completed full auto-analysis | No equivalent whole-program pass | No |", "",
        "Scratcher timings use three fresh MCP processes, including dispatch/stdio; process startup/initialize are excluded. Ghidra used one fresh-project run, default analyzer settings, Java 21.0.5, an 8 GiB heap and an eight-CPU limit. Its 1,800-second timeout is cooperative. The run remained inside a database lookup after the deadline; the owned Java process was eventually stopped. Actual elapsed time is retained in command.json and hard-stop.json. The failed process exit is an intentional benchmark termination, not a completed analysis result.", "",
        "No final Ghidra instruction, function-body, RTTI/type, string, or reference recovery totals were exported by that auto-analysis run. They must not be inferred from the import count or copied from the separate no-analysis diagnostic. The default trial's project is not offered as a successfully saved completed analysis.", "",
        "## Why the fast result is misleading", "",
        f"The large .text region contains {next(x['size'] for x in pe['sections'] if x['name']=='.text'):,} bytes but has no IMAGE_SCN_MEM_EXECUTE flag; the tempest entry region is also non-executable in the PE headers. Scratcher's default scan therefore visits only 2,560 bytes of .rodata. Its 100% coverage means 100% of this tiny declared scope, not 100% of Roblox's code.", "",
        f"The exception directory is empty. The PE Load Configuration instead supplies {pe['cfg_entries']:,} Control Flow Guard entries at {pe['cfg_table']}, with {pe['cfg_stride']}-byte records. Ghidra imports this metadata and delay-load proxy functions. Scratcher currently lacks CFG function-table import and delay-import handling, leaving just the entry record. Imported one-byte function placeholders are not fully recovered function bodies.", "",
        "Three Java thread snapshots and the logs show Ghidra performing RTTI validation/reference search and later constant propagation/database lookups. The log also contains exception-processing disassembly failures and decompiler/p-code warnings. These are additional passes that Scratcher's linear scan does not perform, but longer elapsed time does not prove accurate or complete recovery.", "",
        "```mermaid", "flowchart LR", '  B[Same signed PE bytes] --> S[Scratcher limited PE import]', '  S --> L[2.5 KiB declared-executable scan]', '  B --> G[Ghidra CFG and delay-import processing]', '  G --> A[RTTI, exception, reference and other passes]', '  A --> T[Budget overrun: no final export]', "```", "",
        "## Expanded Scratcher scan: explicit assistance", "",
        "Separate from the default baseline, .text/tempest/.byfron were marked executable inside the analysis workspace only. No file bytes changed. This variant does not import Ghidra's results.", "",
        f"The expanded linear scan visited **{scan['scanned_bytes']:,} bytes in {a['full_scan']['wall_ms']/1000:.3f} s**, decoded {scan['instructions_decoded']:,} instructions and counted {scan['invalid_bytes']:,} invalid bytes ({100*scan['invalid_bytes']/scan['scanned_bytes']:.2f}% of visited bytes). It retained {a['functions_after_scan']:,} candidate functions. Candidate direct-call targets can be false positives; neither this count nor byte coverage establishes semantic correctness.", "",
        "## Same-address pseudocode diagnostic", "",
        "Twelve CFG starts were read independently from the file and stratified by gaps to their next CFG entries. These gaps are conservative manual upper bounds, not proven function extents. Default Scratcher rejected all twelve because their sections lacked execute permission. Assisted Scratcher used a fresh workspace with only those twelve explicit seeds; Ghidra used a fresh import with **-noanalysis**. This comparison measures on-demand behavior without claiming the stopped full-auto-analysis results.", "",
        f"Ghidra completed {summary['ghidra_noauto_sample_listings']}/12 decompiler requests, but **{summary['ghidra_noauto_bad_data_listings']}/12** outputs contained halt_baddata and truncated-flow warnings. Assisted Scratcher returned {summary['assisted_scratcher_listings']}/12 listings, with **{summary['assisted_scratcher_bad_data_listings']}** containing halt_baddata; the remaining request failed with an unmapped-address error. Only one sample in each produced a warning-free listing. Warning-free output still does not prove correctness.", "",
        f"The no-analysis Ghidra diagnostic completed and saved its import-only project in {nc['total_wall_ms']/1000:.2f} s, including JVM startup, metadata import, statistics export and all sample requests. That total is not an auto-analysis time. This diagnostic overlapped the stalled default-run shutdown, so its timings are not isolated. No speedup ratio is calculated.", "",
        "| Address | Assisted Scratcher pseudocode ms | Ghidra no-analysis pseudocode ms | Observed output |", "| --- | ---: | ---: | --- |"]
    gm={int(r["address"],16):r for r in g}
    for row in a["assisted_samples"]:
        other=gm[int(row["address"],16)];pseudo=row.get("pseudocode",{});ms=pseudo.get("wall_ms")
        status="Scratcher error; Ghidra bad instruction data" if "error" in pseudo else ("Both contain bad instruction data" if "halt_baddata" in other.get("code","") else "Neither listing contains a warning; accuracy unproven")
        lines.append(f"| {row['address']} | {f'{ms:.2f}' if ms is not None else 'error'} | {other['decompile_ms']:.2f} | {status} |")
    lines += ["", "At 0x1405ac180 both tools essentially returned a stub ending in halt_baddata. Matching failure output is not successful analysis parity. The raw JSON retains every listing, error and bounded-reachability issue. A static file with this unusual layout and these decoding failures is a poor standalone accuracy benchmark; this trial does not establish the exact reason for the bad bytes or whether runtime code would be recoverable.", "",
        "## What needs to improve", "",
        "1. Import CFG and delay-load metadata, preserve candidate provenance and handle known code entries in sections with unusual permissions.",
        "2. Make unsupported/excluded code visible so a tiny-scope complete scan cannot look like a complete program analysis.",
        "3. Add whole-program reference/code/data recovery, automated RTTI/vtable and exception handling recovery, and broader type/prototype propagation.",
        "4. Compare matched-scope results on a labeled, readable corpus. Measure speed only after validating equivalent work and recovery quality.", "",
        "## Evidence", "",
        "All files are under D:/Scratcher/reports/roblox-comparison. comparison.json summarizes measured results. scratcher.json, scratcher-assisted.json, pe-metadata.json and input-signature.json preserve the native trial and file identity. ghidra-pre.json and ghidra-functions-pre.json preserve imported metadata. console.log, ghidra.log, thread-snapshot*.txt, command.json and hard-stop.json preserve the failed full-auto-analysis attempt. noauto/ghidra-samples.json and noauto/command.json document the separate on-demand diagnostic. Its saved import-only project is projects/Roblox742-NoAuto.gpr.", "",
        "Reproduction scripts: D:/Scratcher/scripts/compare-roblox.py (scratcher / ghidra / ghidra-noauto), roblox-samples.py, roblox-assisted.py and report-roblox.py. The Java exporter is reports/roblox-comparison/scripts/BenchmarkMetrics.java. Run phases serially; use a new project name for a fresh Ghidra run. command.json contains the exact Java arguments. The primary documentation is [Ghidra's headless pipeline](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md).", ""]
    (OUT/"comparison.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    (OUT/"comparison-report.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps(summary,indent=2));print(OUT/"comparison-report.md")

def main():
    if not (OUT/"ghidra-post.json").exists():
        partial_report();return
    s=read("scratcher.json");pre=read("ghidra-pre.json");g=read("ghidra-post.json");command=read("command.json")
    sf=read("scratcher-functions.json");gf=read("ghidra-functions-post.json");gs=read("ghidra-samples.json")
    assisted=read("scratcher-assisted.json");pe=read("pe-metadata.json")
    current=hashlib.file_digest((ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe").open("rb"),"sha256").hexdigest()
    assert current==s["sha256"],"Input changed"
    sa={int(f["address"],16) for f in sf};ga={int(f["address"],16) for f in gf}
    summary={"same_input_sha256":current,"input_bytes":s["size_bytes"],"ghidra_analysis_timed_out":g["analysis_timed_out"],
        "scratcher_open_median_ms":statistics.median(r["open"]["wall_ms"] for r in s["repetitions"]),
        "scratcher_scan_median_ms":statistics.median(r["full_scan"]["wall_ms"] for r in s["repetitions"]),
        "scratcher_scan_bytes":s["repetitions"][0]["full_scan"]["result"]["scanned_bytes"],
        "scratcher_default_functions":len(sf),"ghidra_import_functions":pre["internal_function_count"],
        "ghidra_final_functions":len(gf),"shared_function_starts":len(sa&ga),"ghidra_only_function_starts":len(ga-sa),
        "scratcher_only_function_starts":len(sa-ga),"ghidra_bodies_larger_than_one_byte":sum(f["body_bytes"]>1 for f in gf),
        "ghidra_nondefault_name_sources":dict(collections.Counter(f["name_source"] for f in gf)),
        "ghidra_signature_sources":dict(collections.Counter(f["signature_source"] for f in gf)),
        "ghidra_auto_analysis_interval_ms":g["analysis_interval_ms"],"ghidra_total_wall_ms":command["total_wall_ms"],
        "ghidra_defined_instructions":g["instruction_count"],"ghidra_defined_data":g["defined_data_count"],
        "ghidra_references":g["reference_count"],"ghidra_defined_strings":g["defined_string_count"],
        "ghidra_data_types":g["registered_data_types"],"scratcher_assisted_scan_ms":assisted["full_scan"]["wall_ms"],
        "scratcher_assisted_scan_bytes":assisted["full_scan"]["result"]["scanned_bytes"],
        "scratcher_assisted_candidate_functions":assisted["functions_after_scan"],
        "default_scratcher_sample_failures":sum("error" in r for r in assisted["default_samples"]),
        "assisted_scratcher_pseudocode_results":sum("result" in r.get("pseudocode",{}) for r in assisted["assisted_samples"]),
        "ghidra_completed_sample_pseudocode":sum(r.get("decompile_completed",False) for r in gs)}
    (OUT/"comparison.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    interval=g["analysis_interval_ms"]/1000;total=command["total_wall_ms"]/1000
    lines=["# Roblox Player: Ghidra headless versus Scratcher 0.4", "",
        "Conclusion: the analyzers do not perform the same amount or kind of analysis. Scratcher's current default result on this input is severely incomplete. Its tiny scan time cannot be presented as equivalent to Ghidra auto-analysis.", "",
        "## Input and method", "",
        f"Roblox Player 0.742.0.7421053; {s['size_bytes']:,} bytes ({s['size_bytes']/2**20:.2f} MiB). SHA-256: `{current}`.", "",
        "The valid file was copied from the currently used local Fishstrap installation into D:/Scratcher/benchmark-inputs. Windows Authenticode verification returned Valid with Roblox Corporation as signer. A separate Roblox installation copy was truncated and was rejected. Both analyzers read the same immutable copy. Roblox was not launched, attached to, dumped, patched, or otherwise modified. Its existing running process was used only to identify the installed file path; existing user processes were left running, so this is not an isolated idle-system benchmark. No Computer Use was used.", "",
        "Ghidra 12.1.4 PUBLIC and Scratcher 0.4.0 were used. Ghidra ran with default auto-analysis options, an 8 GiB Java heap, an eight-CPU limit, Java 21.0.5, and a 1,800-second analysis timeout. Missing PDB information was not downloaded. Its project, settings, cache, logs and benchmark artifacts are under D:/Scratcher. A preliminary script smoke check ran on the self-built sample. That smoke run used the normal existing Ghidra settings locations; the actual Roblox run used isolated D: paths.", "",
        "Scratcher's default load/scan values are medians of three fresh MCP processes. Ghidra is one fresh-project run. OS file caches were not flushed. Timings include differing amounts of startup, import, export and persistent database work; they are not an equal-work speed comparison. Scratcher benchmarks and assisted tests were not run concurrently with the timed Ghidra run. Two brief Java thread snapshots were captured to identify the expensive analysis stage.", "",
        "## Default results", "",
        "| Measurement | Scratcher 0.4 default | Ghidra 12.1.4 default |",
        "| --- | ---: | ---: |",
        f"| Opening/indexing through MCP | {summary['scratcher_open_median_ms']:.2f} ms | Included in total run |",
        f"| Full declared-executable linear scan / auto-analysis | {summary['scratcher_scan_median_ms']:.2f} ms | {interval:.2f} s pre/post interval |",
        f"| Total headless process including exports and samples | Not measured comparably | {total:.2f} s |",
        f"| Internal function records | {len(sf):,} | {len(gf):,} |",
        f"| Function records before auto-analysis | {s['function_count_at_import']:,} | {pre['internal_function_count']:,} |",
        f"| Functions with a body larger than one byte | {s['bounded_functions_after_scan']:,} explicit extents | {summary['ghidra_bodies_larger_than_one_byte']:,} recovered bodies |",
        f"| Defined program instructions | No full program instruction database | {g['instruction_count']:,} |",
        f"| Defined data items | No comparable auto-definition pass | {g['defined_data_count']:,} |",
        f"| Program reference records | Separate bounded on-demand pass | {g['reference_count']:,} |",
        f"| Defined strings | Separate capped string discovery | {g['defined_string_count']:,} |",
        f"| Registered data types | No automatic RTTI type recovery | {g['registered_data_types']:,} |", "",
        f"Ghidra analysis timeout occurred: **{g['analysis_timed_out']}**. " + ("The resulting database is partial; this is not a completed full-auto-analysis timing." if g['analysis_timed_out'] else "The default auto-analysis returned without its timeout flag. That does not prove complete or correct recovery of the program."), "",
        "The pre/post interval starts after the pre-script exports its snapshot and ends on post-script entry. It includes analysis orchestration and post-script dispatch; Ghidra's own analyzer timing report is retained in console.log. The full process wall time additionally includes JVM startup, PE import, all statistics exports, sampled pseudocode, and project saving.", "",
        "Function counts, typed data and reference totals are descriptive proxies, not ground-truth accuracy scores. Imported starts with one-byte placeholder bodies are not fully analyzed functions. Scratcher's bounded extents and Ghidra's recovered bodies are different representations and are labeled separately.", "",
        "## Why Scratcher looks so fast here", "",
        f"The file's .text section contains {next(x['size'] for x in pe['sections'] if x['name']=='.text'):,} file-backed bytes but lacks IMAGE_SCN_MEM_EXECUTE. The tempest entry-point section also lacks it. Scratcher obeys those flags and visits only {summary['scratcher_scan_bytes']:,} declared-executable bytes in .rodata. Its reported 100% coverage applies to that tiny scope; it does not cover the large .text section.", "",
        f"The PE exception directory is empty. The Load Configuration directory instead exposes a Control Flow Guard table with {pe['cfg_entries']:,} entries (stride {pe['cfg_stride']} bytes), at {pe['cfg_table']}. Ghidra imports CFG-derived function starts and delay-load proxies; Scratcher's current PE loader lacks both CFG function-table import and delay-import handling. This is a real loader coverage gap, beyond the executable-section flag issue.", "",
        f"The final function-start sets share {summary['shared_function_starts']:,} addresses. Ghidra has {summary['ghidra_only_function_starts']:,} additional addresses; Scratcher has {summary['scratcher_only_function_starts']:,} that Ghidra does not list. These set differences do not establish which candidate starts are correct.", "",
        "A live Java thread snapshot found Ghidra inside the Microsoft RTTI analyzer's memory-reference search. This pass finds and annotates class metadata/vtables. Scratcher has no equivalent automatic pass in this build. Some TypeDescriptors could not be processed; the raw log preserves those warnings. More elapsed time includes broader recovery work and potentially expensive algorithms, not a guarantee that every result is useful or accurate.", "",
        "```mermaid", "flowchart LR", '  B[Same PE bytes] --> S[Scratcher loader: limited PE metadata]', '  S --> L[Declared executable sections: linear call scan]', '  L --> P[On-demand local graph and pseudocode]', '  B --> G[Ghidra loader: CFG and delay imports]', '  G --> A[Auto-analysis: data, references, RTTI and other passes]', '  A --> D[Program database plus sampled pseudocode]', "```", "",
        "## Explicitly assisted Scratcher diagnostic", "",
        "This is a separate diagnostic, not the default result. Only the analysis workspace was changed: .text, tempest and .byfron were marked executable. No bytes were patched. Twelve CFG addresses were independently read from the file; next CFG entries were supplied as conservative manual sample upper bounds. No Ghidra types, function bodies, references or pseudocode were imported.", "",
        f"That expanded Scratcher linear scan visited {summary['scratcher_assisted_scan_bytes']:,} bytes in {summary['scratcher_assisted_scan_ms']:.2f} ms and retained {summary['scratcher_assisted_candidate_functions']:,} candidate functions. Those are direct-call candidates, not equivalently validated Ghidra functions. Only the twelve chosen locations received additional reachable analysis and pseudocode recovery.", "",
        f"At the same twelve locations, default Scratcher rejected {summary['default_scratcher_sample_failures']} requests; assisted Scratcher returned {summary['assisted_scratcher_pseudocode_results']} pseudocode results; Ghidra completed {summary['ghidra_completed_sample_pseudocode']} sampled decompilations. A returned C listing does not prove correctness or equivalent recovered types. The assisted function upper bounds can differ from Ghidra's recovered bodies.", "",
        "| Address | Assisted Scratcher reachable instructions | Ghidra defined instructions | Assisted pseudocode ms | Ghidra pseudocode ms |",
        "| --- | ---: | ---: | ---: | ---: |"]
    byaddr={int(row["address"],16):row for row in gs}
    for row in assisted["assisted_samples"]:
        other=byaddr.get(int(row["address"],16),{})
        n=row.get("reachable",{}).get("result",{}).get("instruction_count","error")
        ms=row.get("pseudocode",{}).get("wall_ms")
        lines.append(f"| {row['address']} | {n} | {other.get('instructions','missing function')} | {f'{ms:.2f}' if ms is not None else 'error'} | {other.get('decompile_ms','unavailable')} |")
    lines += ["", "## What parity requires", "",
        "Scratcher needs CFG/delay-import metadata support, explicit handling of code in sections with unusual permissions, whole-program code/data classification and references, automated RTTI/vtable and exception reconstruction, and broader type/prototype propagation. These need accuracy tests against a labeled corpus as well as matched-scope timing. A fast linear decoder and a per-function decompiler do not supply this surrounding analysis automatically.", "",
        "## Evidence and reproduction", "",
        "All artifacts are in D:/Scratcher/reports/roblox-comparison: comparison.json, scratcher.json, ghidra-pre.json, ghidra-post.json, all function lists, pe-metadata.json, both sampled pseudocode outputs, console.log, ghidra.log, command.json, and thread-snapshot.txt. The saved Ghidra project is projects/Roblox742.gpr.", "",
        "Scripts: scripts/compare-roblox.py, scripts/roblox-samples.py, scripts/roblox-assisted.py, scripts/report-roblox.py and reports/roblox-comparison/scripts/BenchmarkMetrics.java. Run scratcher first; prepare twelve samples from PE metadata; launch the headless phase; after it exits, run assisted Scratcher and generate this report. Use a new project name/directory for a fresh Ghidra repetition. command.json contains the exact Java command.", "",
        "Primary documentation: [Ghidra headless pipeline and timeout behavior](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md); local matching sources show CFG import in ControlFlowGuard.java and RTTI processing in RttiAnalyzer.java. Scratcher's local engine.cpp, binary.cpp and feature_advanced_analysis.cpp define its scan and bounded-analysis scope.", ""]
    (OUT/"comparison-report.md").write_text("\n".join(lines),encoding="utf-8")
    print(OUT/"comparison-report.md")
    print(json.dumps(summary,indent=2))


if __name__=="__main__":main()
