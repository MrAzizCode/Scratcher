"""Fresh-process CPU/CUDA exact fingerprint matching trials; no target execution."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports/hyperdecomp"
DEFAULT_CASES = [(32768,64),(131072,128),(1000000,128)]
FLAGS = getattr(subprocess,"CREATE_NO_WINDOW",0)

def identity(path):
    path=pathlib.Path(path)
    with path.open("rb") as source: digest=hashlib.file_digest(source,"sha256").hexdigest()
    return {"path":str(path.resolve()),"bytes":path.stat().st_size,"sha256":digest}

def command(args,timeout=15):
    try:
        completed=subprocess.run(args,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout,creationflags=FLAGS)
        return {"arguments":[str(a)for a in args],"exit_code":completed.returncode,"stdout":completed.stdout.strip(),"stderr":completed.stderr.strip()}
    except Exception as error:return {"arguments":[str(a)for a in args],"error":str(error)}

def nvidia():
    exe=shutil.which("nvidia-smi")
    if not exe:return {"available":False,"reason":"nvidia-smi not found"}
    return command([exe,"--query-gpu=name,uuid,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw","--format=csv,noheader,nounits"])

def stats(values):
    if not values:return None
    values=sorted(values)
    import math
    return {"count":len(values),"median":statistics.median(values),"p95":values[max(0,math.ceil(len(values)*.95)-1)],
        "mean":statistics.mean(values),"population_variance":statistics.pvariance(values),"min":values[0],"max":values[-1]}

def summarize(trials):
    valid=[t["result"]for t in trials if "result"in t and t["exit_code"]==0]
    gpu=[t for t in valid if t["every_forced_cuda_trial_used_cuda"]and t["every_trial_exactly_equal"]]
    cpu=[r["wall_ms"]for t in valid for r in t["warm_cpu_trials"]]
    cuda=[r["wall_ms"]for t in gpu for r in t["warm_forced_cuda_trials"]]
    result={"processes":len(trials),"successful_processes":len(valid),"actual_cuda_processes":len(gpu),
        "every_process_exact":len(valid)==len(trials)and all(t["every_trial_exactly_equal"]for t in valid),
        "cold_optimized_cpu_wall_ms":stats([t["cold_cpu"]["wall_ms"]for t in valid]),
        "cold_actual_cuda_wall_ms":stats([t["cold_forced_cuda"]["wall_ms"]for t in gpu]),
        "warm_optimized_cpu_wall_ms":stats(cpu),"warm_actual_cuda_wall_ms":stats(cuda),
        "fallback_reasons":sorted({t["cold_forced_cuda"]["fallback_reason"]for t in valid if t["cold_forced_cuda"]["fallback_reason"]}),
        "warm_actual_cuda_speedup_vs_optimized_cpu":statistics.median(cpu)/statistics.median(cuda)if cuda and len(gpu)==len(valid)and valid else None}
    result["cold_actual_cuda_speedup_vs_optimized_cpu"]=(result["cold_optimized_cpu_wall_ms"]["median"]/result["cold_actual_cuda_wall_ms"]["median"]
        if gpu and len(gpu)==len(valid) else None)
    result["warm_actual_cuda_components_ms"]={key:stats([r["timings"][key]for t in gpu for r in t["warm_forced_cuda_trials"]])
        for key in ["setup_ms","corpus_upload_ms","query_upload_ms","kernel_ms","download_ms","end_to_end_ms"]}
    result["cold_actual_cuda_components_ms"]={key:stats([t["cold_forced_cuda"]["timings"][key]for t in gpu])
        for key in ["setup_ms","corpus_upload_ms","query_upload_ms","kernel_ms","download_ms","end_to_end_ms"]}
    return result

def markdown(report,path):
    lines=["# HyperDecomp fingerprint matching measurements","",
        "These trials measure exact nearest-neighbor matching of 256-bit function fingerprints. They do not measure complete binary analysis, decompilation, accuracy against source semantics, or an application-wide speedup.","",
        report["method"],"",
        f"CPU worker count: {report['arguments']['workers']}. GPU: "+next((t["result"]["device"]["name"] for c in report["cases"]for t in c["trials"]if t.get("result",{}).get("device",{}).get("name")),"unavailable")+".","",
        "| Input | Candidates × queries | CPU warm ms | CUDA warm ms | CPU cold ms | CUDA cold ms | Warm CPU/CUDA | Cold CPU/CUDA | Exact trials |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for case in report["cases"]:
        s=case["summary"]
        def fmt(v):return f"{v:.3f}"if v is not None else "unavailable"
        def median(key):return s[key]["median"]if s[key] else None
        lines.append(f"| {case['label']} | {case['candidates']:,} × {case['queries']:,} | {fmt(median('warm_optimized_cpu_wall_ms'))} | {fmt(median('warm_actual_cuda_wall_ms'))} | {fmt(median('cold_optimized_cpu_wall_ms'))} | {fmt(median('cold_actual_cuda_wall_ms'))} | {fmt(s['warm_actual_cuda_speedup_vs_optimized_cpu'])} | {fmt(s['cold_actual_cuda_speedup_vs_optimized_cpu'])} | {s['every_process_exact']} |")
        for reason in s["fallback_reasons"]:lines.extend(["",f"{case['label']}: CPU fallback — {reason}. No CUDA speedup is reported for fallback runs."])
        for trial in case["trials"]:
            if trial.get("exit_code")!=0:
                reason=trial.get("result",{}).get("error",trial.get("stderr")or trial.get("error")or"No successful result")
                lines.extend(["",f"{case['label']} process {trial['repetition']+1} failed: {reason}. This trial is excluded from timings and cannot establish CUDA success."])
    slower=any(c["summary"]["warm_actual_cuda_speedup_vs_optimized_cpu"]is not None and c["summary"]["warm_actual_cuda_speedup_vs_optimized_cpu"]<1 for c in report["cases"])
    lines.extend(["","All timings in the table are medians. Ratios below 1 mean CUDA took longer than the optimized CPU. Cold includes context/module/compiler setup and initial corpus upload; warm retains the corpus on the device. "+("Some synthetic cases here are slower on CUDA even when warm. "if slower else "")+"Results are for the specified CPU worker count; they do not establish an optimal thread count across all processors.","",
        "| Input | CPU-owned corpus bytes | Maximum measured device-buffer bytes |",
        "|---|---:|---:|"])
    for case in report["cases"]:
        values=[t["result"] for t in case["trials"]if t.get("exit_code")==0 and "cold_forced_cuda"in t.get("result",{})]
        buffers=[row["device_bytes"]for t in values for row in [t["cold_forced_cuda"],*t["warm_forced_cuda_trials"]]if row["backend"]=="cuda"]
        lines.append(f"| {case['label']} {case['candidates']:,} × {case['queries']:,} | {values[0]['corpus_bytes'] if values else 'unavailable'} | {max(buffers)if buffers else 'unavailable'} |")
    lines.extend(["","Compiled-kernel attributes reported by the CUDA driver (not dynamic profiling, spill-event counts or measured occupancy):","",
        "| Input | Distance local bytes/thread | Distance registers/thread | Merge local bytes/thread | Merge registers/thread |",
        "|---|---:|---:|---:|---:|"])
    for case in report["cases"]:
        attrs=[row["kernel_driver_attributes"]for t in case["trials"]if t.get("exit_code")==0 and "cold_forced_cuda"in t.get("result",{}) for row in [t["result"]["cold_forced_cuda"],*t["result"]["warm_forced_cuda_trials"]]
            if row["backend"]=="cuda"and "kernel_driver_attributes"in row]
        def attribute(key):
            values=sorted({a[key]for a in attrs if a.get(key)is not None})
            return ", ".join(map(str,values))if values else "unavailable"
        lines.append(f"| {case['label']} {case['candidates']:,} × {case['queries']:,} | {attribute('distance_local_bytes_per_thread')} | {attribute('distance_registers_per_thread')} | {attribute('merge_local_bytes_per_thread')} | {attribute('merge_registers_per_thread')} |")
    lines.extend(["","Raw JSON contains every cold/warm trial, median, nearest-rank p95, population variance, device buffers, transfer/kernel/setup components, source/executable/input hashes, and hardware snapshots. nvidia-smi utilization is sampled before/after each process and is contextual only; it is not an in-kernel utilization trace. Missing hardware readings remain unavailable.","",
        "Cold means the first forced CUDA search in each fresh process, before a probe creates a context. CPU cold is its first library search after that GPU call; host corpus generation and CPU-owned copies already occurred, so this is not a claim of cold CPU caches. The driver or NVRTC may retain operating-system caches between processes; no driver cache was purged. Setup timings are aggregate library instrumentation; no separate uninstrumented compiler or context values are invented.","",
        "The immutable corpus/query objects are identical on CPU and GPU. Every returned index and distance, including deterministic tie order, is compared on every GPU trial. Synthetic corpora contain deliberate duplicate zero fingerprints, exact-match queries and random queries. Exported real fingerprints remain unchanged; all queries are sampled actual corpus fingerprints, with self matches retained. Exact parity measures consistency with this optimized CPU matcher, not the usefulness of the fingerprints.",""])
    path.write_text("\n".join(lines),encoding="utf-8")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--exe",type=pathlib.Path,default=ROOT/"build/Release/HyperDecompBench.exe")
    parser.add_argument("--processes",type=int,default=3)
    parser.add_argument("--warm-repeats",type=int,default=5)
    parser.add_argument("--workers",type=int,default=8)
    parser.add_argument("--k",type=int,default=8)
    parser.add_argument("--seed",type=int,default=0x53435241)
    parser.add_argument("--fingerprints",type=pathlib.Path)
    parser.add_argument("--mcp",type=pathlib.Path,help="Export an actual index through this MCP executable before matching")
    parser.add_argument("--export-input",type=pathlib.Path,help="Read-only binary to index; never executed")
    parser.add_argument("--case",action="append",help="Synthetic N:Q workload, repeatable; default 32768:64,131072:128,1000000:128")
    parser.add_argument("--output",type=pathlib.Path,default=OUT/"performance.json")
    args=parser.parse_args()
    if not 1<=args.processes<=10:parser.error("--processes must be 1..10")
    if bool(args.mcp)!=bool(args.export_input):parser.error("--mcp and --export-input must be supplied together")
    if args.mcp:
        from mcp_client import Client
        args.fingerprints=args.output.with_name(args.output.stem+"-fixture-fingerprints.json")
        with Client(args.mcp)as client:
            opened=client.tool("open_binary",{"path":str(args.export_input)})
            summary=client.tool("build_function_similarity_index",{"max_functions":1000000,"per_function_instruction_budget":256,"time_budget_ms":60000,"workers":args.workers},timeout=90)
            rows=[]
            while True:
                page=client.tool("get_function_similarity_index",{"offset":len(rows),"limit":5000})
                if page.get("cache_stale"):raise RuntimeError("Similarity index became stale during export")
                rows.extend(item["fingerprint_256"] for item in page["items"])
                if len(rows)>=page["total"]:break
            exported={"input":identity(args.export_input),"mcp_executable":identity(args.mcp),"summary":summary,
                "open_metadata":opened,"mcp_memory_after_index":client.memory(),"items":rows,"total":len(rows),"method":"Entire bounded session similarity index exported by paging in index order, retaining every 256-bit fingerprint as a compact hex string. Original binary read, never executed. Detailed row metadata is available through MCP and omitted from this matcher dataset."}
            args.fingerprints.parent.mkdir(parents=True,exist_ok=True)
            args.fingerprints.write_text(json.dumps(exported,separators=(",",":")),encoding="utf-8")
    cases=[]
    for n,q in [tuple(map(int,c.split(":")))for c in args.case]if args.case else DEFAULT_CASES:
        if n*q>128*1024*1024:parser.error("Case exceeds library 128 Mi comparison-pair cap")
        cases.append({"label":"synthetic deterministic","candidates":n,"queries":q,"synthetic":True})
    if args.fingerprints:
        exported=json.loads(args.fingerprints.read_text(encoding="utf-8"))
        rows=exported.get("items",exported.get("fingerprints",[]))if isinstance(exported,dict)else exported
        cases.append({"label":"exported real function fingerprints","candidates":len(rows),"queries":min(128,len(rows)),
            "synthetic":False,"input":identity(args.fingerprints)})
    sources=[p for p in [ROOT/"src/hyperdecomp_bench.cpp",ROOT/"src/accel/matcher.cpp",ROOT/"src/accel/matcher.hpp",pathlib.Path(__file__)]if p.exists()]
    report={"date":datetime.datetime.now().astimezone().isoformat(),"method":"Three fresh processes by default; five retained-corpus warm repeats per process; alternate CPU/GPU ordering after first cold searches. Optimized multithreaded Matcher CPU path with identical corpus, queries and k. CPU fallback is excluded from CUDA timings/speedups. No target execution or Computer Use. No OS/driver cache flush. Process startup, corpus generation, and CPU-owned corpus copies are outside per-search walls but full child wall is retained.",
        "executable":identity(args.exe),"sources":[identity(p)for p in sources],"hardware":{"platform":platform.platform(),"processor":platform.processor(),"logical_cpus":os.cpu_count(),"nvidia_smi":nvidia(),
            "windows_cpu_inventory":command(["powershell","-NoProfile","-NonInteractive","-Command","Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json -Compress"])if os.name=="nt"else None},
        "arguments":{key:str(value)if isinstance(value,pathlib.Path)else value for key,value in vars(args).items()},"cases":[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    for case in cases:
        row=dict(case);row["trials"]=[]
        for repetition in range(args.processes):
            cmd=[str(args.exe),"--candidates",str(case["candidates"]),"--queries",str(case["queries"]),"--k",str(args.k),"--repeats",str(args.warm_repeats),"--workers",str(args.workers),"--seed",str(args.seed)]
            if not case["synthetic"]:cmd.extend(["--fingerprints",str(args.fingerprints)])
            before=nvidia();start=time.perf_counter();raw=command(cmd,timeout=180)
            trial={"repetition":repetition,"arguments":cmd,"process_wall_ms":(time.perf_counter()-start)*1000,
                "nvidia_before":before,"nvidia_after":nvidia(),"exit_code":raw.get("exit_code"),"stderr":raw.get("stderr")}
            try:trial["result"]=json.loads(raw.get("stdout",""))
            except Exception:trial["error"]=raw
            row["trials"].append(trial)
            print(f"{case['label']} {case['candidates']}x{case['queries']} process {repetition+1}: {trial.get('result',{}).get('status',trial.get('error'))}",flush=True)
        row["summary"]=summarize(row["trials"]);report["cases"].append(row)
        args.output.write_text(json.dumps(report,indent=2),encoding="utf-8")
        markdown(report,args.output.with_suffix(".md"))
    if any(not c["summary"]["every_process_exact"]for c in report["cases"]):sys.exit(1)

if __name__=="__main__":main()
