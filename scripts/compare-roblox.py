"""Reproducible static comparison; never runs or changes the Roblox executable."""
import argparse
import collections
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import time
from mcp_client import Client, timed

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports/roblox-comparison"
INPUT = ROOT / "benchmark-inputs/RobloxPlayerBeta-0.742.exe"
GHIDRA = ROOT / "vendor/tools/ghidra_12.1.4_PUBLIC"
JAVA = pathlib.Path("C:/Program Files/Eclipse Adoptium/jdk-21.0.5.11-hotspot/bin/java.exe")


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def functions(client):
    rows = []
    while True:
        page = client.tool("list_functions", {"offset": len(rows), "limit": 10000})
        rows += page["items"]
        if len(rows) >= page["total"]:
            return rows


def scratcher():
    record = {"date": datetime.datetime.now().astimezone().isoformat(), "input": str(INPUT),
        "size_bytes": INPUT.stat().st_size, "sha256": hashlib.file_digest(INPUT.open("rb"), "sha256").hexdigest(),
        "repetitions": [], "method": "Three fresh processes; no OS cache flush; stdio MCP wall times; no input execution."}
    samples = []
    for repetition in range(3):
        with Client(ROOT / "dist-v0.4/ScratcherMCP.exe") as client:
            row = {}
            for key, tool, args in [("open", "open_binary", {"path": str(INPUT)}),
                ("full_scan", "analyze", {"full_scan": True}),
                ("cached_scan", "analyze", {"full_scan": True})]:
                result, wall = timed(client, tool, args, timeout=180)
                row[key] = {"wall_ms": wall, "result": result, "memory": client.memory()}
            record["repetitions"].append(row)
            print("Scratcher repetition", repetition+1, "scan ms", row["full_scan"]["wall_ms"], flush=True)
            if repetition == 0:
                initial = row["open"]["result"]
                all_functions = functions(client)
                save("scratcher-functions.json", all_functions)
                # Deterministic size-stratified metadata functions at different positions.
                for low, high in [(1,32),(33,128),(129,512),(513,2048)]:
                    candidates = [f for f in all_functions if low <= int(f["end"],16)-int(f["address"],16) <= high]
                    if candidates:
                        for fraction in [.2,.5,.8]:
                            item = dict(candidates[min(len(candidates)-1,int(len(candidates)*fraction))])
                            item["selection"] = f"metadata extent {low}-{high} bytes, quantile {fraction}"
                            if item["address"] not in [s["address"] for s in samples]:
                                samples.append(item)
                if not samples:
                    for a, label in [(initial["entry"],"entry point"),("0x140001000",".text start"),("0x146182000","declared executable region")]:
                        samples.append({"address":a,"end":"0x0","name":label,"selection":"No bounded metadata functions; inspect known image locations"})
                save("samples.json", samples)
                record["functions_after_scan"] = len(all_functions)
                record["function_sources_after_scan"] = dict(collections.Counter(f["source"] for f in all_functions))
                record["bounded_functions_after_scan"] = sum(int(f["end"],16)>int(f["address"],16) for f in all_functions)
                record["function_count_at_import"] = initial["function_count"]
            save("scratcher.json", record)
    # Separate sample session; timings cannot contend with headless auto-analysis.
    with Client(ROOT / "dist-v0.4/ScratcherMCP.exe") as client:
        client.tool("open_binary", {"path": str(INPUT)})
        sample_results = []
        for sample in samples:
            row = {"address": sample["address"], "metadata_name": sample["name"], "metadata_end": sample["end"]}
            for key, tool, args in [
                ("reachable", "analyze_reachable", {"address":sample["address"],"instruction_budget":20000,"byte_budget":65536,"include_instructions":False}),
                ("graph", "get_control_flow", {"address":sample["address"],"instruction_budget":10000}),
                ("pseudocode", "decompile", {"address":sample["address"]})]:
                try:
                    result, wall = timed(client, tool, args, timeout=60)
                    row[key] = {"wall_ms":wall,"result":result}
                except Exception as error:
                    row[key] = {"error":str(error)}
            sample_results.append(row)
            save("scratcher-samples.json", sample_results)
            print("Scratcher sample",sample["address"], flush=True)
        # This is deliberately bounded; the result must not be called a full reference pass.
        try:
            refs, wall = timed(client,"get_cross_references",{"address":samples[0]["address"],"instruction_budget":1000000,"limit":10000},timeout=120)
            record["bounded_reference_scan"] = {"wall_ms":wall,"result":refs}
        except Exception as error:
            record["bounded_reference_scan"] = {"error":str(error)}
        save("scratcher.json",record)


def ghidra(smoke=False, noauto=False):
    directory = OUT / "smoke" if smoke else (OUT / "noauto" if noauto else OUT)
    directory.mkdir(exist_ok=True)
    if smoke:
        (directory / "samples.json").write_text("[]",encoding="utf-8")
    elif noauto:
        (directory / "samples.json").write_text((OUT / "samples.json").read_text(encoding="utf-8"),encoding="utf-8")
    properties = []
    for line in (GHIDRA / "support/launch.properties").read_text().splitlines():
        if line.startswith(("VMARGS=","VMARGS_WINDOWS=")):
            value=line.split("=",1)[1]
            if value:
                properties.append(value)
    args = [str(JAVA), *properties, "-Xmx8G", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
        f"-Duser.home={OUT / 'java-home'}",f"-Djava.io.tmpdir={ROOT / '.tmp'}","-Djava.awt.headless=true",
        f"-Dapplication.settingsdir={OUT / 'settings'}",f"-Dapplication.cachedir={OUT / 'cache'}",f"-Dapplication.tempdir={ROOT / '.tmp'}",
        "-cp",str(GHIDRA / "Ghidra/Framework/Utility/lib/Utility.jar"), "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",str(OUT / "projects"),"smoke" if smoke else ("Roblox742-NoAuto" if noauto else "Roblox742"),
        "-import",str(ROOT / "dist-v0.4/samples/ScratcherSample.exe" if smoke else INPUT),
        "-max-cpu","8","-analysisTimeoutPerFile","1800",
        "-scriptPath",str(OUT / "scripts"),"-preScript","BenchmarkMetrics.java","pre",str(directory),
        "-postScript","BenchmarkMetrics.java","post",str(directory),
        "-log",str(directory / "ghidra.log"),"-scriptlog",str(directory / "ghidra-scripts.log")]
    if smoke or noauto:
        args.append("-noanalysis")
    metadata={"arguments":args,"heap_limit_gib":8,"cpu_limit":8,"analysis_timeout_seconds":1800,
        "version":"12.1.4","jdk":"21.0.5","auto_analysis_enabled":not(smoke or noauto),"method":"Default auto-analysis or explicitly labeled no-analysis diagnostic; pre/post snapshot; separate sampled decompilation; no input execution."}
    (directory / "command.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    environment=dict(os.environ,TEMP=str(ROOT / ".tmp"),TMP=str(ROOT / ".tmp"))
    start=time.perf_counter()
    with (directory / "console.log").open("w",encoding="utf-8") as log:
        child=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,env=environment,cwd=ROOT,
            creationflags=subprocess.CREATE_NO_WINDOW)
        print("Ghidra PID",child.pid,"log",directory / "console.log",flush=True)
        metadata["pid"]=child.pid
        (directory / "command.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
        code=child.wait()
    metadata.update(exit_code=code,total_wall_ms=(time.perf_counter()-start)*1000)
    (directory / "command.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    print("Ghidra finished",code,metadata["total_wall_ms"],flush=True)
    if code or not (directory / "ghidra-post.json").exists():
        raise RuntimeError("Headless analysis/export failed; inspect console.log")


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("phase",choices=["scratcher","ghidra","smoke","ghidra-noauto"])
    phase=parser.parse_args().phase
    if phase=="scratcher":scratcher()
    else:ghidra(smoke=phase=="smoke",noauto=phase=="ghidra-noauto")
