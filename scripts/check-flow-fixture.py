"""Read-only fixture regression: independent coverage union and graph byte audit."""
import hashlib
import json
import pathlib
import sys
from mcp_client import Client, timed

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports/coverage-70/readable-fixture-regression.json"
INPUT = ROOT / "build/Release/ScratcherAnalysisFixture.exe"
OPTIONS = {"instruction_budget": 100000000, "byte_budget": 536870912, "time_budget_ms": 30000,
    "per_function_instruction_budget": 4096, "function_budget": 1000000,
    "coverage_span_budget": 4000000, "workers": 8, "discovery_rounds": 3, "use_cache": False}

def sha(path):
    with path.open("rb") as source: return hashlib.file_digest(source,"sha256").hexdigest()

def union(ranges):
    result=[]
    for lo,hi in sorted(ranges):
        if hi<=lo: continue
        if result and lo<=result[-1][1]: result[-1]=(result[-1][0],max(result[-1][1],hi))
        else: result.append((lo,hi))
    return result

def extent(ranges): return sum(hi-lo for lo,hi in ranges)

def intersection(a,b):
    result=[]
    for lo,hi in a:
        for start,end in b:
            if end<=lo: continue
            if start>=hi: break
            if min(hi,end)>max(lo,start): result.append((max(lo,start),min(hi,end)))
    return union(result)

def pages(client, view):
    result=[]
    while True:
        page=client.tool("get_code_analysis",{"view":view,"offset":len(result),"limit":5000})
        result.extend(page["items"])
        if len(result)>=page["total"]: return result

def run(executable,policy):
    result={"executable":str(executable),"executable_sha256":sha(executable),"policy":policy}
    data=INPUT.read_bytes()
    with Client(executable) as client:
        info=client.tool("open_binary",{"path":str(INPUT)})
        schema=next(t for t in client.rpc("tools/list")["tools"]if t["name"]=="analyze_code_paths")
        args=dict(OPTIONS)
        if "boundary_policy" in schema["inputSchema"]["properties"]: args["boundary_policy"]=policy
        elif policy!="next_seed": raise RuntimeError("Preserved release does not implement control_flow policy")
        result["options"]=args
        summary,wall=timed(client,"analyze_code_paths",args,90)
        result["analysis"]={"wall_ms":wall,"result":summary}
        coverage=union([(int(r["start"],16),int(r["end"],16))for r in pages(client,"coverage")])
        file_ranges=[]
        executable_ranges=[]
        for section in info["sections"]:
            lo=int(section["address"],16)
            length=min(section["file_size"],section["memory_size"],max(0,len(data)-section["file_offset"]))
            if length:
                file_ranges.append((lo,lo+length))
                if section["executable"]: executable_ranges.append((lo,lo+length))
        candidates=union(executable_ranges+[(int(r["start"],16),int(r["end"],16))for r in info.get("analysis_candidate_ranges",[])])
        candidates=intersection(candidates,union(file_ranges))
        unique=extent(coverage)
        inside=extent(intersection(coverage,candidates))
        result["coverage_audit"]={"original_candidate_bytes":extent(candidates),"unique_coverage_bytes":unique,
            "coverage_outside_candidates":unique-inside,"summary_covered_bytes_match":unique==summary["covered_bytes"],
            "summary_candidate_bytes_match":summary.get("candidate_code_bytes",extent(candidates))==extent(candidates),
            "coverage_percent":100*inside/extent(candidates),"union_spans":len(coverage),
            "candidate_ranges":[[hex(a),hex(b)]for a,b in candidates],"coverage_ranges":[[hex(a),hex(b)]for a,b in coverage]}
        functions=client.tool("list_functions",{"limit":10000})["items"]
        result["graphs"]=[]
        for name in ["fixture_branch","fixture_switch"]:
            target=next(f for f in functions if f["name"]==name)
            graph=client.tool("get_control_flow",{"address":target["address"],"instruction_budget":4096})
            rows=[i for node in graph["nodes"]for i in node["instructions"]]
            audited=[]
            for ins in rows:
                at=int(ins["address"],16)
                section=next(s for s in info["sections"]if int(s["address"],16)<=at<int(s["address"],16)+min(s["file_size"],s["memory_size"]))
                off=section["file_offset"]+at-int(section["address"],16)
                expected=bytes.fromhex(ins["bytes"])
                audited.append({"address":ins["address"],"length":ins["length"],"bytes":ins["bytes"],
                    "original_file_match":len(expected)==ins["length"]and data[off:off+ins["length"]]==expected})
            result["graphs"].append({"name":name,"address":target["address"],"instruction_count":graph["instruction_count"],
                "blocks":len(graph["nodes"]),"complete":graph["complete"],"instructions":sorted(audited,key=lambda i:int(i["address"],16)),
                "edges":graph["edges"],"switch_tables":graph.get("switch_tables",[]),"all_instruction_bytes_match":all(i["original_file_match"]for i in audited)})
        result["memory"]=client.memory()
    return result

def main():
    report={"input":str(INPUT),"input_sha256":sha(INPUT),"input_size":INPUT.stat().st_size,
        "method":"Fresh stdio MCP processes; identical original readable PE; input never executed; no desktop automation; no OS cache flush; no headless rerun. All scope/coverage counts independently reconstructed from original mapped file-backed sections and paged coverage intervals.",
        "runs":[run(ROOT/"dist-v0.5/ScratcherMCP.exe","next_seed"),run(ROOT/"build/Release/ScratcherMCP.exe","next_seed"),run(ROOT/"build/Release/ScratcherMCP.exe","control_flow")]}
    baseline,current,flow=report["runs"]
    report["comparisons"]={}
    for target in [current,flow]:
        key=target["policy"]
        pairs=[]
        for a,b in zip(baseline["graphs"],target["graphs"]):
            pairs.append({"name":a["name"],"same_instruction_addresses_lengths_and_bytes":a["instructions"]==b["instructions"],
                "same_graph_edges":a["edges"]==b["edges"],"same_blocks":a["blocks"]==b["blocks"]})
        report["comparisons"][key]={"candidate_denominator_unchanged":baseline["coverage_audit"]["original_candidate_bytes"]==target["coverage_audit"]["original_candidate_bytes"],
            "unique_coverage_delta":target["coverage_audit"]["unique_coverage_bytes"]-baseline["coverage_audit"]["unique_coverage_bytes"],"graphs":pairs}
    previous=json.loads((ROOT/"reports/v0.5/ghidra-fixture/ghidra-samples.json").read_text(encoding="utf-8"))
    report["previous_ghidra_counts"]=[{k:g[k]for k in ["name","address","instructions","blocks"]}for g in previous if g["name"]in["fixture_branch","fixture_switch"]]
    report["limitations"]=["Only this readable controlled fixture is measured; its percentage does not establish Roblox 70% coverage.",
        "Decoded coverage and equal graph instruction bytes do not prove function ownership, type accuracy or semantic equivalence.",
        "Previous Ghidra samples retain counts and pseudocode but do not export instruction address sets; exact address equivalence against Ghidra cannot be established from that evidence.",
        "Next-seed versus control-flow recovery can discover overlapping traversals; unique interval union, not summed decoded_bytes, is used."]
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps({"input_sha256":report["input_sha256"],"audit":[r["coverage_audit"]|{"coverage_ranges":"omitted"}for r in report["runs"]],"comparisons":report["comparisons"]},indent=2))
    if not all(r["coverage_audit"]["summary_covered_bytes_match"]and r["coverage_audit"]["summary_candidate_bytes_match"]and r["coverage_audit"]["coverage_outside_candidates"]==0 and all(g["all_instruction_bytes_match"]for g in r["graphs"])for r in report["runs"]): sys.exit(1)

if __name__=="__main__":main()
