"""Static CPU analysis comparison and independently decoded embedded fixtures."""
import argparse
import datetime
import hashlib
import json
import math
import pathlib
import statistics
import struct
import sys
import time
from mcp_client import Client, timed

ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/"reports/deep-analysis"
INDEPENDENT=ROOT/".tmp/independent-decode"
MANIFEST={
    "deep_bytes_lea_jump":{"length":32,"instructions":{0:7,7:2,16:5,21:1},"baseline_offsets":[0,7],"source":7,"target":16,"call":False},
    "deep_bytes_lea_call":{"length":32,"instructions":{0:7,7:2,9:1,16:5,21:1},"baseline_offsets":[0,7,9],"source":7,"target":16,"call":True},
    "deep_bytes_clobber":{"length":32,"instructions":{0:7,7:2,9:2},"baseline_offsets":[0,7,9],"forbidden_target":16},
    "deep_bytes_diamond":{"length":32,"instructions":{0:2,2:2,4:7,11:2,16:5,21:1},"baseline_offsets":[0,2,4,11],"source":11,"target":16,"call":False,"must_preserve_unknown_incoming":True,"target_optional":True},
}
DEFAULT_OPTIONS={"boundary_policy":"control_flow","instruction_budget":1000000,"byte_budget":4194304,
    "per_function_instruction_budget":4096,"function_budget":100000,"coverage_span_budget":100000,
    "discovery_rounds":8,"workers":8,"time_budget_ms":30000,"use_cache":False}

def identity(path):
    with path.open("rb")as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    return {"path":str(path.resolve()),"bytes":path.stat().st_size,"sha256":digest}

def union(ranges):
    result=[]
    for lo,hi in sorted(ranges):
        if hi<=lo:continue
        if result and lo<=result[-1][1]:result[-1]=(result[-1][0],max(hi,result[-1][1]))
        else:result.append((lo,hi))
    return result

def intersection(a,b):return union([(max(x,u),min(y,v))for x,y in a for u,v in b if max(x,u)<min(y,v)])
def extent(ranges):return sum(hi-lo for lo,hi in ranges)
def hexranges(ranges):return [{"start":hex(lo),"end":hex(hi)}for lo,hi in ranges]

def pe_exports(path):
    data=path.read_bytes()
    def read(fmt,off):
        if off<0 or off+struct.calcsize(fmt)>len(data):raise ValueError("Truncated PE")
        return struct.unpack_from(fmt,data,off)
    pe,=read("<I",0x3c)
    if data[pe:pe+4]!=b"PE\0\0":raise ValueError("Fixture is not PE")
    count,=read("<H",pe+6);optional_size,=read("<H",pe+20);opt=pe+24
    if read("<H",opt)[0]!=0x20b:raise ValueError("Fixture must be PE64")
    base,=read("<Q",opt+24);rva,size=read("<II",opt+112);sections=[]
    for n in range(count):
        at=opt+optional_size+n*40;virtual,r,raw,off=read("<IIII",at+8)
        sections.append({"rva":r,"size":raw,"offset":off,"virtual_size":virtual})
    def offset(rva,length=1):
        for s in sections:
            if s["rva"]<=rva and rva-s["rva"]+length<=s["size"]and s["offset"]+rva-s["rva"]+length<=len(data):return s["offset"]+rva-s["rva"]
        raise ValueError("Export is not file-backed")
    table=offset(rva,40);functions,names,ft,nt,ot=read("<IIIII",table+20);result={}
    for n in range(names):
        nr,=read("<I",offset(nt+n*4,4));at=offset(nr);end=data.find(b"\0",at,min(at+512,len(data)))
        if end<0:raise ValueError("Unterminated export")
        name=data[at:end].decode("ascii");ordinal,=read("<H",offset(ot+n*2,2))
        if ordinal>=functions:raise ValueError("Invalid export ordinal")
        fr,=read("<I",offset(ft+ordinal*4,4))
        if not rva<=fr<rva+size:result[name]={"address":base+fr,"offset":offset(fr)}
    return data,result

def collect(client,view):
    result=[]
    while True:
        page=client.tool("get_code_analysis",{"view":view,"offset":len(result),"limit":5000})
        result.extend(page["items"])
        if len(result)>=page["total"]:return result

def tool(client,name,args,timeout=90):
    result,wall=timed(client,name,args,timeout)
    return {"wall_ms":wall,"result":result,"memory":client.memory()}

def arguments(schema,options):return {k:v for k,v in options.items()if k in schema["inputSchema"]["properties"]}

def candidate_scope(info):
    file_ranges=[];code=[]
    for s in info["sections"]:
        at=int(s["address"],16);length=min(s["file_size"],s["memory_size"],max(0,info["size"]-s["file_offset"]))
        if length:
            file_ranges.append((at,at+length))
            if s["executable"]:code.append((at,at+length))
    code.extend((int(r["start"],16),int(r["end"],16))for r in info.get("analysis_candidate_ranges",[]))
    return intersection(union(code),union(file_ranges))

def coverage_audit(info,rows,summary):
    coverage=union([(int(r["start"],16),int(r["end"],16))for r in rows]);scope=candidate_scope(info)
    total=extent(scope);covered=extent(coverage)
    return {"original_candidate_bytes":total,"independent_unique_covered_bytes":covered,
        "coverage_outside_original_scope":covered-extent(intersection(coverage,scope)),
        "summary_covered_bytes_equal":covered==summary["covered_bytes"],
        "summary_denominator_equal":summary.get("candidate_code_bytes",total)==total,
        "original_candidate_coverage_percent":100*covered/total if total else 0,
        "coverage_ranges":hexranges(coverage),"candidate_ranges":hexranges(scope)}

def independent_expected(data,exports):
    sys.path.insert(0,str(INDEPENDENT))
    try:
        import iced_x86
    except ImportError:return {"available":False,"reason":"Independent iced_x86 decoder unavailable; exact source lengths still checked"}
    result={"available":True,"library":"iced_x86","version":"1.21.0 (installed metadata)","cases":{}}
    for name,case in MANIFEST.items():
        symbol=exports[name];rows=[]
        for relative,length in case["instructions"].items():
            code=data[symbol["offset"]+relative:symbol["offset"]+relative+15]
            instruction=iced_x86.Decoder(64,code,ip=symbol["address"]+relative).decode()
            rows.append({"relative_offset":relative,"address":hex(instruction.ip),"length":instruction.len,
                "source_length":length,"length_equal":instruction.len==length,"valid":not instruction.is_invalid,
                "original_bytes":code[:instruction.len].hex(),"text":str(instruction)})
        result["cases"][name]=rows
    return result

def analyze(client,schemas,info,options):
    opts=arguments(schemas["analyze_code_paths"],options)
    row={"options":opts,"unsupported_requested_options":sorted(set(options)-set(opts)),"code":tool(client,"analyze_code_paths",opts)}
    row["coverage"]=collect(client,"coverage")
    row["audit"]=coverage_audit(info,row["coverage"],row["code"]["result"])
    views=schemas["get_code_analysis"]["inputSchema"]["properties"]["view"].get("enum",[])
    row["transfers"]=collect(client,"transfers")if "transfers"in views else {"unavailable":"Preserved build does not export transfer pages"}
    refs={"code_policy":"reachable","instruction_budget":1000000,"byte_budget":8388608,"scan_data":False,"scan_relocations":False,"time_budget_ms":30000,"refresh":True}
    row["references_options"]=arguments(schemas["analyze_references"],refs)
    row["references"]=tool(client,"analyze_references",row["references_options"])
    row["reference_items"]=client.tool("get_analysis_references",{"limit":10000})
    return row

def one(exe,path,data,exports):
    with Client(exe)as client:
        schemas={t["name"]:t for t in client.rpc("tools/list")["tools"]}
        row={"server":client.initialization["serverInfo"],"open":tool(client,"open_binary",{"path":str(path)})}
        info=row["open"]["result"]
        row["whole_fixture"]=analyze(client,schemas,info,DEFAULT_OPTIONS)
        row["compiler_export_graphs"]={}
        for name in ["deep_branch","deep_loop","deep_switch","deep_readonly_dispatch","deep_mutable_dispatch"]:
            try:row["compiler_export_graphs"][name]=tool(client,"get_control_flow",{"address":hex(exports[name]["address"]),"instruction_budget":4096})
            except Exception as error:row["compiler_export_graphs"][name]={"error":str(error)}
        # Separate workspace for explicit, identical bounds. No bytes or PE flags changed.
        info=client.tool("open_binary",{"path":str(path)})
        indexed=[]
        while True:
            page=client.tool("list_functions",{"offset":len(indexed),"limit":10000});indexed.extend(page["items"])
            if len(indexed)>=page["total"]:break
        starts={int(f["address"],16)for f in indexed};row["manual_bounds"]=[];ranges=[]
        for name,case in MANIFEST.items():
            at=exports[name]["address"];args={"address":hex(at),"end":hex(at+case["length"])}
            operation="set_function_bounds"if at in starts else "create_function"
            if operation=="create_function":args["name"]=name
            row["manual_bounds"].append({"tool":operation,"arguments":args,"result":client.tool(operation,args)})
            ranges.append({"start":hex(at),"end":hex(at+case["length"])})
        row["embedded_arrays"]=analyze(client,schemas,info,DEFAULT_OPTIONS|{"scan_ranges":ranges})
        records=collect(client,"functions")
        scope=union([(int(r["start"],16),int(r["end"],16))for r in row["embedded_arrays"]["coverage"]])
        transfers=row["embedded_arrays"]["transfers"]
        checks=[]
        for name,case in MANIFEST.items():
            at=exports[name]["address"]
            expected=union([(at+off,at+off+length)for off,length in case["instructions"].items()])
            old_expected=union([(at+off,at+off+case["instructions"][off])for off in case["baseline_offsets"]])
            reached=intersection(scope,[(at,at+32)])
            evidence=[t for t in transfers if int(t["source"],16)>=at and int(t["source"],16)<at+32]if isinstance(transfers,list)else []
            record=next((f for f in records if int(f["address"],16)==at),None)
            references=row["embedded_arrays"]["reference_items"]["items"]
            reference_consistency=all(any(int(ref["from"],16)==int(t["source"],16)and int(ref["to"],16)==int(t["target"],16)
                and ref["kind"]==("recovered_indirect_call"if t["call"]else "recovered_indirect_jump")
                and ref.get("path_local")==t.get("path_local")and ref.get("residual_unknown")==t.get("residual_unknown")for ref in references)for t in evidence)
            checks.append({"name":name,"kind":"hand-authored x64 embedded bytecode, never executed",
                "start":hex(at),"expected_new_ranges":hexranges(expected),"expected_baseline_ranges":hexranges(old_expected),
                "actual_ranges":hexranges(reached),"expected_new_bytes":extent(expected),"actual_bytes":extent(reached),
                "matches_known_new_spans":reached==expected,"matches_known_baseline_spans":reached==old_expected,
                "matches_allowed_new_spans":reached==expected or (case.get("target_optional",False)and reached==old_expected),
                "transfer_evidence":evidence,
                "transfer_references_preserve_uncertainty":reference_consistency,
                "function_record":record,
                "constant_target_may_be_conservatively_absent":case.get("target_optional",False),
                "expected_transfer_present":any(int(t["source"],16)==at+case["source"]and int(t["target"],16)==at+case["target"]and t["call"]==case["call"]for t in evidence)if "source"in case else None,
                "stale_clobbered_target_absent":not any(int(t["target"],16)==at+case["forbidden_target"]for t in evidence)if "forbidden_target"in case else None,
                "all_register_evidence_retains_unknown":all(t.get("path_local")and t.get("residual_unknown")for t in evidence if t.get("provenance")=="path_local_register_constant")})
        row["embedded_checks"]=checks
        return row

def stats(values):
    values=sorted(values)
    return {"median":statistics.median(values),"p95":values[max(0,math.ceil(len(values)*.95)-1)],"population_variance":statistics.pvariance(values),"count":len(values)}

def heavy_one(exe,path,repetition):
    with Client(exe)as client:
        schemas={t["name"]:t for t in client.rpc("tools/list")["tools"]}
        row={"server":client.initialization["serverInfo"],"open":tool(client,"open_binary",{"path":str(path)})}
        options=DEFAULT_OPTIONS|{"instruction_budget":5000000,"byte_budget":67108864,"time_budget_ms":60000,
            "per_function_instruction_budget":100000,"function_budget":1000000,"coverage_span_budget":500000,"discovery_rounds":32}
        row["options"]=arguments(schemas["analyze_code_paths"],options)
        row["unsupported_requested_options"]=sorted(set(options)-set(row["options"]))
        # Older schemas capped rounds at eight. Use the shared accepted limit and
        # explicitly report it, rather than failing or hiding a different budget.
        for key in ["discovery_rounds"]:
            maximum=schemas["analyze_code_paths"]["inputSchema"]["properties"].get(key,{}).get("maximum")
            if maximum and row["options"].get(key,0)>maximum:row["options"][key]=maximum
        row["code"]=tool(client,"analyze_code_paths",row["options"],timeout=120)
        coverage=collect(client,"coverage")
        row["audit"]=coverage_audit(row["open"]["result"],coverage,row["code"]["result"])
        if repetition:
            intervals=row["audit"].pop("coverage_ranges")
            row["audit"]["coverage_range_storage"]={"count":len(intervals),"sha256":hashlib.sha256(json.dumps(intervals,separators=(",",":")).encode()).hexdigest(),"note":"Complete intervals retained for first fresh process of this input/build; summary audited in every repetition"}
        views=schemas["get_code_analysis"]["inputSchema"]["properties"]["view"].get("enum",[])
        if "transfers"in views:
            transfers=collect(client,"transfers")
            row["transfer_evidence"]={"retained":len(transfers),"path_local_candidates":sum(t.get("path_local",False)for t in transfers),
                "residual_unknown":sum(t.get("residual_unknown",False)for t in transfers),"sample":transfers[:100],
                "sha256":hashlib.sha256(json.dumps(transfers,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
        else:row["transfer_evidence"]={"unavailable":"Preserved build does not expose transfer pages"}
        refs={"code_policy":"reachable","instruction_budget":5000000,"byte_budget":67108864,"time_budget_ms":60000,
            "memory_budget":134217728,"reference_limit":2000000,"scan_data":False,"scan_relocations":False,"refresh":True}
        row["references_options"]=arguments(schemas["analyze_references"],refs)
        row["references"]=tool(client,"analyze_references",row["references_options"],timeout=120)
        row["reference_sample"]=client.tool("get_analysis_references",{"limit":100})
        return row

def markdown(report):
    lines=["# Deep CPU analysis validation","","The hand-authored x64 arrays are embedded executable-section test data, not compiler-generated functions, and are never executed. The compiler-generated C++ exports are measured separately. All timing sessions are fresh processes; no OS cache flush. Unique covered intervals are independently audited against original file-backed candidate regions; candidate coverage is not semantic accuracy.","",
        "| Build/input | Whole code median ms | Embedded code median ms | Original candidate bytes | Embedded uniquely reached bytes |",
        "|---|---:|---:|---:|---:|"]
    for case in report["cases"]:
        r=case["runs"][0]
        lines.append(f"| {case['variant']} / {case['input']['path']} | {case['timings']['whole_fixture']['median']:.3f} | {case['timings']['embedded_arrays']['median']:.3f} | {r['embedded_arrays']['audit']['original_candidate_bytes']} | {r['embedded_arrays']['audit']['independent_unique_covered_bytes']} |")
    if report.get("heavy_cases"):
        lines.extend(["","Optional bounded original-file passes: 5 million examined instructions, 64 MiB decoded bytes, 60 seconds, 100,000 instructions/function; requested 32 discovery rounds. Every accepted option and limit is retained. Earlier builds that reject 32 rounds use their schema maximum, explicitly recorded. No analysis/capture target is executed. References are separately bounded and scan only reachable candidates; data/relocations disabled.","",
            "| Input/build | Code median ms | Unique candidate bytes / original candidate bytes | Resolved register candidates / residual indirect edges | Peak working set MiB |",
            "|---|---:|---:|---:|---:|"])
        for case in report["heavy_cases"]:
            r=case["runs"][0];s=r["code"]["result"];a=r["audit"]
            lines.append(f"| {case['input']['path']} / {case['variant']} | {case['timings']['code']['median']:.3f} | {a['independent_unique_covered_bytes']:,} / {a['original_candidate_bytes']:,} | {s.get('resolved_register_indirect_edges','unavailable')} / {s.get('unresolved_indirect_edges','unavailable')} | {r['references']['memory']['peak_working_set_mib']:.2f} |")
        lines.extend(["","Budgets and unresolved edges limit these passes. Original candidate denominators are fixed for each exact input; memory/coverage/transfer evidence are descriptive measurements, not proof of valid recovered functions or source-equivalent semantics. The complete independently audited coverage interval union is retained for each first input/build trial."])
    lines.extend(["","Every report retains the exact options, budgets, stop flags, executable/input hashes, memory counters, paged coverage, transfer evidence, reference evidence, and independently decoded expected instruction lengths. Straight-line register-derived targets remain path-local candidates with residual unknown incoming routes. The clobber fixture must not reuse the earlier LEA target; the diamond bypass must not be reported globally closed.","",
        "This readable fixture does not establish Roblox recovery, a 70% Roblox result, full decompilation equivalence, or parity with Ghidra. No Ghidra pass or Roblox capture is performed.",""])
    (OUT/"comparison.md").write_text("\n".join(lines),encoding="utf-8")

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--baseline",type=pathlib.Path,default=ROOT/"dist-v0.6/ScratcherMCP.exe")
    parser.add_argument("--current",type=pathlib.Path,default=ROOT/"build/Release/ScratcherMCP.exe")
    parser.add_argument("--fixture",type=pathlib.Path,action="append");parser.add_argument("--runs",type=int,default=3)
    parser.add_argument("--heavy",type=pathlib.Path,action="append",help="Optional static heavy original; uses bounded CPU passes, never executed")
    args=parser.parse_args();fixtures=args.fixture or [ROOT/"build/Release/ScratcherDeepFixtureOd.exe",ROOT/"build/Release/ScratcherDeepFixtureO2.exe"]
    report={"date":datetime.datetime.now().astimezone().isoformat(),"method":"Static CLI/MCP read-only originals; three fresh processes per build/input, no target execution, no Computer Use, no cache flush; whole fixture and explicit-bound embedded cases use separate workspaces. CPU wall timings include MCP JSON/dispatch; process startup excluded. Machine byte spans are independently decoded when iced_x86 is available.",
        "validation_status":"in_progress","source":identity(ROOT/"examples/deep_analysis_fixture.cpp"),
        "source_hashes":[identity(p)for p in sorted((ROOT/"src").glob("*"))if p.is_file()and (p.name in ["feature_auto_code.cpp","feature_advanced_analysis.cpp","feature_graph.cpp","feature_auto_references.cpp"]or "flow_const"in p.name)]+[identity(pathlib.Path(__file__)),identity(ROOT/"examples/deep_analysis_fixture.cpp")],
        "manifest":MANIFEST,"cases":[],"heavy_cases":[],"independent_decode":{}}
    OUT.mkdir(parents=True,exist_ok=True)
    for path in fixtures:
        data,exports=pe_exports(path);report["independent_decode"][str(path)]=independent_expected(data,exports)
        for variant,exe in [("0.6 preserved",args.baseline),("current",args.current)]:
            case={"variant":variant,"executable":identity(exe),"input":identity(path),"exports":{n:{"address":hex(v["address"]),"offset":v["offset"]}for n,v in exports.items()if n.startswith("deep_")},"runs":[]}
            for repetition in range(args.runs):
                print(variant,path.name,"run",repetition+1,flush=True);case["runs"].append(one(exe,path,data,exports))
            case["timings"]={name:stats([r[name]["code"]["wall_ms"]for r in case["runs"]])for name in ["whole_fixture","embedded_arrays"]}
            report["cases"].append(case)
            (OUT/"comparison.json").write_text(json.dumps(report,indent=2),encoding="utf-8");markdown(report)
    for path in args.heavy or []:
        for variant,exe in [("0.6 preserved",args.baseline),("current",args.current)]:
            case={"variant":variant,"executable":identity(exe),"input":identity(path),"runs":[]}
            for repetition in range(args.runs):
                print(variant,path.name,"bounded heavy run",repetition+1,flush=True)
                case["runs"].append(heavy_one(exe,path,repetition))
            case["timings"]={name:stats([r[name]["wall_ms"]for r in case["runs"]])for name in ["open","code","references"]}
            report["heavy_cases"].append(case)
            (OUT/"comparison.json").write_text(json.dumps(report,indent=2),encoding="utf-8");markdown(report)
    invalid=[(c["variant"],c["input"]["path"])for c in report["cases"]for r in c["runs"]for name in ["whole_fixture","embedded_arrays"]if not r[name]["audit"]["summary_covered_bytes_equal"]or not r[name]["audit"]["summary_denominator_equal"]or r[name]["audit"]["coverage_outside_original_scope"]]
    invalid.extend((c["variant"],c["input"]["path"])for c in report["heavy_cases"]for r in c["runs"]if not r["audit"]["summary_covered_bytes_equal"]or not r["audit"]["summary_denominator_equal"]or r["audit"]["coverage_outside_original_scope"])
    if invalid:raise RuntimeError("Independent coverage audit failed: "+str(invalid))
    for c in report["cases"]:
        if c["variant"]!="current":continue
        for r in c["runs"]:
            for check in r["embedded_checks"]:
                if not check["matches_allowed_new_spans"]or check["stale_clobbered_target_absent"]is False or not check["all_register_evidence_retains_unknown"]or not check["transfer_references_preserve_uncertainty"]:
                    raise RuntimeError("Embedded fixture evidence invariant failed: "+check["name"])
                if check["expected_transfer_present"]is False and not check["constant_target_may_be_conservatively_absent"]:
                    raise RuntimeError("Expected register transfer missing: "+check["name"])
                if check["name"]=="deep_bytes_diamond"and check["function_record"]and check["function_record"].get("traversal_closed"):
                    raise RuntimeError("Diamond with unknown incoming register was falsely marked closed")
    for decoding in report["independent_decode"].values():
        if decoding["available"]and not all(r["length_equal"]and r["valid"]for rows in decoding["cases"].values()for r in rows):
            raise RuntimeError("Independent bytecode decoder disagreed with source manifest")
    report["validation_status"]="passed"
    report["completed_fresh_processes"]=sum(len(c["runs"])for c in report["cases"]+report["heavy_cases"])
    (OUT/"comparison.json").write_text(json.dumps(report,indent=2),encoding="utf-8");markdown(report)
    print(OUT/"comparison.md",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as error:
        OUT.mkdir(parents=True,exist_ok=True)
        (OUT/"validation-failure.json").write_text(json.dumps({"validation_status":"failed","error":str(error)},indent=2),encoding="utf-8")
        saved=OUT/"comparison.json"
        if saved.exists():
            partial=json.loads(saved.read_text(encoding="utf-8"));partial["validation_status"]="failed";partial["error"]=str(error)
            saved.write_text(json.dumps(partial,indent=2),encoding="utf-8")
        raise
