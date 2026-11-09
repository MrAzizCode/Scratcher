"""Independent stop-site taxonomy plus bounded, fresh-process CPU comparisons.

Never executes an input, reads a process, transforms bytes, or resynchronizes a
decoder after an invalid encoding. Live phases require an explicit CLI action.
"""
import argparse
import collections
import datetime
import hashlib
import json
import math
import pathlib
import re
import statistics
import sys
from mcp_client import Client, timed

ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/"reports/deep-next"
ORIGINAL=ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe"
CHROME=pathlib.Path("C:/Program Files/Google/Chrome/Application/155.0.8059.40/chrome.dll")
BASELINE=ROOT/"dist-v0.7/ScratcherMCP.exe"
CURRENT=ROOT/"build/Release/ScratcherMCP.exe"
INDEPENDENT=ROOT/".tmp/independent-decode"
ORIGINAL_SHA="11a30ada177d15a9ec1c1dc30957b28b46839c9c6407e53be6138d2f12f6f2fe"
KNOWN_ORIGINALS={"RobloxPlayerBeta-0.742.exe":ORIGINAL_SHA,
    "RobloxPlayerBeta-0.743.exe":"68edd5ccc8543fadf1e5d38fa64b35837fbe93cb622277e1aeafdb3c3ae8dd53"}
OPTIONS={"boundary_policy":"control_flow","instruction_budget":5000000,"byte_budget":67108864,
    "time_budget_ms":60000,"per_function_instruction_budget":100000,"function_budget":1000000,
    "coverage_span_budget":500000,"discovery_rounds":32,"workers":8,"use_cache":False}

def read(path):return json.loads(path.read_text(encoding="utf-8"))
def save(name,value):
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/name).write_text(json.dumps(value,indent=2),encoding="utf-8")
def identity(path):
    with path.open("rb")as source:digest=hashlib.file_digest(source,"sha256").hexdigest()
    return {"path":str(path.resolve()),"bytes":path.stat().st_size,"sha256":digest}
def source_hashes():
    paths=[pathlib.Path(__file__),ROOT/"scripts/mcp_client.py"]
    paths.extend(p for p in sorted((ROOT/"src").glob("*"))if p.is_file()and p.name in ["feature_auto_code.cpp","feature_auto_code.hpp","feature_flow_constants.cpp","feature_flow_constants.hpp","feature_advanced_analysis.cpp","feature_graph.cpp","feature_auto_references.cpp"])
    return [identity(p)for p in paths]
def union(ranges):
    result=[]
    for lo,hi in sorted(ranges):
        if hi<=lo:continue
        if result and lo<=result[-1][1]:result[-1]=(result[-1][0],max(hi,result[-1][1]))
        else:result.append((lo,hi))
    return result
def extent(ranges):return sum(hi-lo for lo,hi in ranges)
def intersect(a,b):return union((max(x,u),min(y,v))for x,y in a for u,v in b if max(x,u)<min(y,v))
def hexranges(ranges):return [{"start":hex(a),"end":hex(b)}for a,b in ranges]
def candidate_scope(info):
    physical=[];candidates=[]
    for section in info["sections"]:
        lo=int(section["address"],16);length=min(section["file_size"],section["memory_size"],max(0,info["size"]-section["file_offset"]))
        if not length:continue
        physical.append((lo,lo+length))
        if section["executable"]:candidates.append((lo,lo+length))
    candidates.extend((int(r["start"],16),int(r["end"],16))for r in info.get("analysis_candidate_ranges",[]))
    return intersect(union(candidates),union(physical))
def pages(client,view):
    rows=[];last=None
    while True:
        last=client.tool("get_code_analysis",{"view":view,"offset":len(rows),"limit":5000},timeout=90)
        rows.extend(last["items"])
        if len(rows)>=last["total"]:return rows,last
        if not last["items"]:raise RuntimeError("Empty page before total reached")
def accepted(schema,options):
    props=schema["inputSchema"]["properties"]
    result={k:v for k,v in options.items()if k in props}
    for k,v in list(result.items()):
        if isinstance(v,int)and not isinstance(v,bool)and "maximum"in props[k]and v>props[k]["maximum"]:
            raise RuntimeError(f"Requested common budget {k}={v} exceeds schema max {props[k]['maximum']}; do not silently change comparison work")
    return result
def stats(values):
    values=sorted(values)
    return {"count":len(values),"median":statistics.median(values),"p95":values[max(0,math.ceil(len(values)*.95)-1)],"population_variance":statistics.pvariance(values),"min":values[0],"max":values[-1]}

def existing():
    """Reads established reports only; deliberately does not rerun old probes."""
    folder=ROOT/"reports/coverage-70"
    decoder=read(folder/"independent-decoder.json")
    transform=read(folder/"transform-probe.json")
    conditional=read(folder/"existing-code-image.json")
    flow=read(folder/"control-flow-discovery-32.json")
    diagnostics=read(folder/"diagnostics.json")
    evidence={"phase":"existing_evidence_only","created":datetime.datetime.now().astimezone().isoformat(),
        "method":"Read prior saved evidence; no new decoder comparison, XOR/transform probe, MCP process, target execution, capture or process access.",
        "prior_artifacts":[identity(folder/n)for n in ["independent-decoder.json","transform-probe.json","existing-code-image.json","control-flow-discovery-32.json","diagnostics.md"]],
        "original_sha256_previously_verified":ORIGINAL_SHA,
        "original_candidate_bytes":102242816,"required_70_percent_unique_bytes":71569972,
        "previous_original_control_flow_runs":[{k:v for k,v in r.items()if k in ["covered_bytes","coverage_percent","analysis_wall_ms","target_met"]}for r in flow["runs"]],
        "previous_decoder_counters":[{"path":s["path"],"sha256":s["sha256"],"provenance":s["provenance"],"counters":s["counters"]}for s in decoder["sources"]],
        "previous_transform_probe":{"transformation_validated":transform["transformation_validated"],"whole_image_recovery_ready":transform["whole_image_recovery_ready"]},
        "conditional_source":{"whole_image_provenance_verified":conditional["whole_image_provenance_verified"],"read_success_verified_bytes":conditional["read_success_verified_bytes"],"source_has_read_success_bitmap":conditional["source_has_read_success_bitmap"],"inferred_identity":conditional["inferred_identity"]},
        "old_stop_attribution_limit":"Old per-function observed maximum ends are not exact failure addresses. Existing full-width observed-end probes cannot establish first-seed versus downstream failure-site populations.",
        "old_traversal_population":diagnostics["traversal_population"],
        "next_measurement":"Bounded exact stop pages: classify each retained PC with original file-backed bytes, at most15 bytes, strict iced_x86 once at the exact stop PC; no byte skipping or new coverage credit.",
        "inputs_executed":False,"process_reads":False,"new_coverage_added_bytes":0}
    save("existing-evidence.json",evidence)
    text=["# Existing evidence and next stop-site measurement","",
        "The previous 32-round original-file pass reached 3,321,405 unique bytes (3.248546%) of the fixed 102,242,816-byte candidate scope. These are decoded instruction candidates, not source-equivalent function recovery. The 70% goal remains unverified.","",
        "The saved strict independent-decoder comparison already rejected the same 253 sampled native failure encodings in the original file, with zero sampled validity or length disagreements. That sample does not classify the full stop population. No decoder or XOR comparison was rerun for this report.","",
        "Previous transformation probes did not validate a whole-image transformation. The conditional image lacks a verified read-success bitmap and whole-image provenance; it remains separate from original-file recovery.","",
        "Old observed maximum function ends can belong to another branch. Exact stop PCs, seed/path attribution, decoder byte count and bounded completeness metadata are required to distinguish seed-entry rejection, downstream invalid encoding, clipped decoder windows and unresolved indirect operands.","",
        "The prepared classifier reads up to the full remaining 15 original file-backed bytes at each retained exact stop PC. It decodes once without resynchronization, retains disagreements/counterexamples, deduplicates site counts separately from event counts and reports incomplete evidence caps. Independent acceptance does not add coverage or prove executable code.",""]
    (OUT/"existing-evidence.md").write_text("\n".join(text),encoding="utf-8")
    print(OUT/"existing-evidence.md",flush=True)

class OriginalReader:
    def __init__(self,path,info):self.data=path.read_bytes();self.info=info
    def bytes_at(self,at,count=15):
        for s in self.info["sections"]:
            lo=int(s["address"],16);delta=at-lo;length=min(s["memory_size"],s["file_size"])
            if 0<=delta<length:
                off=s["file_offset"]+delta;return self.data[off:min(off+count,s["file_offset"]+length,len(self.data))],s,off
        return b"",None,None

def indirect_classification(ins,iced,reader,imports):
    kinds={iced.FlowControl.INDIRECT_CALL:"indirect_call",iced.FlowControl.INDIRECT_BRANCH:"indirect_jump"}
    result={"flow":kinds.get(ins.flow_control,"other"),"operand_category":"not_indirect"}
    if result["flow"]=="other":return result
    if ins.op0_kind==iced.OpKind.REGISTER:
        result.update(operand_category="register",register=int(ins.op0_register));return result
    if ins.op0_kind!=iced.OpKind.MEMORY:
        result.update(operand_category="other_operand",op0_kind=int(ins.op0_kind));return result
    result.update(memory_base=int(ins.memory_base),memory_index=int(ins.memory_index),memory_scale=int(ins.memory_index_scale))
    if ins.memory_segment in [iced.Register.FS,iced.Register.GS]:
        result.update(operand_category="segmented_memory",segment=int(ins.memory_segment))
        return result
    slot=None
    if ins.is_ip_rel_memory_operand:slot=ins.ip_rel_memory_address;result["operand_category"]="ip_relative_fixed_memory"
    elif ins.memory_base==iced.Register.NONE and ins.memory_index==iced.Register.NONE:slot=ins.memory_displacement;result["operand_category"]="absolute_fixed_memory"
    elif ins.memory_index!=iced.Register.NONE:result["operand_category"]="indexed_memory"
    else:result["operand_category"]="register_based_memory"
    if slot is not None:
        result["slot"]=hex(slot);data,section,_=reader.bytes_at(slot,8)
        # Import slots remain runtime mutable even if the declared section is R.
        overlap=[i for i in imports if slot<int(i["address"],16)+8 and slot+8>int(i["address"],16)]
        result.update(slot_import_overlap=overlap,slot_file_backed_bytes=len(data),slot_writable=section["writable"]if section else None)
        if len(data)==8:
            target=int.from_bytes(data,"little");result["stored_pointer"]=hex(target)
            _,target_section,_=reader.bytes_at(target,1);result["stored_pointer_file_backed"]=target_section is not None
    return result

def classify_row(row,reader,iced,imports):
    address=int(row["address"],16);seed=int(row["seed"],16);full,section,offset=reader.bytes_at(address,15)
    supplied=int(row.get("bytes_supplied_to_decoder",0));native=bytes.fromhex(row.get("bytes",""))
    result={"stop":row,"stratum":"seed_entry"if address==seed and row.get("first_instruction")else "downstream",
        "path_entry":row.get("path_instructions_before_stop")==0,"full_file_backed_bytes":full.hex(),"full_available":len(full),
        "file_offset":offset,"section":section["name"]if section else None,
        "supplied_byte_prefix_matches_original":not native or native==full[:len(native)],"native_supplied_count":supplied}
    if not full:result["independent_class"]="no_file_backed_bytes";return result
    ins=iced.Decoder(64,full,ip=address).decode()
    result["independent"]={"valid":not ins.is_invalid,"length":ins.len,"text":str(ins),"flow_control":int(ins.flow_control)}
    if row["reason"] in ["invalid_decode","operand_decode_failure"]:
        if ins.is_invalid:result["independent_class"]="strict_independent_rejection"
        elif supplied and ins.len>supplied:result["independent_class"]="accepted_with_full_file_bytes_exceeds_native_window"
        else:result["independent_class"]="independent_acceptance_requires_review_no_coverage_credit"
    elif ins.is_invalid:result["independent_class"]="non_decode_stop_but_independent_encoding_invalid"
    else:result["independent_class"]="valid_encoding_at_non_decode_stop"
    if not ins.is_invalid:result["indirect"]=indirect_classification(ins,iced,reader,imports)
    if supplied:
        short=iced.Decoder(64,full[:min(supplied,len(full))],ip=address).decode()
        result["independent_native_window"]={"valid":not short.is_invalid,"length":short.len}
    return result

def diagnose(args):
    sys.path.insert(0,str(INDEPENDENT));import iced_x86
    source=identity(args.input)
    expected=KNOWN_ORIGINALS.get(args.input.name)
    if expected and source["sha256"]!=expected:raise RuntimeError("Original benchmark input hash changed")
    label=re.sub(r"[^A-Za-z0-9_.-]+","-",args.label or args.input.stem)
    if args.switch_address and not args.label:label+="-selected-switch"
    with Client(args.current)as client:
        schemas={t["name"]:t for t in client.rpc("tools/list")["tools"]}
        views=schemas["get_code_analysis"]["inputSchema"]["properties"]["view"].get("enum",[])
        if "stops"not in views:raise RuntimeError("Build does not expose exact stop pages; no observed-end substitution allowed")
        info=client.tool("open_binary",{"path":str(args.input)})
        imports=client.tool("list_imports")["items"]
        requested=OPTIONS|{"stop_limit":args.stop_limit}
        if args.switch_address:
            if len(set(args.switch_address))>256:raise RuntimeError("Selected switch experiment is capped at256 explicit indexed functions")
            requested.update(switch_functions=list(dict.fromkeys(args.switch_address)),switch_instruction_budget=4096,switch_time_budget_ms=100,switch_transfer_limit=4096)
        options=accepted(schemas["analyze_code_paths"],requested)
        if args.switch_address and "switch_functions"not in options:raise RuntimeError("Selected switch experiment unavailable in this build")
        if "stop_limit"not in options:raise RuntimeError("Stop retention budget is unavailable")
        summary,wall=timed(client,"analyze_code_paths",options,timeout=120)
        stops,page=pages(client,"stops");coverage,_=pages(client,"coverage")
        spans=union((int(r["start"],16),int(r["end"],16))for r in coverage);scope=candidate_scope(info)
        if extent(spans)!=summary["covered_bytes"]or extent(scope)!=summary["candidate_code_bytes"]or extent(intersect(spans,scope))!=extent(spans):raise RuntimeError("Independent scope/coverage union audit failed")
        reader=OriginalReader(args.input,info);counts=collections.Counter();reason=collections.Counter();sites=collections.defaultdict(set);strata=collections.Counter();categories=collections.Counter();samples=collections.defaultdict(list);switches=collections.Counter();mismatch=0
        raw_path=OUT/f"exact-stops-{label}.jsonl";OUT.mkdir(parents=True,exist_ok=True)
        with raw_path.open("w",encoding="utf-8")as raw:
            for stop in stops:
                row=classify_row(stop,reader,iced_x86,imports)
                raw.write(json.dumps(row,separators=(",",":"))+"\n")
                reason[stop["reason"]]+=1;counts[row["independent_class"]]+=1
                sites[(stop["reason"],row["stratum"])].add(int(stop["address"],16));strata[(stop["reason"],row["stratum"])]+=1
                category=row.get("indirect",{}).get("operand_category")
                if category:categories[(stop["reason"],category)]+=1
                if "indirect_jump"in stop["reason"]and category in ["register","indexed_memory"]:switches[stop["seed"]]+=1
                key=(stop["reason"],row["stratum"],row["independent_class"])
                if len(samples[key])<16:samples[key].append(row)
                mismatch+=not row["supplied_byte_prefix_matches_original"]
        report={"phase":"exact_stop_classification","experiment_label":label,"old_0_742_goal_experiment":source["sha256"]==ORIGINAL_SHA and not args.conditional_input,
            "input_provenance":"Conditional raw-derived analysis image; no whole-image provenance/read-success claim or original-file coverage credit"if args.conditional_input else "Known immutable original on-disk binary"if expected else "Supplied immutable file; provenance not established by decoding",
            "selected_switch_functions":args.switch_address or [],"input":source,"executable":identity(args.current),"source_hashes":source_hashes(),"options":options,"analysis_wall_ms":wall,"analysis":summary,
            "stop_page_metadata":{k:v for k,v in page.items()if k!="items"},"events_classified":len(stops),
            "independent_decoder":{"name":"iced_x86","bits":64,"version":"1.21.0","method":"One strict decode at each exact retained stop PC using at most the full remaining15 original file-backed bytes. No invalid-byte skipping, stream resynchronization, byte transformation or added coverage."},
            "event_counts_by_reason":dict(reason),"independent_class_counts":dict(counts),
            "stratified_counts":[{"reason":r,"stratum":s,"events":n,"unique_stop_sites":len(sites[(r,s)])}for (r,s),n in sorted(strata.items())],
            "unique_stop_sites_all_reasons":len({int(s["address"],16)for s in stops}),
            "indirect_operand_categories":[{"reason":r,"operand_category":c,"events":n}for (r,c),n in sorted(categories.items())],
            "samples":[{"reason":r,"stratum":s,"classification":c,"items":rows}for (r,s,c),rows in sorted(samples.items())],
            "candidate_switch_functions":[{"address":a,"retained_indirect_jump_events":n,"status":"candidate only; no switch/function closure inferred"}for a,n in switches.most_common(128)],
            "raw_classified_events":identity(raw_path),"original_byte_prefix_mismatches":mismatch,"coverage_audit":{"original_candidate_bytes":extent(scope),"unique_covered_bytes":extent(spans),"uncovered_original_candidate_bytes":extent(scope)-extent(spans)},
            "memory":client.memory(),"inputs_executed":False,"process_reads":False,"coverage_added_by_classification":0,
            "limitations":["Event counts and unique stop PCs are different populations; a site may occur on multiple seed paths.","Retained evidence may be bounded; no unretained event population is inferred from samples.","Independent acceptance at a stop PC is a diagnostic counterexample, not permission to skip bytes or credit code coverage.","Valid x64 instructions in arbitrary data do not establish semantics or input transformation."]}
        save(f"stop-classification-{label}.json",report)
        text=["# Exact file-backed stop classification","",report["input_provenance"]+".","",f"Classified {len(stops):,} retained events at {report['unique_stop_sites_all_reasons']:,} unique stop PCs; evidence complete={summary.get('stop_evidence_complete')}. Input SHA256 `{source['sha256']}`.","",
            "| Reason | Seed-entry events / unique sites | Downstream events / unique sites |","|---|---:|---:|"]
        for r in sorted(reason):text.append(f"| {r} | {strata[(r,'seed_entry')]:,} / {len(sites[(r,'seed_entry')]):,} | {strata[(r,'downstream')]:,} / {len(sites[(r,'downstream')]):,} |")
        text.extend(["","Independent strict classifications: `"+json.dumps(dict(counts),sort_keys=True)+"`.","",
            "All decoding starts at exact retained stop PCs and uses the original file-backed bytes, up to15 bytes. An invalid encoding is never skipped. Native-window clipping, valid full-window counterexamples and no-file-byte cases remain separate. Event/site counts are not semantic recovery or new coverage. Detailed classified JSONL, evidence completeness, raw options, source/executable/input hashes and indirect-operand categories are retained.",""])
        (OUT/f"stop-classification-{label}.md").write_text("\n".join(text),encoding="utf-8")
        if mismatch:raise RuntimeError("Retained stop bytes differ from original input")
        print(OUT/f"stop-classification-{label}.md",flush=True)

def benchmark_one(exe,path):
    with Client(exe)as client:
        schemas={t["name"]:t for t in client.rpc("tools/list")["tools"]}
        opened,wall=timed(client,"open_binary",{"path":str(path)})
        opts=accepted(schemas["analyze_code_paths"],OPTIONS|{"stop_limit":0})
        result,code_wall=timed(client,"analyze_code_paths",opts,timeout=120)
        coverage,_=pages(client,"coverage");spans=union((int(r["start"],16),int(r["end"],16))for r in coverage);scope=candidate_scope(opened)
        if extent(scope)!=result["candidate_code_bytes"]or extent(spans)!=result["covered_bytes"]or extent(intersect(spans,scope))!=extent(spans):raise RuntimeError("Coverage audit failed")
        return {"open_wall_ms":wall,"code_wall_ms":code_wall,"options":opts,"unsupported_requested_options":sorted(set(OPTIONS|{"stop_limit":0})-set(opts)),
            "result":result,"memory":client.memory(),"audit":{"candidate_bytes":extent(scope),"unique_bytes":extent(spans),"coverage_percent":100*extent(spans)/extent(scope),"coverage_union_sha256":hashlib.sha256(json.dumps(hexranges(spans),separators=(",",":")).encode()).hexdigest()}}

def benchmark(args):
    report={"phase":"fresh_process_cpu_comparison","validation_status":"in_progress","method":"Three fresh MCP processes per input/build; no OS cache flush. Same explicit CPU budgets and fixed original candidate denominator. Stop retention disabled for comparable timing; detailed diagnostic phase is separate. No GPU matching, target execution or capture.","source_hashes":source_hashes(),"cases":[]}
    workloads=[("original Roblox",args.input,False),("original Chrome DLL",args.chrome,False)]
    if args.conditional_source:workloads.append(("conditional raw-derived PE replay",args.conditional_source,True))
    for label,path,conditional in workloads:
        source=identity(path)
        if label=="original Roblox"and source["sha256"]!=ORIGINAL_SHA:raise RuntimeError("Original Roblox hash mismatch")
        for variant,exe in [("0.7 preserved",args.baseline),("upcoming current",args.current)]:
            row={"label":label,"conditional":conditional,"provenance":"Unverified conditional source; never credited to original Roblox recovery"if conditional else "Original immutable file","input":source,"variant":variant,"executable":identity(exe),"runs":[]}
            for n in range(args.runs):
                print(label,variant,"run",n+1,flush=True);row["runs"].append(benchmark_one(exe,path))
            row["code_wall_ms"]=stats([r["code_wall_ms"]for r in row["runs"]]);row["open_wall_ms"]=stats([r["open_wall_ms"]for r in row["runs"]]);report["cases"].append(row)
            save("performance.json",report)
    for label in {r["label"]for r in report["cases"]}:
        denominators={r["audit"]["candidate_bytes"]for c in report["cases"]if c["label"]==label for r in c["runs"]}
        if len(denominators)!=1:raise RuntimeError("Builds changed coverage denominator for "+label)
    report["validation_status"]="passed";save("performance.json",report)
    text=["# Bounded CPU analysis comparison","","Stop retention is disabled for these timing trials; exact stop classification uses a separate process and does not enter these timing denominators. All inputs are read, never executed.","",
        "| Input/build | Code median ms | p95 ms | Unique original candidate bytes | Fixed candidate scope | Budget exhausted |","|---|---:|---:|---:|---:|---|"]
    for c in report["cases"]:
        r=c["runs"][0];text.append(f"| {c['label']} / {c['variant']} | {c['code_wall_ms']['median']:.3f} | {c['code_wall_ms']['p95']:.3f} | {r['audit']['unique_bytes']:,} | {r['audit']['candidate_bytes']:,} | {r['result'].get('budget_exhausted')} |")
    text.extend(["","The conditional source, if supplied, remains an unverified raw-derived PE replay and is never added to original-file coverage. Unique interval unions are independently audited; decoded bytes, function starts, stops and valid instruction encodings do not prove function ownership or semantics. All settings, partial flags, hashes, peak process memory, median, nearest-rank p95 and population variance are in JSON.",""])
    (OUT/"performance.md").write_text("\n".join(text),encoding="utf-8")
    print(OUT/"performance.md",flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument("phase",choices=["existing","diagnose","benchmark"])
    p.add_argument("--current",type=pathlib.Path,default=CURRENT);p.add_argument("--baseline",type=pathlib.Path,default=BASELINE)
    p.add_argument("--input",type=pathlib.Path,default=ORIGINAL);p.add_argument("--chrome",type=pathlib.Path,default=CHROME)
    p.add_argument("--conditional-source",type=pathlib.Path);p.add_argument("--runs",type=int,default=3);p.add_argument("--stop-limit",type=int,default=500000);p.add_argument("--label",help="Distinct diagnostic output suffix, e.g original-743")
    p.add_argument("--conditional-input",action="store_true",help="Label diagnosis input as unverified raw-derived image, never original-file coverage")
    p.add_argument("--switch-address",action="append",help="Optional explicit indexed function for separately labeled bounded switch experiment; max256")
    args=p.parse_args()
    if args.runs<1 or args.runs>10:p.error("--runs must be1..10")
    if args.phase=="existing":existing()
    elif args.phase=="diagnose":diagnose(args)
    else:benchmark(args)

if __name__=="__main__":
    try:main()
    except Exception as error:
        save("diagnostic-failure.json",{"validation_status":"failed","error":str(error)})
        raise
