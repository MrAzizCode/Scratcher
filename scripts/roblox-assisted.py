"""Explicit static execute-permission assistance, separate from the default baseline."""
import json
import pathlib
from mcp_client import Client, timed

ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/"reports/roblox-comparison"
samples=json.loads((OUT/"samples.json").read_text(encoding="utf-8"))
record={"method":"Default sample requests first. Assisted variant marks .text/tempest/.byfron executable in the analysis workspace only; file bytes remain unchanged. Uses 12 independently read CFG entries with the next CFG start as a conservative manually supplied upper bound, not a proven function extent. No imported Ghidra analysis.","default_samples":[],"assisted_samples":[]}
def save():
    (OUT/"scratcher-assisted.json").write_text(json.dumps(record,indent=2,ensure_ascii=False),encoding="utf-8")
with Client(ROOT/"dist-v0.4/ScratcherMCP.exe") as client:
    info=client.tool("open_binary",{"path":str(ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe")})
    for sample in samples:
        item={"address":sample["address"]}
        try:
            result,wall=timed(client,"decompile",{"address":sample["address"]},timeout=45)
            item.update(result=result,wall_ms=wall)
        except Exception as error:item["error"]=str(error)
        record["default_samples"].append(item)
    record["permission_edits"]=[]
    for section in info["sections"]:
        if section["name"] in [".text","tempest",".byfron"]:
            record["permission_edits"].append(client.tool("edit_segment",{"address":section["address"],"executable":True}))
    scan,wall=timed(client,"analyze",{"full_scan":True},timeout=180)
    record["full_scan"]={"wall_ms":wall,"result":scan,"memory":client.memory()}
    record["functions_after_scan"]=client.tool("list_functions",{"limit":1})["total"]
    save()
    # Sample recovery uses a fresh image so speculative scan candidates cannot
    # impose overlapping inferred extents. Only chosen CFG seeds are added.
    info=client.tool("open_binary",{"path":str(ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe")})
    for section in info["sections"]:
        if section["name"] in [".text","tempest",".byfron"]:
            client.tool("edit_segment",{"address":section["address"],"executable":True})
    record["sample_context"]="Fresh workspace; only 12 manually bounded CFG seeds plus the imported entry. No preceding scan candidates or Ghidra metadata."
    # Fetch candidates once; requests and manual edits remain separate from scan timing.
    all_candidates=[];off=0
    while True:
        page=client.tool("list_functions",{"offset":off,"limit":10000})
        all_candidates += page["items"];off += len(page["items"])
        if off>=page["total"]:break
    # Inspect only the chosen metadata gaps; no claim of whole-program deep analysis.
    for sample in samples:
        # New sample functions are supplied via the public manual API after removing
        # overlapping speculative direct-call candidates within the selected extent.
        a,b=int(sample["address"],16),int(sample["end"],16)
        rows=[f for f in all_candidates if a<=int(f["address"],16)<b]
        for f in rows:client.tool("delete_function",{"address":f["address"]})
        client.tool("create_function",{"address":sample["address"],"end":sample["end"],"name":sample["name"]})
    for sample in samples:
        row={"address":sample["address"],"manual_upper_bound":sample["end"]}
        for key,tool,args in [
            ("reachable","analyze_reachable",{"address":sample["address"],"instruction_budget":20000,"byte_budget":65536,"include_instructions":False}),
            ("graph","get_control_flow",{"address":sample["address"],"instruction_budget":10000}),
            ("pseudocode","decompile",{"address":sample["address"]})]:
            try:
                result,wall=timed(client,tool,args,timeout=45)
                row[key]={"wall_ms":wall,"result":result}
            except Exception as error:row[key]={"error":str(error)}
        record["assisted_samples"].append(row);save()
        print("Assisted sample",sample["address"],flush=True)
    save()
