"""Read PE function metadata without relying on section execute flags."""
import json
import pathlib
import struct

ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/"reports/roblox-comparison"
image=(ROOT/"benchmark-inputs/RobloxPlayerBeta-0.742.exe").read_bytes()
pe=struct.unpack_from("<I",image,0x3c)[0]
count=struct.unpack_from("<H",image,pe+6)[0]
opt=pe+24
optional_size=struct.unpack_from("<H",image,pe+20)[0]
assert struct.unpack_from("<H",image,opt)[0]==0x20b
base=struct.unpack_from("<Q",image,opt+24)[0]
sections=[]
for i in range(count):
    off=opt+optional_size+40*i
    vs,rva,raw_size,raw=struct.unpack_from("<IIII",image,off+8)
    name=image[off:off+8].split(b"\0")[0].decode("ascii",errors="replace")
    flags=struct.unpack_from("<I",image,off+36)[0]
    sections.append({"name":name,"address":hex(base+rva),"rva":rva,"offset":raw,"size":raw_size,
        "virtual_size":vs,"flags":hex(flags),"declared_executable":bool(flags&0x20000000)})
def offset(rva):
    for s in sections:
        if s["rva"]<=rva<s["rva"]+s["size"]:
            return s["offset"]+rva-s["rva"]
    raise ValueError("Unmapped RVA")
pdata,size=struct.unpack_from("<II",image,opt+112+8*3)
functions=[]
for i in range(0,size-11,12):
    begin,end,unwind=struct.unpack_from("<III",image,offset(pdata)+i)
    if begin and end>begin:
        functions.append({"address":hex(base+begin),"end":hex(base+end),"name":"unwind_"+hex(base+begin)[2:],"source":"PE unwind metadata read without execute-flag filter"})
selected=[]
metadata={"exception_directory_rva":hex(pdata),"exception_directory_bytes":size,"unwind_function_extents":len(functions),"sections":sections}
if not functions:
    config,config_size=struct.unpack_from("<II",image,opt+112+8*10)
    at=offset(config)
    table,count=struct.unpack_from("<QQ",image,at+128)
    flags=struct.unpack_from("<I",image,at+144)[0]
    stride=4+((flags>>28)&15)
    assert config_size>=148 and 0<count<1000000
    raw=offset(table-base)
    assert raw+count*stride<=len(image)
    starts=sorted(set(base+struct.unpack_from("<I",image,raw+i*stride)[0] for i in range(count)))
    metadata.update(load_config_rva=hex(config),cfg_table=hex(table),cfg_entries=count,cfg_stride=stride,
        sample_boundaries="Next distinct CFG entry is a conservative sample upper bound, not a recovered function end.")
    for index,a in enumerate(starts[:-1]):
        functions.append({"address":hex(a),"end":hex(starts[index+1]),"name":"cfg_"+hex(a)[2:],"source":"CFG entry; next start used only as a sample upper bound"})
for lo,hi in [(1,32),(33,128),(129,512),(513,2048)]:
    candidates=[f for f in functions if lo<=int(f["end"],16)-int(f["address"],16)<=hi]
    for fraction in [.2,.5,.8]:
        if candidates:
            item=dict(candidates[min(len(candidates)-1,int(len(candidates)*fraction))])
            item["selection"]=f"metadata gap {lo}-{hi} bytes; address-order quantile {fraction}"
            if item["address"] not in [s["address"] for s in selected]:selected.append(item)
(OUT/"samples.json").write_text(json.dumps(selected,indent=2),encoding="utf-8")
(OUT/"pe-metadata.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
print(metadata.get("cfg_entries",metadata["unwind_function_extents"]),"metadata entries;",len(selected),"sample addresses")
