#include "feature_power_tools.hpp"
#include "feature_navigation.hpp"
#include "feature_xrefs.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <set>

namespace scratcher {
namespace {
constexpr size_t reportLimit=8*1024*1024;
const Binary& requireBinary(const Engine& engine){if(!engine.binary())throw std::runtime_error("Open a binary first");return *engine.binary();}
void cancellation(const Engine& engine){if(engine.cancelled())throw std::runtime_error("Operation cancelled");}
size_t bounded(const Json& args,const char* key,size_t fallback,size_t minimum,size_t maximum){
 if(!args.contains(key))return fallback;
 const auto& value=args.at(key);if(!value.is_number_unsigned()&&!(value.is_number_integer()&&value.get<int64_t>()>=0))throw std::runtime_error(std::string(key)+" must be a nonnegative integer");
 auto number=value.get<uint64_t>();if(number<minimum||number>maximum)throw std::runtime_error(std::string(key)+" is outside the supported range");return static_cast<size_t>(number);
}
Json functionDetail(Engine& engine,Address requested,bool pseudocode,bool references,size_t count,size_t referenceBudget){
 cancellation(engine);const auto& binary=requireBinary(engine);auto location=describeAddress(binary,requested);
 if(location["function"].is_null())throw std::runtime_error("No indexed function contains this address");
 Address start=address(location["function"]["address"]);const Function* function=nullptr;
 for(const auto& candidate:binary.functions)if(candidate.va==start){function=&candidate;break;}
 if(!function)throw std::runtime_error("Function metadata is unavailable");
 Address end=function->end;std::string endSource="metadata";
 if(end<=start){const auto* section=binary.section(start);endSource="section boundary";end=section->va+section->memorySize;
  for(const auto& next:binary.functions)if(next.va>start&&next.va<end&&binary.section(next.va)==section){end=next.va;endSource="next indexed function";}}
 Json result={{"requested_address",hex(requested)},{"address",hex(start)},{"name",function->name},{"end",hex(end)},{"boundary_source",endSource},{"source",function->source},{"location",location},{"instructions",Json::array()},{"annotations",Json::array()}};
 if(count){for(const auto& instruction:engine.disassemble(start,count)){cancellation(engine);if(instruction.va>=end)break;
   Json row={{"address",hex(instruction.va)},{"length",instruction.length},{"mnemonic",instruction.mnemonic},{"operands",instruction.operands},{"bytes",instruction.bytes},{"target",nullptr}};
   if(auto target=operandTarget(binary,instruction))row["target"]=hex(*target);result["instructions"].push_back(std::move(row));}}
 result["instruction_limit"]=count;result["instructions_complete"]=false;if(!result["instructions"].empty()){auto last=address(result["instructions"].back()["address"]);result["instructions_complete"]=last<end&&result["instructions"].back()["length"].get<Address>()>=end-last;}
 auto annotations=engine.annotations();for(const auto& note:annotations["annotations"]){auto va=address(note["address"]);if(va>=start&&va<end)result["annotations"].push_back(note);}
 if(pseudocode){cancellation(engine);result["pseudocode"]=engine.decompile(start);}
 if(references){cancellation(engine);auto index=collectCrossReferences(engine,referenceBudget);Json incoming=Json::array(),outgoing=Json::array();for(const auto& item:index["items"]){cancellation(engine);auto from=address(item["from"]),to=address(item["to"]);if(to>=start&&to<end)incoming.push_back(item);if(from>=start&&from<end)outgoing.push_back(item);}
  auto referenceResult=[&](Json items,const char* direction){auto total=items.size();return Json{{"address",hex(start)},{"end",hex(end)},{"scope","function_range"},{"direction",direction},{"items",std::move(items)},{"total",total},{"truncated",index.value("truncated",false)},{"instructions_examined",index.value("instructions_examined",size_t(0))},{"instruction_budget",referenceBudget}};};
  result["incoming_references"]=referenceResult(std::move(incoming),"incoming");result["outgoing_references"]=referenceResult(std::move(outgoing),"outgoing");}
 return result;
}
std::vector<Address> addressList(const Json& args){
 const auto& list=args.at("addresses");if(!list.is_array()||list.size()>128)throw std::runtime_error("Provide at most 128 address strings");std::vector<Address> result;
 for(const auto& item:list){if(!item.is_string())throw std::runtime_error("Each address must be a string");result.push_back(address(item));}return result;
}
Json resolve(Engine& engine,const Json& args){
 const auto& binary=requireBinary(engine);const bool hasAddress=args.contains("address"),hasQuery=args.contains("query");
 if(hasAddress==hasQuery)throw std::runtime_error("Provide exactly one address or symbol query");
 if(hasAddress){auto location=describeAddress(binary,address(args["address"]));return {{"resolved",location["mapped"]},{"ambiguous",false},{"location",location},{"candidates",Json::array()},{"total",0},{"truncated",false}};}
 auto query=args.at("query").get<std::string>();if(query.empty()||query.size()>1024)throw std::runtime_error("Symbol query must contain 1 to 1024 bytes");
 Json candidates=Json::array();std::set<Address> found;size_t total=0;
 auto add=[&](Address va,const std::string& name,const char* kind){if(!found.insert(va).second)return;++total;if(candidates.size()<512)candidates.push_back({{"address",hex(va)},{"name",name},{"kind",kind}});};
 for(const auto& function:binary.functions){cancellation(engine);if(function.name==query)add(function.va,function.name,"function");}
 for(const auto& item:binary.imports)if(item.name==query||item.module+"!"+item.name==query)add(item.va,item.name,"import");
 for(const auto& section:binary.sections)if(section.name==query)add(section.va,section.name,"section");
 auto annotations=engine.annotations();for(const auto& note:annotations["annotations"])if(note.value("label",std::string())==query)add(address(note["address"]),query,"label");
 Json location=nullptr;if(total==1)location=describeAddress(binary,address(candidates.front()["address"]));
 return {{"query",query},{"resolved",total==1},{"ambiguous",total>1},{"location",location},{"candidates",candidates},{"total",total},{"truncated",total>candidates.size()}};
}
Json toOffset(const Binary& binary,Address value){auto location=describeAddress(binary,value);return {{"address",hex(value)},{"mapped",location["mapped"]},{"file_backed",!location["file_offset"].is_null()},{"zero_filled",location["mapped"].get<bool>()&&location["file_offset"].is_null()},{"file_offset",location["file_offset"]},{"location",location}};}
Json fromOffset(const Binary& binary,uint64_t offset){
 Json candidates=Json::array();if(offset<binary.size())for(const auto& section:binary.sections){if(offset>=section.offset&&offset-section.offset<section.fileSize&&offset-section.offset<section.memorySize&&section.va<=UINT64_MAX-(offset-section.offset)){
   auto va=section.va+offset-section.offset;bool duplicate=false;for(const auto& item:candidates)if(item["address"]==hex(va)){duplicate=true;break;}if(!duplicate)candidates.push_back(describeAddress(binary,va));}}
 return {{"file_offset",offset},{"in_file",offset<binary.size()},{"mapped",!candidates.empty()},{"ambiguous",candidates.size()>1},{"address",candidates.size()==1?candidates[0]["address"]:Json(nullptr)},{"candidates",candidates}};
}
Json batch(Engine& engine,const Json& args){
 requireBinary(engine);auto addresses=addressList(args);auto maximum=bounded(args,"max_output_bytes",1024*1024,1024,4*1024*1024);bool stop=args.value("stop_on_error",false);size_t processed=0,attempted=0;bool truncated=false,cancelled=false,stopped=false;Json items=Json::array();
 auto envelope=[&](){return Json{{"items",items},{"processed",processed},{"attempted",attempted},{"remaining",addresses.size()-processed},{"next_index",processed},{"truncated",truncated},{"cancelled",cancelled},{"stopped_on_error",stopped},{"max_output_bytes",maximum}};};
 for(auto requested:addresses){if(engine.cancelled()){cancelled=true;break;}Json item={{"requested_address",hex(requested)}};++attempted;
  try{auto location=describeAddress(*engine.binary(),requested);if(location["function"].is_null())throw std::runtime_error("No indexed function contains this address");auto va=address(location["function"]["address"]);item["address"]=hex(va);item["success"]=true;item["pseudocode"]=engine.decompile(va);}
  catch(const std::exception& error){if(engine.cancelled()){cancelled=true;break;}item["success"]=false;item["error"]=error.what();}
  items.push_back(item);++processed;if(envelope().dump().size()+256>maximum){items.erase(items.size()-1);--processed;truncated=true;break;}
  if(!item["success"].get<bool>()&&stop){stopped=true;break;}}
 cancelled=cancelled||engine.cancelled();return envelope();
}
struct TempFile {std::filesystem::path path;HANDLE file=INVALID_HANDLE_VALUE;bool committed=false;~TempFile(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(!committed&&!path.empty())DeleteFileW(path.c_str());}};
void rejectDestination(const std::filesystem::path& destination,const std::filesystem::path& source){
 if(destination.empty()||destination.filename().empty()||destination.filename().native().find(L':')!=std::wstring::npos)throw std::runtime_error("Choose a new report file path");
 std::error_code error;auto target=std::filesystem::weakly_canonical(destination,error);if(error)throw std::runtime_error("Cannot resolve the report path");auto original=std::filesystem::weakly_canonical(source,error);if(error)throw std::runtime_error("Cannot resolve the binary path");
 if(CompareStringOrdinal(target.c_str(),-1,original.c_str(),-1,TRUE)==CSTR_EQUAL)throw std::runtime_error("Choose a report path different from the input binary");
 auto attributes=GetFileAttributesW(destination.c_str());if(attributes!=INVALID_FILE_ATTRIBUTES)throw std::runtime_error("Report destination already exists; choose a new file");auto code=GetLastError();if(code!=ERROR_FILE_NOT_FOUND&&code!=ERROR_PATH_NOT_FOUND)throw std::runtime_error("Cannot inspect the report destination");
}
void writeNew(const std::filesystem::path& destination,const std::filesystem::path& source,const std::string& text,const Engine& engine){
 rejectDestination(destination,source);auto absolute=std::filesystem::absolute(destination);TempFile temporary;
 for(int attempt=0;attempt<16;++attempt){std::array<uint8_t,16> bytes{};if(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("Cannot create temporary report name");std::wstring suffix;constexpr wchar_t digits[]=L"0123456789abcdef";for(auto byte:bytes){suffix+=digits[byte>>4];suffix+=digits[byte&15];}auto candidate=absolute.parent_path()/(L".scratcher-report-"+suffix+L".tmp");
  temporary.file=CreateFileW(candidate.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(temporary.file!=INVALID_HANDLE_VALUE){temporary.path=candidate;break;}auto error=GetLastError();if(error!=ERROR_FILE_EXISTS&&error!=ERROR_ALREADY_EXISTS)throw std::runtime_error("Cannot create report in the selected folder");}
 if(temporary.file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create report file");
 for(size_t offset=0;offset<text.size();){cancellation(engine);DWORD count=static_cast<DWORD>(std::min<size_t>(65536,text.size()-offset)),written=0;if(!WriteFile(temporary.file,text.data()+offset,count,&written,nullptr)||!written)throw std::runtime_error("Cannot write report file");offset+=written;}
 if(!FlushFileBuffers(temporary.file))throw std::runtime_error("Cannot flush report file");auto handle=temporary.file;temporary.file=INVALID_HANDLE_VALUE;if(!CloseHandle(handle))throw std::runtime_error("Cannot close report file");cancellation(engine);rejectDestination(absolute,source);
 if(!MoveFileExW(temporary.path.c_str(),absolute.c_str(),MOVEFILE_WRITE_THROUGH))throw std::runtime_error("Cannot publish report; existing files were preserved");temporary.committed=true;
}
Json exportReport(Engine& engine,const Json& args){
 const auto& binary=requireBinary(engine);auto path=std::filesystem::u8path(args.at("path").get<std::string>());auto format=args.value("format",std::string("json"));if(format!="json"&&format!="markdown")throw std::runtime_error("Report format must be json or markdown");rejectDestination(path,binary.path);cancellation(engine);
 Json report={{"scratcher_report",1},{"binary",binary.info()},{"functions",Json::array()},{"annotations",engine.annotations()},{"patches",engine.listPatches()},{"selected_functions",Json::array()}};size_t estimate=report.dump().size();
 auto append=[&](const char* key,Json item){estimate+=item.dump().size()+2;if(estimate>reportLimit)throw std::runtime_error("Report exceeds the 8 MiB limit; export fewer selected functions");report[key].push_back(std::move(item));};
 for(const auto& function:binary.functions){cancellation(engine);append("functions",{{"address",hex(function.va)},{"end",function.end?Json(hex(function.end)):Json(nullptr)},{"name",function.name},{"source",function.source}});}
 if(args.contains("addresses"))for(auto va:addressList(args)){cancellation(engine);append("selected_functions",functionDetail(engine,va,args.value("include_pseudocode",false),false,32,0));}
 std::string text;if(format=="json")text=report.dump(2);else {text="# Scratcher analysis report\n\n";for(const char* key:{"binary","functions","annotations","patches","selected_functions"}){auto body=report[key].dump(2);size_t longest=0,run=0;for(char c:body){run=c=='`'?run+1:0;longest=std::max(longest,run);}auto fence=std::string(std::max<size_t>(3,longest+1),'`');text+="## "+std::string(key)+"\n\n"+fence+"json\n"+body+"\n"+fence+"\n\n";}}
 if(text.size()>reportLimit)throw std::runtime_error("Report exceeds the 8 MiB limit; export fewer selected functions");writeNew(path,binary.path,text,engine);return {{"path",pathText(std::filesystem::absolute(path))},{"format",format},{"bytes",text.size()},{"function_count",report["functions"].size()},{"selected_function_count",report["selected_functions"].size()}};
}
}
Json powerTools(){
 Json tools=Json::array();auto str=[](const char* description,size_t maximum=32768){return Json{{"type","string"},{"description",description},{"minLength",1},{"maxLength",maximum}};};auto number=[](size_t minimum,size_t maximum){return Json{{"type","integer"},{"minimum",minimum},{"maximum",maximum}};};auto addr=str("Virtual address string, for example 0x140001000",32);auto list=Json{{"type","array"},{"items",addr},{"maxItems",128}};
 auto add=[&](const char* name,const char* description,Json properties,Json required,bool readOnly){tools.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",properties},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readOnly},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("resolve_address","Resolve an address or exact symbol name. Ambiguous names return candidates without selecting one.",{{"address",addr},{"query",str("Exact function, import, section, or label name",1024)}},Json::array(),true);
 tools.back()["inputSchema"]["oneOf"]=Json::array({Json{{"required",{"address"}}},Json{{"required",{"query"}}}});
 add("get_function_details","Inspect the containing function with bounded decoded instructions, annotations, optional pseudocode and references.",{{"address",addr},{"include_pseudocode",{{"type","boolean"}}},{"include_references",{{"type","boolean"}}},{"instruction_count",number(0,512)},{"reference_budget",number(1,1000000)}},{"address"},true);
 add("get_memory_map","Read mapped sections, file extents, memory extents and access permissions.",Json::object(),Json::array(),true);
 add("address_to_offset","Convert a virtual address to a file offset, distinguishing unmapped and zero-filled memory.",{{"address",addr}},{"address"},true);
 add("offset_to_address","Convert a file offset to mapped address candidates, including ambiguous mappings and file-only bytes.",{{"file_offset",number(0,SIZE_MAX)}},{"file_offset"},true);
 add("batch_decompile","Decompile up to 128 containing functions within a response byte budget. Resume at next_index if truncated or cancelled.",{{"addresses",list},{"max_output_bytes",number(1024,4*1024*1024)},{"stop_on_error",{{"type","boolean"}}}},{"addresses"},true);
 add("export_analysis","Create a new JSON or Markdown analysis report. Existing files and the input binary are preserved; output is bounded to 8 MiB.",{{"path",str("New report output path")},{"format",{{"type","string"},{"enum",{"json","markdown"}}}},{"addresses",list},{"include_pseudocode",{{"type","boolean"}}}},{"path","format"},false);return tools;
}
std::optional<Json> callPowerTool(Engine& engine,const std::string& name,const Json& args){
 if(name=="resolve_address")return resolve(engine,args);
 if(name=="get_function_details")return functionDetail(engine,address(args.at("address")),args.value("include_pseudocode",false),args.value("include_references",false),bounded(args,"instruction_count",32,0,512),bounded(args,"reference_budget",100000,1,1000000));
 if(name=="get_memory_map"){const auto& binary=requireBinary(engine);return Json{{"sections",binary.info()["sections"]},{"size",binary.size()},{"base",hex(binary.base)},{"entry",hex(binary.entry)}};}
 if(name=="address_to_offset")return toOffset(requireBinary(engine),address(args.at("address")));
 if(name=="offset_to_address")return fromOffset(requireBinary(engine),bounded(args,"file_offset",0,0,SIZE_MAX));
 if(name=="batch_decompile")return batch(engine,args);
 if(name=="export_analysis")return exportReport(engine,args);return std::nullopt;
}
}
