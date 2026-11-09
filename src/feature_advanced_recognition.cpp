#include "feature_advanced_recognition.hpp"
#include <Zydis/Zydis.h>
#include <windows.h>
#include <algorithm>
#include <array>
#include <bit>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>

namespace scratcher {
namespace {
constexpr size_t maxSignatures=10000,maxLength=4096,maxDatabaseBytes=8*1024*1024;
void cancelled(const Engine& engine){if(engine.cancelled())throw std::runtime_error("Operation cancelled");}
const Binary& binary(const Engine& engine){if(!engine.binary())throw std::runtime_error("Open a binary first");return *engine.binary();}
size_t bounded(const Json& args,const char* name,size_t fallback,size_t minimum,size_t maximum){
 if(!args.contains(name))return fallback;const auto& value=args.at(name);
 if(!value.is_number_unsigned()&&!(value.is_number_integer()&&value.get<int64_t>()>=0))throw std::runtime_error(std::string(name)+" must be a nonnegative integer");
 auto n=value.get<uint64_t>();if(n<minimum||n>maximum)throw std::runtime_error(std::string(name)+" is outside its supported range");return static_cast<size_t>(n);
}
std::string text(const Json& value,const char* name,size_t maximum,bool empty=false){
 if(!value.contains(name)||!value.at(name).is_string())throw std::runtime_error(std::string(name)+" must be a string");auto result=value.at(name).get<std::string>();
 if((result.empty()&&!empty)||result.size()>maximum||result.find('\0')!=std::string::npos)throw std::runtime_error(std::string(name)+" has an invalid length");return result;
}
int nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
struct Signature {Json row;std::vector<uint8_t> bytes,mask;size_t fixedBits=0,anchor=0;bool exactLength=false;};
std::string patternText(const std::vector<uint8_t>& bytes,const std::vector<uint8_t>& mask){
 constexpr char digits[]="0123456789ABCDEF";std::string result;for(size_t i=0;i<bytes.size();++i){if(i)result+=' ';result+=mask[i]&0xf0?digits[bytes[i]>>4]:'?';result+=mask[i]&0x0f?digits[bytes[i]&15]:'?';}return result;
}
Signature parse(Json row){
 if(!row.is_object())throw std::runtime_error("Each signature must be an object");
 for(const auto& item:row.items())if(item.key()!="id"&&item.key()!="name"&&item.key()!="library"&&item.key()!="architecture"&&item.key()!="pattern"&&item.key()!="exact_length"&&item.key()!="source"&&item.key()!="description")throw std::runtime_error("Unknown signature field: "+item.key());
 text(row,"id",128);text(row,"name",512);text(row,"library",512);auto architecture=text(row,"architecture",32);if(architecture!="x86"&&architecture!="x86_64")throw std::runtime_error("Signature architecture must be x86 or x86_64");
 auto pattern=text(row,"pattern",maxLength*3);if(row.contains("exact_length")&&!row["exact_length"].is_boolean())throw std::runtime_error("exact_length must be boolean");
 if(!row.contains("source"))row["source"]="User supplied; provenance not verified";text(row,"source",2048);
 if(row.contains("description"))text(row,"description",2048,true);
 Signature result;std::istringstream tokens(pattern);std::string token;while(tokens>>token){if(token.size()!=2)throw std::runtime_error("Pattern tokens must be two hexadecimal or wildcard nibbles");uint8_t byte=0,mask=0;
  for(int i=0;i<2;++i){if(token[i]=='?')continue;auto n=nibble(token[i]);if(n<0)throw std::runtime_error("Invalid signature pattern");byte|=static_cast<uint8_t>(n<<(i?0:4));mask|=static_cast<uint8_t>(i?0x0f:0xf0);}result.bytes.push_back(byte);result.mask.push_back(mask);result.fixedBits+=std::popcount(mask);if(result.bytes.size()>maxLength)throw std::runtime_error("Signature exceeds 4096 bytes");}
 if(result.bytes.size()<4||result.fixedBits<32)throw std::runtime_error("Signature must contain at least 4 bytes and 32 fixed bits");
 auto anchor=std::find(result.mask.begin(),result.mask.end(),uint8_t(0xff));if(anchor==result.mask.end())throw std::runtime_error("Signature requires at least one fully fixed byte");result.anchor=static_cast<size_t>(anchor-result.mask.begin());
 result.exactLength=row.value("exact_length",false);row["exact_length"]=result.exactLength;row["pattern"]=patternText(result.bytes,result.mask);result.row=std::move(row);return result;
}
Json starter(){
 const char* source="https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/arch-x86/bionic/__x86.get_pc_thunk.S";
 return Json::array({Json{{"id","gcc-pic-bx"},{"name","__x86.get_pc_thunk.bx"},{"library","GCC-compatible PIC runtime thunk"},{"architecture","x86"},{"pattern","8B 1C 24 C3"},{"exact_length",true},{"source",source},{"description","Small architectural pattern; identical user code can collide. Candidate evidence only."}},Json{{"id","gcc-pic-cx"},{"name","__x86.get_pc_thunk.cx"},{"library","GCC-compatible PIC runtime thunk"},{"architecture","x86"},{"pattern","8B 0C 24 C3"},{"exact_length",true},{"source",source},{"description","Small architectural pattern; identical user code can collide. Candidate evidence only."}}});
}
Json& state(Engine& engine){auto& root=engine.advancedState();if(!root.contains("recognition"))root["recognition"]={{"version",1},{"generation",1},{"signatures",starter()}};
 auto& result=root["recognition"];if(!result.is_object()||!result.contains("signatures")||!result["signatures"].is_array())throw std::runtime_error("Invalid recognition state");return result;
}
std::vector<Signature> validated(const Json& rows,const Engine& engine){
 if(!rows.is_array()||rows.size()>maxSignatures)throw std::runtime_error("Signature database exceeds 10000 records");if(rows.dump().size()>maxDatabaseBytes)throw std::runtime_error("Signature database exceeds 8 MiB");std::vector<Signature> result;std::set<std::string> ids;
 for(const auto& row:rows){cancelled(engine);auto signature=parse(row);if(!ids.insert(signature.row["id"].get<std::string>()).second)throw std::runtime_error("Duplicate signature id");result.push_back(std::move(signature));}
 std::sort(result.begin(),result.end(),[](const Signature& a,const Signature& b){return a.row["id"].get<std::string>()<b.row["id"].get<std::string>();});return result;
}
Json rows(const std::vector<Signature>& signatures){auto result=Json::array();for(const auto& signature:signatures)result.push_back(signature.row);return result;}
void replace(Engine& engine,const Json& signatures){auto valid=validated(signatures,engine);auto& target=state(engine);target["signatures"]=rows(valid);target["generation"]=target.value("generation",uint64_t(0))+1;engine.runtimeSlots().erase("recognition.compiled");}
struct Compiled {Json source;std::vector<Signature> signatures;std::map<size_t,std::array<std::vector<size_t>,256>> anchors;size_t maximum=0;};
std::shared_ptr<Compiled> compiled(Engine& engine){auto& current=state(engine);auto& slot=engine.runtimeSlots()["recognition.compiled"];auto result=std::static_pointer_cast<Compiled>(slot);
 if(result&&result->source==current["signatures"])return result;result=std::make_shared<Compiled>();result->source=current["signatures"];result->signatures=validated(result->source,engine);
 for(size_t i=0;i<result->signatures.size();++i){const auto& signature=result->signatures[i];result->anchors[signature.anchor][signature.bytes[signature.anchor]].push_back(i);result->maximum=std::max(result->maximum,signature.bytes.size());}slot=result;return result;
}
std::string architecture(const Binary& value){if(value.language.rfind("x86:",0)!=0)throw std::runtime_error("This signature collection supports x86 and x86_64 only");return value.bits==64?"x86_64":"x86";}
uint64_t fileSpan(const Binary& value,Address va){const auto* section=value.section(va);if(!section||!section->executable)return 0;auto delta=va-section->va;if(delta>=section->fileSize||delta>=section->memorySize||section->offset>value.size()||delta>value.size()-section->offset)return 0;return std::min({section->fileSize-delta,section->memorySize-delta,value.size()-section->offset-delta});}
const Function* findFunction(const Binary& value,Address va){for(const auto& function:value.functions)if(function.va==va)return &function;return nullptr;}
Json train(Engine& engine,const Json& args){
 const auto& value=binary(engine);auto architectureName=architecture(value);cancelled(engine);auto va=address(args.at("address"));const auto* function=findFunction(value,va);if(!function)throw std::runtime_error("Train at an indexed function start");
 auto span=fileSpan(value,va);if(function->end>va)span=std::min(span,function->end-va);auto count=bounded(args,"byte_count",static_cast<size_t>(std::min<uint64_t>(span,256)),4,maxLength);if(count>span)throw std::runtime_error("Signature extends beyond the file-backed function range");
 Signature signature;signature.bytes.resize(count);signature.mask.resize(count,0xff);value.load(va,signature.bytes.data(),count);auto masking=args.value("mask_addresses",true);size_t undecoded=0;
 if(masking){ZydisDecoder decoder;ZydisDecoderInit(&decoder,value.bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32,value.bits==64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32);
  for(size_t offset=0;offset<count;){cancelled(engine);ZydisDecodedInstruction instruction{};ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
   if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,signature.bytes.data()+offset,count-offset,&instruction,operands))){++undecoded;++offset;continue;}
   auto mask=[&](size_t relative,size_t bits){for(size_t i=relative;i<relative+bits/8&&offset+i<count;++i)signature.mask[offset+i]=0;};
   for(const auto& immediate:instruction.raw.imm)if(immediate.size&&(immediate.is_relative||value.section(immediate.value.u)))mask(immediate.offset,immediate.size);
   for(size_t i=0;i<instruction.operand_count;++i)if(operands[i].type==ZYDIS_OPERAND_TYPE_MEMORY&&(operands[i].mem.base==ZYDIS_REGISTER_RIP||operands[i].mem.base==ZYDIS_REGISTER_EIP||operands[i].mem.base==ZYDIS_REGISTER_NONE))mask(instruction.raw.disp.offset,instruction.raw.disp.size);
   offset+=instruction.length;
  }
 }
 Json row={{"id",text(args,"id",128)},{"name",args.contains("name")?text(args,"name",512):function->name},{"library",text(args,"library",512)},{"architecture",architectureName},{"pattern",patternText(signature.bytes,signature.mask)},{"exact_length",function->end>va&&function->end-va==count},{"source",args.contains("source")?text(args,"source",2048):"Locally trained from "+pathText(value.path)+" at "+hex(va)},{"description","User-trained byte pattern; inferred address operands are masked, not a complete relocation parser."}};
 auto parsed=parse(row);auto all=state(engine)["signatures"];for(const auto& existing:all)if(existing["id"]==row["id"])throw std::runtime_error("Signature id already exists; remove it before retraining");all.push_back(parsed.row);replace(engine,all);
 return {{"signature",parsed.row},{"byte_count",count},{"fixed_bits",parsed.fixedBits},{"masked_bytes",std::count(parsed.mask.begin(),parsed.mask.end(),uint8_t(0))},{"undecoded_bytes",undecoded},{"relocation_masking_complete",false}};
}
Json identify(Engine& engine,const Json& args){
 const auto& value=binary(engine);auto architectureName=architecture(value);auto index=compiled(engine);size_t offset=bounded(args,"function_offset",0,0,SIZE_MAX),maximum=bounded(args,"max_functions",1000,1,10000),limit=bounded(args,"limit",500,1,1000),comparisonBudget=bounded(args,"comparison_budget",1000000,1,10000000),outputBudget=bounded(args,"max_output_bytes",1024*1024,1024,4*1024*1024);
 std::vector<const Function*> selected;if(args.contains("addresses")){const auto& addresses=args.at("addresses");if(!addresses.is_array()||addresses.size()>1000)throw std::runtime_error("Provide at most 1000 function addresses");std::set<Address> seen;for(const auto& item:addresses){if(!item.is_string())throw std::runtime_error("Each address must be a string");auto va=address(item);auto* function=findFunction(value,va);if(!function)throw std::runtime_error("Recognition requires indexed function start addresses");if(seen.insert(va).second)selected.push_back(function);}}
 else for(const auto& function:value.functions)selected.push_back(&function);
 if(offset>selected.size())throw std::runtime_error("Function offset exceeds the function index");Json matches=Json::array();size_t examined=0,comparisons=0,unavailable=0,outputBytes=1024;bool budgetHit=false,outputHit=false;
 for(size_t i=offset;i<selected.size()&&examined<maximum;){if(engine.cancelled())break;const auto& function=*selected[i];auto span=fileSpan(value,function.va);bool knownLength=function.end>function.va;if(knownLength)span=std::min(span,function.end-function.va);auto count=static_cast<size_t>(std::min<uint64_t>(span,index->maximum));if(!count){++unavailable;++examined;++i;continue;}
  std::vector<uint8_t> bytes(count);value.load(function.va,bytes.data(),count);std::vector<size_t> candidates;for(const auto& [anchor,buckets]:index->anchors){if(anchor>=count)continue;for(size_t id:buckets[bytes[anchor]]){if(engine.cancelled())break;if(comparisons==comparisonBudget){budgetHit=true;break;}++comparisons;const auto& signature=index->signatures[id];if(signature.row["architecture"].get<std::string>()!=architectureName||signature.bytes.size()>count||(signature.exactLength&&(!knownLength||function.end-function.va!=signature.bytes.size())))continue;bool match=true;for(size_t n=0;n<signature.bytes.size();++n)if((bytes[n]&signature.mask[n])!=signature.bytes[n]){match=false;break;}if(match)candidates.push_back(id);}if(budgetHit||engine.cancelled())break;}
  if(budgetHit||engine.cancelled())break;
  if(!candidates.empty()){if(matches.size()==limit)break;std::sort(candidates.begin(),candidates.end(),[&](size_t a,size_t b){return index->signatures[a].row["id"].get<std::string>()<index->signatures[b].row["id"].get<std::string>();});Json evidence=Json::array();std::set<std::pair<std::string,std::string>> identities;
   for(size_t id:candidates){const auto& signature=index->signatures[id];identities.emplace(signature.row["library"].get<std::string>(),signature.row["name"].get<std::string>());if(evidence.size()==64)continue;auto strength=signature.fixedBits>=256&&signature.exactLength?"strong_pattern":signature.fixedBits>=128?"moderate_pattern":"weak_pattern";evidence.push_back({{"signature_id",signature.row["id"]},{"name",signature.row["name"]},{"library",signature.row["library"]},{"source",signature.row["source"]},{"fixed_bits",signature.fixedBits},{"byte_count",signature.bytes.size()},{"whole_function",signature.exactLength},{"strength",strength}});}
   Json match={{"address",hex(function.va)},{"current_name",function.name},{"ambiguous",identities.size()>1},{"identity_verified",false},{"candidate_count",candidates.size()},{"candidates_truncated",candidates.size()>evidence.size()},{"candidates",std::move(evidence)}};auto itemBytes=match.dump().size()+2;if(itemBytes>outputBudget-outputBytes){outputHit=true;break;}outputBytes+=itemBytes;matches.push_back(std::move(match));
  }++examined;++i;
 }
 auto next=offset+examined;return {{"matches",matches},{"functions_examined",examined},{"next_function_offset",next},{"remaining_functions",selected.size()-next},{"truncated",next<selected.size()},{"cancelled",engine.cancelled()},{"comparison_budget_exhausted",budgetHit},{"output_budget_exhausted",outputHit},{"max_output_bytes",outputBudget},{"comparisons",comparisons},{"unavailable_functions",unavailable},{"signature_count",index->signatures.size()},{"analysis_skipped",false},{"note","Pattern matches are candidate evidence; ambiguous or short patterns do not establish library identity. Names and analysis are unchanged."}};
}
Json load(Engine& engine,const Json& args){cancelled(engine);auto path=std::filesystem::u8path(text(args,"path",32768));std::ifstream input(path,std::ios::binary|std::ios::ate);if(!input)throw std::runtime_error("Cannot open signature database");auto size=input.tellg();if(size<0||size>static_cast<std::streamoff>(maxDatabaseBytes))throw std::runtime_error("Signature database exceeds 8 MiB");std::string body(static_cast<size_t>(size),'\0');input.seekg(0);if(!input.read(body.data(),static_cast<std::streamsize>(body.size())))throw std::runtime_error("Cannot read signature database");cancelled(engine);auto document=Json::parse(body);if(!document.is_object()||document.value("scratcher_signatures",0)!=1||!document.contains("signatures"))throw std::runtime_error("Unsupported signature database");auto incoming=rows(validated(document["signatures"],engine));if(args.value("merge",false)){auto previous=state(engine)["signatures"];for(const auto& row:incoming)previous.push_back(row);incoming=std::move(previous);}replace(engine,incoming);return {{"path",pathText(path)},{"signature_count",incoming.size()},{"merged",args.value("merge",false)}};}
Json save(Engine& engine,const Json& args){cancelled(engine);auto path=std::filesystem::absolute(std::filesystem::u8path(text(args,"path",32768)));if(path.filename().empty()||path.filename().native().find(L':')!=std::wstring::npos)throw std::runtime_error("Choose a new signature database file");auto signatures=rows(validated(state(engine)["signatures"],engine));auto body=Json{{"scratcher_signatures",1},{"signatures",signatures}}.dump(2);if(body.size()>maxDatabaseBytes)throw std::runtime_error("Signature database exceeds 8 MiB");
 auto file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create signature database; existing files are preserved");bool committed=false;
 try{for(size_t offset=0;offset<body.size();){cancelled(engine);DWORD written=0;auto count=static_cast<DWORD>(std::min<size_t>(65536,body.size()-offset));if(!WriteFile(file,body.data()+offset,count,&written,nullptr)||!written)throw std::runtime_error("Cannot write signature database");offset+=written;}cancelled(engine);if(!FlushFileBuffers(file))throw std::runtime_error("Cannot flush signature database");CloseHandle(file);file=INVALID_HANDLE_VALUE;committed=true;}
 catch(...){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(!committed)DeleteFileW(path.c_str());throw;}
 return {{"path",pathText(path)},{"signature_count",signatures.size()},{"bytes",body.size()}};
}
}
Json recognitionTools(){
 Json result=Json::array();auto str=[](size_t maximum){return Json{{"type","string"},{"minLength",1},{"maxLength",maximum}};};auto number=[](size_t minimum,size_t maximum){return Json{{"type","integer"},{"minimum",minimum},{"maximum",maximum}};};auto boolean=Json{{"type","boolean"}};auto add=[&](const char* name,const char* description,Json properties,Json required,bool readOnly){result.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",properties},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readOnly},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("train_library_signature","Train a function byte signature with optional masking of relative/address operands. Identity and relocation coverage remain unverified.",{{"address",str(32)},{"id",str(128)},{"name",str(512)},{"library",str(512)},{"source",str(2048)},{"byte_count",number(4,maxLength)},{"mask_addresses",boolean}},{"address","id","library"},false);
 add("add_library_signature","Add a masked byte pattern with explicit provenance. Requires at least 32 fixed bits; duplicate identifiers are rejected.",{{"id",str(128)},{"name",str(512)},{"library",str(512)},{"architecture",{{"type","string"},{"enum",{"x86","x86_64"}}}},{"pattern",str(maxLength*3)},{"exact_length",boolean},{"source",str(2048)},{"description",{{"type","string"},{"maxLength",2048}}}},{"id","name","library","architecture","pattern"},false);
 add("remove_library_signature","Remove one signature by identifier.",{{"id",str(128)}},{"id"},false);
 add("list_library_signatures","List bounded signature records and their pattern strength.",{{"offset",number(0,SIZE_MAX)},{"limit",number(1,500)}},Json::array(),true);
 add("identify_libraries","Find candidate library signatures at indexed function starts. Reports ambiguity and evidence; never skips analysis or changes names.",{{"addresses",{{"type","array"},{"items",str(32)},{"maxItems",1000}}},{"function_offset",number(0,SIZE_MAX)},{"max_functions",number(1,10000)},{"limit",number(1,1000)},{"comparison_budget",number(1,10000000)},{"max_output_bytes",number(1024,4*1024*1024)}},Json::array(),true);
 add("load_library_signatures","Load a bounded signature database; optionally merge without replacing existing identifiers.",{{"path",str(32768)},{"merge",boolean}},{"path"},false);
 add("save_library_signatures","Write a new signature database file. Existing files are preserved.",{{"path",str(32768)}},{"path"},false);return result;
}
std::optional<Json> callRecognitionTool(Engine& engine,const std::string& name,const Json& args){
 if(name=="train_library_signature")return train(engine,args);
 if(name=="identify_libraries")return identify(engine,args);
 if(name=="add_library_signature"){cancelled(engine);auto signature=parse(args);auto all=state(engine)["signatures"];for(const auto& row:all)if(row["id"]==signature.row["id"])throw std::runtime_error("Signature id already exists");all.push_back(signature.row);replace(engine,all);return Json{{"signature",signature.row},{"fixed_bits",signature.fixedBits}};}
 if(name=="remove_library_signature"){cancelled(engine);auto id=text(args,"id",128);auto all=state(engine)["signatures"];auto found=std::find_if(all.begin(),all.end(),[&](const Json& row){return row["id"].get<std::string>()==id;});bool removed=found!=all.end();if(removed){all.erase(found);replace(engine,all);}return Json{{"removed",removed},{"id",id}};}
 if(name=="list_library_signatures"){auto signatures=compiled(engine);auto offset=bounded(args,"offset",0,0,SIZE_MAX),limit=bounded(args,"limit",100,1,500);auto items=Json::array();for(size_t i=offset;i<signatures->signatures.size()&&items.size()<limit;++i){cancelled(engine);auto row=signatures->signatures[i].row;row["fixed_bits"]=signatures->signatures[i].fixedBits;items.push_back(std::move(row));}return Json{{"items",items},{"total",signatures->signatures.size()},{"offset",offset},{"next_offset",offset+items.size()},{"truncated",offset+items.size()<signatures->signatures.size()}};}
 if(name=="load_library_signatures")return load(engine,args);
 if(name=="save_library_signatures")return save(engine,args);return std::nullopt;
}
}
