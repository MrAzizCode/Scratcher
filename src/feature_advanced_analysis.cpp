#include "feature_advanced_analysis.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <chrono>
#include <deque>
#include <limits>
#include <set>
#include <tuple>

namespace scratcher {
namespace {
constexpr size_t cacheLimit=8*1024*1024, rowLimit=1024;
const Binary& requireBinary(const Engine& engine){if(!engine.binary())throw std::runtime_error("Open a binary first");return *engine.binary();}
void checkCancellation(const Engine& engine){if(engine.cancelled())throw std::runtime_error("Operation cancelled");}
size_t bounded(const Json& args,const char* key,size_t fallback,size_t low,size_t high){
 if(!args.contains(key))return fallback;const auto& j=args.at(key);
 if(!j.is_number_integer()||(j.is_number_integer()&&!j.is_number_unsigned()&&j.get<int64_t>()<0))throw std::runtime_error(std::string(key)+" must be a nonnegative integer");
 auto v=j.get<uint64_t>();if(v<low||v>high)throw std::runtime_error(std::string(key)+" is outside its supported range");return static_cast<size_t>(v);
}
uint64_t fingerprint(const void* input,size_t length){auto p=static_cast<const uint8_t*>(input);uint64_t h=14695981039346656037ULL;for(size_t i=0;i<length;++i){h^=p[i];h*=1099511628211ULL;}return h;}
bool importOverlap(const Binary& b,Address va,size_t bytes){if(!bytes)return false;for(const auto& slot:b.imports)if(va<=slot.va?slot.va-va<bytes:va-slot.va<static_cast<uint64_t>(b.bits/8))return true;return false;}
bool readOnlySpan(const Binary& b,Address va,size_t bytes){auto s=b.section(va);if(!s||s->writable||!bytes||va>UINT64_MAX-(bytes-1)||importOverlap(b,va,bytes))return false;auto extent=std::min(s->fileSize,s->memorySize),delta=va-s->va;return delta<extent&&bytes<=extent-delta&&s->offset<=UINT64_MAX-delta&&b.has(s->offset+delta,bytes);}
std::optional<uint64_t> memoryValue(const Binary& b,Address va,size_t bytes){
 auto s=b.section(va);if(!s||va<s->va||!bytes||bytes>8||va>UINT64_MAX-(bytes-1)||importOverlap(b,va,bytes))return {};auto delta=va-s->va;
 if(delta>=s->fileSize||bytes>s->fileSize-delta||delta>=s->memorySize||bytes>s->memorySize-delta||s->offset>UINT64_MAX-delta||!b.has(s->offset+delta,bytes))return {};
 uint64_t v=0;std::memcpy(&v,b.bytes()+s->offset+delta,bytes);return v;
}
bool manualData(const Engine& e,Address va){
 const auto& a=e.advancedState();if(!a.contains("manual")||!a["manual"].is_object())return false;
 for(const auto& r:a["manual"].value("ranges",Json::array()))try{if(r.value("kind",std::string())=="data"&&va>=address(r.at("start"))&&va<address(r.at("end")))return true;}catch(const std::exception&){}return false;
}
std::vector<Address> manualTargets(const Engine& e,Address va){std::vector<Address> result;const auto& a=e.advancedState();if(!a.contains("manual")||!a["manual"].is_object())return result;
 for(const auto& sw:a["manual"].value("switches",Json::array()))try{if(address(sw.at("address"))==va){for(const auto& t:sw.at("targets")){if(result.size()>=256)break;result.push_back(address(t));}break;}}catch(const std::exception&){}return result;
}
bool deletedFunction(const Engine& e,Address va){const auto& a=e.advancedState();if(!a.contains("manual")||!a["manual"].is_object())return false;for(const auto& item:a["manual"].value("deleted_functions",Json::array()))if(item==hex(va))return true;return false;}
ZydisMachineMode mode(const Binary& b){return b.bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32;}
ZydisRegister canonical(const Binary& b,ZydisRegister r){return ZydisRegisterGetLargestEnclosing(mode(b),r);}
Address trustedCodeEnd(const Binary& b,Address va){auto s=b.section(va);if(!s||!b.analysisCode(va)||s->offset>b.size())return 0;auto extent=std::min({s->fileSize,s->memorySize,b.size()-s->offset});if(s->va>UINT64_MAX-extent||va-s->va>=extent)return 0;Address limit=s->va+extent;if(s->executable)return limit;Address end=va;for(const auto& range:b.analysisRanges)if(range.first<=va&&range.second>va)end=std::max(end,range.second);bool changed=true;while(changed){changed=false;for(const auto& range:b.analysisRanges)if(range.first<=end&&range.second>end){end=range.second;changed=true;}}return std::min(end,limit);}
struct Decoded {Instruction row;ZydisDecodedInstruction instruction{};ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};};
std::optional<Decoded> decode(Engine& e,Address va){const auto& b=requireBinary(e);if(!b.language.starts_with("x86:"))return {};auto s=b.section(va);if(!s||!b.analysisCode(va)||va-s->va>=std::min(s->fileSize,s->memorySize))return {};
 auto codeEnd=trustedCodeEnd(b,va);if(codeEnd<=va)return {};auto delta=va-s->va;auto available=static_cast<size_t>(std::min<uint64_t>(15,codeEnd-va));if(s->offset>UINT64_MAX-delta||!b.has(s->offset+delta,available))return {};
 ZydisDecoder decoder{};ZydisDecoderInit(&decoder,mode(b),b.bits==64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32);Decoded d;
 if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,b.bytes()+s->offset+delta,available,&d.instruction,d.operands)))return {};
 auto rows=e.disassemble(va,1);if(rows.empty())return {};d.row=std::move(rows.front());return d;
}
struct Bound {uint64_t maximum=0;uint16_t width=0;bool operator==(const Bound&)const=default;};
struct Comparison {ZydisRegister reg=ZYDIS_REGISTER_NONE;uint64_t maximum=0;uint16_t width=0;bool operator==(const Comparison&)const=default;};
struct State {
 std::optional<int64_t> stack=0,frame;
 std::map<ZydisRegister,uint64_t> constants;
 std::map<ZydisRegister,Bound> bounds;
 std::set<ZydisRegister> zeroUpper32;
 std::optional<Comparison> comparison;
 bool operator==(const State&)const=default;
};
bool merge(State& existing,const State& incoming){auto old=existing;if(existing.stack!=incoming.stack)existing.stack.reset();if(existing.frame!=incoming.frame)existing.frame.reset();if(existing.comparison!=incoming.comparison)existing.comparison.reset();
 for(auto it=existing.constants.begin();it!=existing.constants.end();) {auto found=incoming.constants.find(it->first);if(found==incoming.constants.end()||found->second!=it->second)it=existing.constants.erase(it);else ++it;}
 for(auto it=existing.bounds.begin();it!=existing.bounds.end();) {auto found=incoming.bounds.find(it->first);if(found==incoming.bounds.end())it=existing.bounds.erase(it);else {it->second.maximum=std::max(it->second.maximum,found->second.maximum);it->second.width=std::min(it->second.width,found->second.width);++it;}}
 for(auto it=existing.zeroUpper32.begin();it!=existing.zeroUpper32.end();)if(!incoming.zeroUpper32.contains(*it))it=existing.zeroUpper32.erase(it);else ++it;
 return !(old==existing);
}
std::optional<Address> effective(const Binary& b,const Decoded& d,const ZydisDecodedOperand& op,const State& state,bool ignoreIndex=false){
 if(op.type!=ZYDIS_OPERAND_TYPE_MEMORY||op.mem.segment==ZYDIS_REGISTER_FS||op.mem.segment==ZYDIS_REGISTER_GS)return {};
 ZydisRegisterContext context{};
 for(auto r:{op.mem.base,ignoreIndex?ZYDIS_REGISTER_NONE:op.mem.index})if(r!=ZYDIS_REGISTER_NONE&&r!=ZYDIS_REGISTER_RIP&&r!=ZYDIS_REGISTER_EIP){auto found=state.constants.find(canonical(b,r));if(found==state.constants.end())return {};auto width=ZydisRegisterGetWidth(mode(b),r);context.values[r]=width==32?found->second&0xffffffffULL:found->second;}
 auto modified=op;if(ignoreIndex)modified.mem.index=ZYDIS_REGISTER_NONE;
 ZyanU64 result=0;if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&d.instruction,&modified,d.row.va,&context,&result)))return {};return result;
}
std::optional<uint64_t> operandValue(const Binary& b,const Decoded& d,const ZydisDecodedOperand& op,const State& state){
 if(op.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){if(op.imm.is_relative){ZyanU64 result=0;if(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction,&op,d.row.va,&result)))return result;return {};}return op.imm.value.u;}
 if(op.type==ZYDIS_OPERAND_TYPE_REGISTER){auto found=state.constants.find(canonical(b,op.reg.value));auto width=ZydisRegisterGetWidth(mode(b),op.reg.value);if(found!=state.constants.end()&&width>=32)return width==32?found->second&0xffffffffULL:found->second;}
 if(op.type==ZYDIS_OPERAND_TYPE_MEMORY){auto va=effective(b,d,op,state);if(va){auto s=b.section(*va);if(s&&!s->writable&&(op.size==32||op.size==64))return memoryValue(b,*va,op.size/8);}}
 return {};
}
State transfer(const Binary& b,const Decoded& d,const State& input){State output=input;const auto m=d.instruction.mnemonic;const auto sp=b.bits==64?ZYDIS_REGISTER_RSP:ZYDIS_REGISTER_ESP,bp=b.bits==64?ZYDIS_REGISTER_RBP:ZYDIS_REGISTER_EBP;
 if(d.instruction.meta.category!=ZYDIS_CATEGORY_COND_BR)output.comparison.reset();
 // Clear every explicit and implicit written register before setting proven values.
 bool writesSP=false,writesBP=false;
 for(size_t i=0;i<d.instruction.operand_count;++i){const auto& o=d.operands[i];if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&(o.actions&ZYDIS_OPERAND_ACTION_MASK_WRITE)){auto r=canonical(b,o.reg.value);output.constants.erase(r);output.bounds.erase(r);output.zeroUpper32.erase(r);if(output.comparison&&output.comparison->reg==r)output.comparison.reset();if(b.bits==64&&o.size==32&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE))output.zeroUpper32.insert(r);writesSP|=r==sp;writesBP|=r==bp;}}
 if(writesSP)output.stack.reset();if(writesBP)output.frame.reset();
 auto delta=[&](int64_t v){if(input.stack&&((v>=0&&*input.stack<=INT64_MAX-v)||(v<0&&*input.stack>=INT64_MIN-v)))output.stack=*input.stack+v;};
 if(m==ZYDIS_MNEMONIC_PUSH||m==ZYDIS_MNEMONIC_PUSHF||m==ZYDIS_MNEMONIC_PUSHFD||m==ZYDIS_MNEMONIC_PUSHFQ)delta(-static_cast<int64_t>(d.instruction.operand_width/8));
 else if(m==ZYDIS_MNEMONIC_POP||m==ZYDIS_MNEMONIC_POPF||m==ZYDIS_MNEMONIC_POPFD||m==ZYDIS_MNEMONIC_POPFQ){if(d.operands[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||canonical(b,d.operands[0].reg.value)!=sp)delta(d.instruction.operand_width/8);}
 else if(m==ZYDIS_MNEMONIC_LEAVE){if(d.instruction.operand_width==b.bits&&input.frame&&*input.frame<=INT64_MAX-b.bits/8)output.stack=*input.frame+b.bits/8;output.frame.reset();}
 else if(d.instruction.meta.category==ZYDIS_CATEGORY_CALL){output.stack=b.bits==64?input.stack:std::nullopt;output.frame.reset();output.constants.clear();output.bounds.clear();output.zeroUpper32.clear();output.comparison.reset();}
 else if(d.instruction.meta.category==ZYDIS_CATEGORY_RET)output.stack=input.stack;
 if(d.instruction.operand_count_visible>=2){const auto& dest=d.operands[0];const auto& src=d.operands[1];
  if(m==ZYDIS_MNEMONIC_CMP&&dest.type==ZYDIS_OPERAND_TYPE_REGISTER&&dest.size>=32&&src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&src.imm.value.u<=255)output.comparison=Comparison{canonical(b,dest.reg.value),src.imm.value.u,dest.size};
  if(dest.type==ZYDIS_OPERAND_TYPE_REGISTER){auto r=canonical(b,dest.reg.value);std::optional<uint64_t> value;
   if(m==ZYDIS_MNEMONIC_MOV)value=operandValue(b,d,src,input);
   else if(m==ZYDIS_MNEMONIC_LEA)value=effective(b,d,src,input);
   else if(m==ZYDIS_MNEMONIC_XOR&&src.type==ZYDIS_OPERAND_TYPE_REGISTER&&dest.reg.value==src.reg.value)value=0;
   else if(m==ZYDIS_MNEMONIC_ADD||m==ZYDIS_MNEMONIC_SUB){auto a=operandValue(b,d,dest,input),c=operandValue(b,d,src,input);if(a&&c)value=m==ZYDIS_MNEMONIC_ADD?*a+*c:*a-*c;
    if(r==sp&&dest.size==b.bits&&src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&src.imm.value.u<=INT64_MAX)delta(m==ZYDIS_MNEMONIC_ADD?static_cast<int64_t>(src.imm.value.u):-static_cast<int64_t>(src.imm.value.u));}
   if(value&&dest.size>=32){output.constants[r]=dest.size==32?*value&0xffffffffULL:*value;if(b.bits==64&&output.constants[r]<=0xffffffffULL)output.zeroUpper32.insert(r);}
   if(m==ZYDIS_MNEMONIC_MOV&&src.type==ZYDIS_OPERAND_TYPE_REGISTER){if(r==bp&&canonical(b,src.reg.value)==sp&&dest.size==b.bits)output.frame=input.stack;if(r==sp&&canonical(b,src.reg.value)==bp&&dest.size==b.bits)output.stack=input.frame;}
  }
 }
 return output;
}
struct Range {Address start,end;std::string boundary;};
Range functionRange(const Binary& b,Address requested,size_t byteBudget,bool exactStart){auto s=b.section(requested);auto codeEnd=trustedCodeEnd(b,requested);if(!s||codeEnd<=requested)throw std::runtime_error("Analysis address must be file-backed code or a trusted code candidate");
 Range r{requested,codeEnd,s->executable?"section":"metadata_candidate"};const Function* containing=nullptr;
 for(const auto& f:b.functions)if(f.va==requested||(!exactStart&&f.end>f.va&&requested>=f.va&&requested<f.end)){if(!containing||f.va>containing->va)containing=&f;}
 if(containing&&b.section(containing->va)==s&&trustedCodeEnd(b,containing->va)>=requested){r.start=containing->va;r.end=std::min(r.end,trustedCodeEnd(b,r.start));if(containing->end>r.start){r.end=std::min(r.end,containing->end);r.boundary="indexed_function";}}
 if(r.boundary=="section"||r.boundary=="metadata_candidate")for(const auto& f:b.functions)if(f.va>r.start&&f.va<r.end){r.end=f.va;r.boundary="next_indexed_function";}
 if(byteBudget<r.end-r.start){r.end=r.start+byteBudget;r.boundary="byte_budget";}if(r.start>=r.end)throw std::runtime_error("Analysis address has no file-backed executable bytes");return r;
}
Json recoverTable(Engine& engine,Address table,size_t count,size_t width,std::optional<Address> relative){const auto& b=requireBinary(engine);Json rows=Json::array();size_t valid=0;const bool immutable=count<=SIZE_MAX/width&&readOnlySpan(b,table,count*width);bool complete=immutable;
 for(size_t i=0;i<count;++i){checkCancellation(engine);if(i>(UINT64_MAX-table)/width){complete=false;rows.push_back({{"index",i},{"reason","address_overflow"}});break;}auto at=table+i*width;auto raw=memoryValue(b,at,width);if(!raw){complete=false;rows.push_back({{"index",i},{"entry_address",hex(at)},{"reason","unmapped_entry"}});continue;}
  Address target=*raw;bool overflow=false;if(relative){int64_t signedValue=width==4?static_cast<int64_t>(static_cast<int32_t>(*raw)):static_cast<int64_t>(*raw);if(signedValue>=0){overflow=static_cast<uint64_t>(signedValue)>UINT64_MAX-*relative;if(!overflow)target=*relative+static_cast<uint64_t>(signedValue);}else {auto magnitude=static_cast<uint64_t>(-(signedValue+1))+1;overflow=magnitude>*relative;if(!overflow)target=*relative-magnitude;}}
  bool executable=!overflow&&b.analysisCode(target)&&!manualData(engine,target);bool decodable=executable&&decode(engine,target).has_value();if(decodable)++valid;else complete=false;
  auto section=b.section(at);rows.push_back({{"index",i},{"entry_address",hex(at)},{"target",overflow?Json(nullptr):Json(hex(target))},{"executable",executable},{"decodable",decodable},{"mutable_storage",section&&section->writable},{"certainty","table_candidate"},{"reason",overflow?"target_overflow":decodable?"valid_candidate":"non_code_target"}});
 }
 return {{"table",hex(table)},{"entry_size",width},{"relative_base",relative?Json(hex(*relative)):Json(nullptr)},{"entry_count",count},{"valid_candidates",valid},{"all_entries_valid",complete},{"storage_read_only",immutable},{"storage_policy","Whole nonwrapping table must fit one file-backed read-only section and not overlap runtime import slots."},{"items",rows},{"certainty","candidate_targets_require_verified_dispatch_and_bounds"},{"format_inferred",false}};
}
std::string cacheKey(Engine& e,const Range& range,size_t budget,bool rows){const auto& b=requireBinary(e);auto s=b.section(range.start);auto offset=s->offset+(range.start-s->va);auto h=fingerprint(b.bytes()+offset,static_cast<size_t>(range.end-range.start));
 auto manual=e.advancedState().value("manual",Json::object()).dump();auto layout=b.info().value("sections",Json::array()).dump();Json imports=Json::array();for(const auto& slot:b.imports)imports.push_back(slot.va);auto policy=Json{{"bits",b.bits},{"language",b.language},{"candidate_ranges",b.analysisRanges},{"import_slots",imports}}.dump();return "typed_bounds_v3:"+hex(range.start)+":"+hex(range.end)+":"+std::to_string(budget)+":"+std::to_string(rows)+":"+hex(h)+":"+hex(fingerprint(manual.data(),manual.size()))+":"+hex(fingerprint(layout.data(),layout.size()))+":"+hex(fingerprint(policy.data(),policy.size()));
}
bool validDependencies(const Binary& b,const Json& dependencies){for(const auto& dep:dependencies){auto va=address(dep.at("address"));auto count=dep.at("bytes").get<size_t>();auto section=b.section(va);if(!section||count>4096||va-section->va>section->fileSize||count>section->fileSize-(va-section->va))return false;auto offset=section->offset+(va-section->va);if(!b.has(offset,count)||hex(fingerprint(b.bytes()+offset,count))!=dep.at("fingerprint").get<std::string>())return false;}return true;}
struct SwitchOutput {std::vector<BoundedSwitchTransfer> transfers;size_t limit=0;bool storageComplete=true,timedOut=false,filtered=false;};
Json reachable(Engine& engine,const Json& args,bool exactStart=false,SwitchOutput* typed=nullptr,std::optional<std::chrono::steady_clock::time_point> deadline={}){const auto started=std::chrono::steady_clock::now();checkCancellation(engine);const auto& b=requireBinary(engine);if(!b.language.starts_with("x86:")||(b.bits!=32&&b.bits!=64))throw std::runtime_error("Reachable analysis currently supports x86 and x64");
 auto requested=address(args.at("address"));auto budget=bounded(args,"instruction_budget",4096,1,20000),bytes=bounded(args,"byte_budget",1024*1024,1,16*1024*1024);bool includeRows=args.value("include_instructions",false),useCache=args.value("use_cache",true);auto range=functionRange(b,requested,bytes,exactStart);auto key=cacheKey(engine,range,budget,includeRows);
 auto& cache=engine.advancedState()["analysis"];if(!cache.is_object())cache=Json::object();if(!cache.contains("cache")||!cache["cache"].is_array())cache["cache"]=Json::array();
 if(useCache&&!typed)for(const auto& item:cache["cache"])if(item.value("key",std::string())==key&&validDependencies(b,item.value("dependencies",Json::array()))){auto result=item.at("result");result["cache_hit"]=true;result["analysis_ms"]=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count();return result;}
 std::map<Address,Decoded> decoded;std::map<Address,State> states;std::map<Address,size_t> visits;std::set<Address> queued;std::deque<Address> pending;std::map<Address,std::string> issues;std::set<std::tuple<Address,Address,std::string>> edges,calls;Json dependencies=Json::array();size_t updates=0;bool truncated=false,stalled=false;std::set<std::pair<Address,size_t>> pointerSeen;
 auto addIssue=[&](Address at,const std::string& reason){if(issues.size()<rowLimit)issues.try_emplace(at,reason);};
 auto enqueue=[&](Address at,const State& state,Address from,const std::string& label){edges.emplace(from,at,label);if(at<range.start||at>=range.end||!b.analysisCode(at)){addIssue(from,"edge_outside_function_range");return;}if(manualData(engine,at)){addIssue(at,"manual_data_boundary");return;}auto found=states.find(at);bool changed=found==states.end();if(changed)states[at]=state;else changed=merge(found->second,state);if(changed&&queued.insert(at).second)pending.push_back(at);};
 states[range.start]=State{};pending.push_back(range.start);queued.insert(range.start);
 auto addDependency=[&](Address at,size_t width){if(!pointerSeen.insert({at,width}).second)return;auto s=b.section(at);if(s&&width<=4096&&at-s->va<s->fileSize&&width<=s->fileSize-(at-s->va)&&b.has(s->offset+at-s->va,width))dependencies.push_back({{"address",hex(at)},{"bytes",width},{"fingerprint",hex(fingerprint(b.bytes()+s->offset+at-s->va,width))}});};
 while(!pending.empty()){checkCancellation(engine);if(deadline&&std::chrono::steady_clock::now()>=*deadline){truncated=true;if(typed)typed->timedOut=true;break;}auto va=pending.front();pending.pop_front();queued.erase(va);if(++visits[va]>8){addIssue(va,"dataflow_iteration_limit");stalled=true;continue;}++updates;
  if(manualData(engine,va)){addIssue(va,"manual_data_boundary");continue;}
  auto found=decoded.find(va);if(found==decoded.end()){
   if(decoded.size()>=budget){truncated=true;break;}auto prev=decoded.upper_bound(va);if(prev!=decoded.begin()){--prev;if(va>prev->first&&va-prev->first<static_cast<Address>(prev->second.row.length)){addIssue(va,"overlapping_instruction_target");continue;}}
   auto d=decode(engine,va);if(!d){addIssue(va,"invalid_or_unmapped_instruction");continue;}if(static_cast<Address>(d->row.length)>range.end-va){addIssue(va,"instruction_crosses_boundary");continue;}
   auto next=decoded.upper_bound(va);if(next!=decoded.end()&&next->first<va+d->row.length){addIssue(va,"overlapping_instruction_target");continue;}
   bool definedData=false;for(int n=0;n<d->row.length;++n)definedData|=manualData(engine,va+n);if(definedData){addIssue(va,"instruction_crosses_manual_data");continue;}
   found=decoded.emplace(va,std::move(*d)).first;
  }
  // Recomputed states replace prior provisional outgoing facts. A join can
  // invalidate a constant target, so never retain its previous proven edge.
  for(auto it=edges.lower_bound({va,0,""});it!=edges.end()&&std::get<0>(*it)==va;)it=edges.erase(it);
  for(auto it=calls.lower_bound({va,0,""});it!=calls.end()&&std::get<0>(*it)==va;)it=calls.erase(it);
  issues.erase(va);
  const auto& d=found->second;auto input=states.at(va);for(size_t i=0;i<d.instruction.operand_count_visible;++i){const auto& op=d.operands[i];if(op.type==ZYDIS_OPERAND_TYPE_MEMORY&&(op.size==32||op.size==64)){auto at=effective(b,d,op,input);if(at){auto section=b.section(*at);if(section&&!section->writable)addDependency(*at,op.size/8);}}}auto output=transfer(b,d,input);auto next=va+d.row.length;auto category=d.instruction.meta.category;auto m=d.instruction.mnemonic;
  if(category==ZYDIS_CATEGORY_CALL||category==ZYDIS_CATEGORY_UNCOND_BR||category==ZYDIS_CATEGORY_COND_BR){std::optional<Address> target;const auto& op=d.operands[0];std::string certainty="direct";
   if(op.type==ZYDIS_OPERAND_TYPE_IMMEDIATE)target=operandValue(b,d,op,input);
   else if(op.type==ZYDIS_OPERAND_TYPE_REGISTER){target=operandValue(b,d,op,input);certainty="proven_register_constant";}
   else if(op.type==ZYDIS_OPERAND_TYPE_MEMORY){auto at=effective(b,d,op,input);if(at&&(op.size==32||op.size==64)){addDependency(*at,op.size/8);auto s=b.section(*at);if(s&&!s->writable){target=memoryValue(b,*at,op.size/8);certainty="read_only_file_pointer";}else addIssue(va,s?"mutable_indirect_pointer_runtime_unknown":"unmapped_indirect_pointer");}}
   if(category==ZYDIS_CATEGORY_CALL){if(target&&b.analysisCode(*target)&&!manualData(engine,*target))calls.emplace(va,*target,certainty);else addIssue(va,"unresolved_or_external_call");enqueue(next,output,va,"fallthrough");}
   else if(category==ZYDIS_CATEGORY_COND_BR){if(target)enqueue(*target,output,va,"taken");else addIssue(va,"unresolved_conditional_branch");
    if(input.comparison&&(m==ZYDIS_MNEMONIC_JNBE||m==ZYDIS_MNEMONIC_JNB)){const auto& cmp=*input.comparison;if(m==ZYDIS_MNEMONIC_JNBE)output.bounds[cmp.reg]={cmp.maximum,cmp.width};else if(cmp.maximum)output.bounds[cmp.reg]={cmp.maximum-1,cmp.width};}output.comparison.reset();enqueue(next,output,va,"not_taken");}
   else if(target)enqueue(*target,output,va,certainty);
   else {auto targets=manualTargets(engine,va);if(!targets.empty()){for(auto t:targets)enqueue(t,output,va,"manual_switch");}
    else if(op.type==ZYDIS_OPERAND_TYPE_MEMORY&&op.mem.index!=ZYDIS_REGISTER_NONE&&op.mem.scale==op.size/8&&(op.size==32||op.size==64)){
     auto bound=input.bounds.find(canonical(b,op.mem.index));auto table=effective(b,d,op,input,true);auto section=table?b.section(*table):nullptr;
     const auto index=canonical(b,op.mem.index);auto indexWidth=ZydisRegisterGetWidth(mode(b),op.mem.index);
     // A 32-bit comparison constrains only the low half of a 64-bit address
     // index. It is usable for RAX only when an unconditional 32-bit write (or
     // a full known constant) proved the upper half zero on every input path.
     bool widthCovered=bound!=input.bounds.end()&&(bound->second.width>=indexWidth||(bound->second.width==32&&indexWidth==64&&input.zeroUpper32.contains(index)));
     bool tableDoesNotWrap=true;if(widthCovered&&table&&d.instruction.address_width<64){uint64_t limit=d.instruction.address_width==32?0xffffffffULL:0xffffULL;uint64_t span=(bound->second.maximum+1)*(op.size/8);tableDoesNotWrap=*table<=limit&&span&&span-1<=limit-*table;}
     if(widthCovered&&bound->second.maximum<256&&table&&section&&!section->writable&&tableDoesNotWrap){auto count=static_cast<size_t>(bound->second.maximum+1),width=static_cast<size_t>(op.size/8);auto report=recoverTable(engine,*table,count,width,{});addDependency(*table,count*width);
      if(report["all_entries_valid"].get<bool>()){for(const auto& row:report["items"])enqueue(address(row["target"]),output,va,"bounded_read_only_table");}else addIssue(va,"jump_table_has_invalid_entries");}
     else addIssue(va,"indirect_jump_bounds_or_table_unknown");}
    else addIssue(va,"unresolved_indirect_jump");}
  }else if(category==ZYDIS_CATEGORY_RET){}
  else if(category==ZYDIS_CATEGORY_INTERRUPT||m==ZYDIS_MNEMONIC_HLT||m==ZYDIS_MNEMONIC_UD2){addIssue(va,"trap_or_system_transition");}
  else enqueue(next,output,va,"fallthrough");
 }
 // Remove instructions reached only through a constant edge invalidated by a
 // later join. The final report uses the converged graph, not transient paths.
 std::set<Address> finalReachable{range.start};std::deque<Address> finalPending{range.start};
 while(!finalPending.empty()){auto at=finalPending.front();finalPending.pop_front();for(auto it=edges.lower_bound({at,0,""});it!=edges.end()&&std::get<0>(*it)==at;++it){auto to=std::get<1>(*it);if(to>=range.start&&to<range.end&&finalReachable.insert(to).second)finalPending.push_back(to);}}
 for(auto it=decoded.begin();it!=decoded.end();)if(!finalReachable.count(it->first))it=decoded.erase(it);else ++it;
 for(auto it=edges.begin();it!=edges.end();)if(!finalReachable.count(std::get<0>(*it)))it=edges.erase(it);else ++it;
 for(auto it=calls.begin();it!=calls.end();)if(!finalReachable.count(std::get<0>(*it)))it=calls.erase(it);else ++it;
 for(auto it=issues.begin();it!=issues.end();)if(!finalReachable.count(it->first))it=issues.erase(it);else ++it;
 if(typed&&!truncated&&!stalled){
  // Group complete dispatches before applying the typed storage limit. Never
  // turn a clipped JSON page or omitted case into a purported complete table.
  std::map<Address,std::vector<Address>> tables;
  for(const auto& [from,to,kind]:edges)if(kind=="bounded_read_only_table")tables[from].push_back(to);
  for(const auto& [from,targets]:tables){
   bool valid=decoded.contains(from)&&!manualData(engine,from)&&manualTargets(engine,from).empty();
   for(auto to:targets)if(to<range.start||to>=range.end||!decoded.contains(to)||manualData(engine,to)||deletedFunction(engine,to))valid=false;
   if(!valid){typed->filtered=true;continue;}
   if(targets.size()>typed->limit-typed->transfers.size()){typed->storageComplete=false;continue;}
   for(auto to:targets)typed->transfers.push_back({from,to,"bounded_read_only_table"});
  }
 }
 Json instructions=Json::array(),stackRows=Json::array(),edgeRows=Json::array(),callRows=Json::array(),issueRows=Json::array(),ranges=Json::array(),dataRefs=Json::array();Address reachableBytes=0,observedEnd=range.start;size_t unknownStack=0,returnCount=0,unbalanced=0;
 Address runStart=0,runEnd=0;size_t rangeCount=0;auto flushRange=[&](){if(runEnd>runStart){++rangeCount;if(ranges.size()<rowLimit)ranges.push_back({{"start",hex(runStart)},{"end",hex(runEnd)},{"certainty","reachable_instruction_candidate"}});}};
 std::set<Address> referenced;for(const auto& [va,d]:decoded){checkCancellation(engine);reachableBytes+=d.row.length;observedEnd=std::max(observedEnd,va+d.row.length);if(runEnd==va)runEnd=va+d.row.length;else {flushRange();runStart=va;runEnd=va+d.row.length;}
  auto in=states.at(va),out=transfer(b,d,in);if(!in.stack)++unknownStack;if(d.instruction.meta.category==ZYDIS_CATEGORY_RET){++returnCount;if(in.stack&&*in.stack!=0)++unbalanced;}
  if(stackRows.size()<512)stackRows.push_back({{"address",hex(va)},{"sp_delta_before",in.stack?Json(*in.stack):Json(nullptr)},{"sp_delta_after",out.stack?Json(*out.stack):Json(nullptr)},{"frame_delta",in.frame?Json(*in.frame):Json(nullptr)}});
  if(includeRows&&instructions.size()<512)instructions.push_back({{"address",hex(va)},{"length",d.row.length},{"mnemonic",d.row.mnemonic},{"operands",d.row.operands},{"bytes",d.row.bytes}});
  for(size_t i=0;i<d.instruction.operand_count_visible;++i)if(d.operands[i].type==ZYDIS_OPERAND_TYPE_MEMORY){auto ref=effective(b,d,d.operands[i],in);if(ref&&referenced.insert(*ref).second&&dataRefs.size()<512)dataRefs.push_back({{"from",hex(va)},{"to",hex(*ref)},{"classification",b.analysisCode(*ref)?"reference_into_executable_region":"data_reference_candidate"},{"certainty","fixed_effective_address"}});}
 }flushRange();for(const auto& [from,to,kind]:edges)if(edgeRows.size()<rowLimit)edgeRows.push_back({{"from",hex(from)},{"to",hex(to)},{"kind",kind},{"decoded_target",decoded.count(to)!=0}});
 for(const auto& [from,to,certainty]:calls)if(callRows.size()<512)callRows.push_back({{"from",hex(from)},{"target",hex(to)},{"certainty",certainty}});for(const auto& [va,reason]:issues)issueRows.push_back({{"address",hex(va)},{"reason",reason}});
 auto span=range.end-range.start;Json result={{"requested_address",hex(requested)},{"entry",hex(range.start)},{"range_end",hex(range.end)},{"boundary_source",range.boundary},{"observed_reachable_end",hex(observedEnd)},{"instruction_count",decoded.size()},{"instruction_budget",budget},{"reachable_bytes",reachableBytes},{"range_bytes",span},{"unclassified_bytes",span-reachableBytes},{"unclassified_meaning","Unvisited bytes may be data, padding, unreachable code, or targets not recovered; they are not classified as data."},{"reachable_ranges",ranges},{"reachable_range_count",rangeCount},{"instructions",instructions},{"instructions_truncated",includeRows&&decoded.size()>instructions.size()},{"edges",edgeRows},{"edge_count",edges.size()},{"edges_truncated",edges.size()>edgeRows.size()},{"calls",callRows},{"call_count",calls.size()},{"calls_truncated",calls.size()>callRows.size()},{"data_references",dataRefs},{"issues",issueRows},{"stack",{{"states",stackRows},{"states_truncated",decoded.size()>stackRows.size()},{"unknown_instruction_states",unknownStack},{"return_count",returnCount},{"returns_with_nonzero_entry_sp_delta",unbalanced},{"assumptions",{"SP delta is relative to function entry before its return address is removed.","x64 calls are assumed to return with conventional caller SP; x86 call cleanup is unknown.","This is bounded constant and stack dataflow, not an ABI proof or a symbolic executor."}}}},{"dataflow_updates",updates},{"truncated",truncated},{"dataflow_converged",!stalled},{"reachable_traversal_closed",issues.empty()&&!truncated&&!stalled},{"semantic_analysis_complete",false},{"byte_source","original_file; staged patches are not applied"},{"cache_hit",false},{"analysis_ms",std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count()}};
 checkCancellation(engine);auto size=result.dump().size();if(!typed&&size<=1024*1024){Json item={{"key",key},{"entry",hex(range.start)},{"dependencies",dependencies},{"result",result}};auto& entries=cache["cache"];for(auto it=entries.begin();it!=entries.end();)if(it->value("key",std::string())==key)it=entries.erase(it);else ++it;entries.push_back(std::move(item));while(entries.size()>32||entries.dump().size()>cacheLimit)entries.erase(entries.begin());}return result;
}
Json discover(Engine& engine,const Json& args){checkCancellation(engine);auto& b=*engine.editableBinary();auto maxFunctions=bounded(args,"function_budget",128,1,1024),totalBudget=bounded(args,"instruction_budget",20000,1,200000);size_t examined=0,processed=0;std::deque<Address> pending;std::set<Address> queued,existing;for(const auto& f:b.functions)existing.insert(f.va);
 if(args.contains("addresses")){if(!args["addresses"].is_array()||args["addresses"].size()>128)throw std::runtime_error("Provide at most 128 seed addresses");for(const auto& a:args["addresses"])if(queued.insert(address(a)).second)pending.push_back(address(a));}else {if(!b.analysisCode(b.entry))throw std::runtime_error("No executable entry point; provide seed addresses");pending.push_back(b.entry);queued.insert(b.entry);}
 Json reports=Json::array();std::map<Address,Function> additions;bool cancelled=false;
 while(!pending.empty()&&processed<maxFunctions&&examined<totalBudget){if(engine.cancelled()){cancelled=true;break;}auto va=pending.front();pending.pop_front();if(!b.analysisCode(va)||manualData(engine,va))continue;
  auto remaining=std::min<size_t>(20000,totalBudget-examined);auto r=reachable(engine,{{"address",hex(va)},{"instruction_budget",remaining},{"byte_budget",1024*1024}},true);examined+=r["instruction_count"].get<size_t>();++processed;
  for(const auto& call:r["calls"]){auto target=address(call.at("target"));if(!existing.count(target)&&!additions.count(target)&&!deletedFunction(engine,target)&&additions.size()<maxFunctions){if(decode(engine,target)){additions.emplace(target,Function{target,0,"sub_"+hex(target).substr(2),"reachable_call"});if(queued.insert(target).second)pending.push_back(target);}}}
  reports.push_back({{"address",hex(va)},{"instruction_count",r["instruction_count"]},{"observed_reachable_end",r["observed_reachable_end"]},{"truncated",r["truncated"]},{"issue_count",r["issues"].size()},{"return_count",r["stack"]["return_count"]}});
 }
 Json added=Json::array();if(engine.cancelled())cancelled=true;if(!cancelled){for(auto& [va,f]:additions){b.functions.push_back(f);added.push_back({{"address",hex(va)},{"name",f.name},{"end",nullptr},{"boundary_certainty","unknown"},{"source",f.source}});}std::sort(b.functions.begin(),b.functions.end(),[](const auto& a,const auto& c){return a.va<c.va;});if(!additions.empty()){engine.invalidateDecompilation();engine.advancedState()["analysis"]["cache"]=Json::array();}}
 return {{"processed_functions",processed},{"instructions_examined",examined},{"added_functions",added},{"added_count",added.size()},{"cancelled",cancelled},{"truncated",!pending.empty()},{"reports",reports},{"boundary_policy","Call evidence adds entry candidates only; reachable extent is reported, never asserted as a definitive function end."}};
}
}
BoundedSwitchSnapshot prepareBoundedSwitchSnapshot(Engine& engine,const std::vector<Address>& requested,size_t instructionBudget,size_t timeBudgetMs,size_t transferLimit){
 checkCancellation(engine);const auto& b=requireBinary(engine);
 if(requested.size()>256)throw std::runtime_error("Switch preparation supports at most 256 explicit functions");
 if(!instructionBudget||instructionBudget>20000)throw std::runtime_error("Switch preparation instruction budget must be 1..20000");
 if(!timeBudgetMs||timeBudgetMs>300000)throw std::runtime_error("Switch preparation time budget must be 1..300000 ms");
 if(!transferLimit||transferLimit>1000000)throw std::runtime_error("Switch preparation transfer limit must be 1..1000000");
 if(!b.language.starts_with("x86:")||(b.bits!=32&&b.bits!=64))throw std::runtime_error("Switch preparation currently supports x86 and x64");
 auto entries=requested;std::sort(entries.begin(),entries.end());entries.erase(std::unique(entries.begin(),entries.end()),entries.end());
 BoundedSwitchSnapshot snapshot;snapshot.requestedFunctions=entries.size();Json functions=Json::array();
 for(auto entry:entries){
  checkCancellation(engine);
  if(snapshot.transfers.size()==transferLimit){snapshot.selectedFunctionsComplete=false;snapshot.storageComplete=false;snapshot.limitReached=true;snapshot.skippedFunctions+=entries.end()-std::lower_bound(entries.begin(),entries.end(),entry);break;}
  auto indexed=std::lower_bound(b.functions.begin(),b.functions.end(),entry,[](const Function& f,Address at){return f.va<at;});
  if((entry!=b.entry&&(indexed==b.functions.end()||indexed->va!=entry))||deletedFunction(engine,entry)||manualData(engine,entry)||!trustedCodeEnd(b,entry)){
   ++snapshot.skippedFunctions;snapshot.selectedFunctionsComplete=false;snapshot.residualUnknown=true;
   functions.push_back({{"entry",hex(entry)},{"accepted",false},{"reason","unindexed_deleted_data_or_unmapped_entry"}});continue;
  }
  SwitchOutput output;output.limit=transferLimit-snapshot.transfers.size();
  try{
   auto result=reachable(engine,{{"address",hex(entry)},{"instruction_budget",instructionBudget},{"byte_budget",1024*1024},{"use_cache",false}},true,&output,std::chrono::steady_clock::now()+std::chrono::milliseconds(timeBudgetMs));
   ++snapshot.processedFunctions;snapshot.instructionsExamined+=result.at("instruction_count").get<size_t>();
   const bool converged=result.at("dataflow_converged").get<bool>(),truncated=result.at("truncated").get<bool>();
   snapshot.dataflowComplete&=converged&&!truncated;snapshot.selectedFunctionsComplete&=converged&&!truncated;
   snapshot.storageComplete&=output.storageComplete;snapshot.limitReached|=truncated||!output.storageComplete;
   snapshot.residualUnknown|=!result.at("reachable_traversal_closed").get<bool>()||output.filtered||!output.storageComplete;
   functions.push_back({{"entry",hex(entry)},{"accepted",true},{"instruction_count",result.at("instruction_count")},{"range_end",result.at("range_end")},{"boundary_source",result.at("boundary_source")},{"dataflow_converged",converged},{"truncated",truncated},{"deadline_exceeded",output.timedOut},{"table_targets_retained",output.transfers.size()},{"storage_complete",output.storageComplete},{"targets_withheld",output.filtered},{"residual_unknown",!result.at("reachable_traversal_closed").get<bool>()||output.filtered}});
   snapshot.transfers.insert(snapshot.transfers.end(),output.transfers.begin(),output.transfers.end());
  }catch(const std::exception&){if(engine.cancelled())throw;++snapshot.skippedFunctions;snapshot.selectedFunctionsComplete=false;snapshot.dataflowComplete=false;snapshot.residualUnknown=true;functions.push_back({{"entry",hex(entry)},{"accepted",false},{"reason","bounded_analysis_failed"}});}
 }
 std::sort(snapshot.transfers.begin(),snapshot.transfers.end(),[](const auto& a,const auto& c){return std::tie(a.source,a.target,a.provenance)<std::tie(c.source,c.target,c.provenance);});
 snapshot.transfers.erase(std::unique(snapshot.transfers.begin(),snapshot.transfers.end(),[](const auto& a,const auto& c){return std::tie(a.source,a.target,a.provenance)==std::tie(c.source,c.target,c.provenance);}),snapshot.transfers.end());
 snapshot.residualUnknown|=!snapshot.selectedFunctionsComplete||!snapshot.storageComplete||!snapshot.dataflowComplete;
 snapshot.metadata={{"requested_functions",snapshot.requestedFunctions},{"processed_functions",snapshot.processedFunctions},{"skipped_functions",snapshot.skippedFunctions},{"instructions_examined",snapshot.instructionsExamined},{"selected_functions_complete",snapshot.selectedFunctionsComplete},{"storage_complete",snapshot.storageComplete},{"dataflow_complete",snapshot.dataflowComplete},{"residual_unknown",snapshot.residualUnknown},{"limit_reached",snapshot.limitReached},{"transfer_count",snapshot.transfers.size()},{"transfer_limit",transferLimit},{"per_function_instruction_budget",instructionBudget},{"per_function_time_budget_ms",timeBudgetMs},{"capture_restricted_supported",false},{"semantic_analysis_complete",false},{"source_provenance","bounded_read_only_table"},{"functions",std::move(functions)},{"scope","Explicit selected functions only; immutable snapshot of converged guarded read-only table candidates, not all program switches."},{"deadline_policy","Cooperative checks per dataflow work item; an individual decode/table validation or final serialization may finish after its deadline."}};
 return snapshot;
}
Json analysisTools(){Json list=Json::array();auto integer=[](size_t a,size_t b){return Json{{"type","integer"},{"minimum",a},{"maximum",b}};};Json addr={{"type","string"},{"minLength",1},{"maxLength",32}},boolean={{"type","boolean"}};auto add=[&](const char* name,const char* description,Json properties,Json required,bool readOnly){list.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",properties},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readOnly},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("analyze_reachable","Analyze reachable x86/x64 instructions with bounded constant/stack dataflow, direct calls, proven fixed indirect pointers, guarded read-only tables, manual corrections, and honest unknowns. Uses original file bytes.",{{"address",addr},{"instruction_budget",integer(1,20000)},{"byte_budget",integer(1,16*1024*1024)},{"include_instructions",boolean},{"use_cache",boolean}},{"address"},true);
 add("recover_switch_table","Validate explicitly bounded absolute or signed-relative 4/8-byte table candidates. Does not assert dispatch semantics or install corrections.",{{"table",addr},{"entry_count",integer(1,256)},{"entry_size",{{"type","integer"},{"enum",{4,8}}}},{"relative_base",addr}},{"table","entry_count","entry_size"},true);
 add("discover_reachable_functions","Discover function-entry candidates from reachable executable calls, bounded by functions/instructions. Candidate ends remain unknown. Adds entries only after successful processing.",{{"addresses",{{"type","array"},{"items",addr},{"minItems",1},{"maxItems",128}}},{"function_budget",integer(1,1024)},{"instruction_budget",integer(1,200000)}},Json::array(),false);
 add("analysis_cache_stats","Inspect persistent reachable-analysis cache bounds and entry count.",Json::object(),Json::array(),true);
 add("invalidate_analysis_cache","Clear cached reachable-analysis reports for one entry or the entire open project.",{{"address",addr}},Json::array(),false);return list;
}
std::optional<Json> callAnalysisTool(Engine& e,const std::string& name,const Json& args){
 if(name=="analyze_reachable")return reachable(e,args);
 if(name=="recover_switch_table"){requireBinary(e);auto width=bounded(args,"entry_size",0,4,8);if(width!=4&&width!=8)throw std::runtime_error("entry_size must be 4 or 8");return recoverTable(e,address(args.at("table")),bounded(args,"entry_count",0,1,256),width,args.contains("relative_base")?std::optional<Address>(address(args["relative_base"])):std::nullopt);}
 if(name=="discover_reachable_functions"){requireBinary(e);return discover(e,args);}
 if(name=="analysis_cache_stats"){auto state=e.advancedState().value("analysis",Json::object());auto entries=state.value("cache",Json::array());return Json{{"entries",entries.size()},{"bytes",entries.dump().size()},{"max_entries",32},{"max_bytes",cacheLimit},{"persistent",true}};}
 if(name=="invalidate_analysis_cache"){checkCancellation(e);auto& state=e.advancedState()["analysis"];if(!state.is_object())state=Json::object();auto entries=state.value("cache",Json::array());size_t before=entries.size();if(args.contains("address")){auto target=hex(address(args["address"]));for(auto it=entries.begin();it!=entries.end();)if(it->value("entry",std::string())==target)it=entries.erase(it);else ++it;}else entries=Json::array();state["cache"]=entries;return Json{{"removed",before-entries.size()},{"remaining",entries.size()}};}
 return std::nullopt;
}
}
