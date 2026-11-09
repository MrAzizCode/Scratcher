#include "feature_auto_exceptions.hpp"
#include <algorithm>
#include <chrono>
#include <set>
#include <string_view>
#include <unordered_map>

namespace scratcher {
namespace {
using Clock=std::chrono::steady_clock;
struct Record {uint32_t begin=0,end=0,unwind=0,handler=0;uint8_t prolog=0;bool rangeValid=false,unwindValid=false;const char* reason=nullptr;};
struct Cache {const Binary* binary=nullptr;std::vector<Record> records;Json summary;};
size_t bounded(const Json& a,const char* name,size_t fallback,size_t lo,size_t hi){if(!a.contains(name))return fallback;const auto& j=a.at(name);if(!j.is_number_integer()||(!j.is_number_unsigned()&&j.get<int64_t>()<0))throw std::runtime_error(std::string(name)+" must be a nonnegative integer");auto n=j.get<uint64_t>();if(n<lo||n>hi)throw std::runtime_error(std::string(name)+" outside supported range");return static_cast<size_t>(n);}
const Binary& binary(Engine& e){if(!e.binary())throw std::runtime_error("Open a binary first");return *e.binary();}
std::optional<uint64_t> offset(const Binary& b,uint32_t rva,uint64_t n){if(rva>UINT64_MAX-b.base)return {};auto va=b.base+rva;auto s=b.section(va);if(!s)return {};auto delta=va-s->va;auto span=std::min(s->fileSize,s->memorySize);if(delta>span||n>span-delta||s->offset>UINT64_MAX-delta||!b.has(s->offset+delta,n))return {};return s->offset+delta;}
bool validRange(const Binary& b,uint32_t start,uint32_t end){return start&&end>start&&offset(b,start,uint64_t(end)-start).has_value();}
bool nonvolatile(unsigned r){return r==3||r==5||r==6||r==7||r>=12;}
const char* registerName(unsigned r){static const char* names[]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};return names[r&15];}
struct Unwind {bool valid=false;uint32_t handler=0;uint8_t prolog=0,frame=0;const char* reason=nullptr;Json detail;};
struct CachedUnwind {bool valid=false;uint32_t handler=0;uint8_t prolog=0;const char* reason=nullptr;};
Unwind parseUnwind(const Binary& b,uint32_t rva,bool details,std::set<uint32_t>& path,unsigned depth){
 Unwind out;auto fail=[&](const char* reason){out.reason=reason;return out;};
 if(depth>=16)return fail("chain_depth_limit");if(!path.insert(rva).second)return fail("cyclic_unwind_chain");
 struct Erase {std::set<uint32_t>& path;uint32_t rva;~Erase(){path.erase(rva);}} erase{path,rva};
 if(!rva||(rva&3))return fail("unaligned_or_zero_unwind_rva");auto header=offset(b,rva,4);if(!header)return fail("truncated_unwind_header");
 auto first=b.read<uint8_t>(*header);unsigned version=first&7,flags=first>>3;out.prolog=b.read<uint8_t>(*header+1);auto count=b.read<uint8_t>(*header+2),frame=b.read<uint8_t>(*header+3);out.frame=frame;unsigned frameReg=frame&15,frameOffset=frame>>4;
 if(details)out.detail={{"address",hex(b.base+rva)},{"version",version},{"flags",flags},{"prolog_size",out.prolog},{"code_slots",count},{"frame_register",frameReg?Json(registerName(frameReg)):Json(nullptr)},{"frame_offset",frameOffset*16},{"operations",Json::array()}};
 if(version!=1)return fail("unsupported_unwind_version");if(flags&~7)return fail("reserved_unwind_flags");if((flags&4)&&(flags&3))return fail("conflicting_chain_and_handler_flags");if((!frameReg&&frameOffset)||(frameReg&&!nonvolatile(frameReg)))return fail("invalid_frame_register");
 auto tail=uint64_t(4)+uint64_t((count+1)&~1)*2;if(!offset(b,rva,tail))return fail("truncated_unwind_codes");unsigned previous=256;
 for(unsigned i=0;i<count;){auto at=*header+4+i*2;auto codeOffset=b.read<uint8_t>(at),encoded=b.read<uint8_t>(at+1);unsigned op=encoded&15,info=encoded>>4,slots=1;uint64_t amount=0;const char* name=nullptr;
  if(codeOffset>out.prolog||codeOffset>previous)return fail("invalid_prolog_code_order");previous=codeOffset;
  switch(op){case 0:name="push_nonvolatile";if(!nonvolatile(info))return fail("invalid_nonvolatile_register");amount=8;break;
   case 1:name="allocate_large";if(info>1)return fail("invalid_allocate_large_info");slots=info?3:2;break;
   case 2:name="allocate_small";amount=info*8+8;break;
   // The operation-info nibble is reserved, not an operand. MSVC emits
   // nonzero values in valid records; use the header's frame fields instead.
   // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
   case 3:name="establish_frame";if(!frameReg)return fail("invalid_frame_operation");break;
   case 4:name="save_nonvolatile";slots=2;if(!nonvolatile(info))return fail("invalid_nonvolatile_register");break;
   case 5:name="save_nonvolatile_far";slots=3;if(!nonvolatile(info))return fail("invalid_nonvolatile_register");break;
   case 8:name="save_xmm128";slots=2;break;case 9:name="save_xmm128_far";slots=3;break;
   case 10:name="push_machine_frame";if(info>1)return fail("invalid_machine_frame_info");amount=info?48:40;break;
   default:return fail("unsupported_unwind_operation");}
  if(slots>count-i)return fail("truncated_unwind_operand");
  if(slots==2)amount=uint64_t(b.read<uint16_t>(at+2))*(op==8?16:8);else if(slots==3)amount=b.read<uint32_t>(at+2);
  if((op==1&&(!amount||(amount&7)))||((op==4||op==5)&&(amount&7))||((op==8||op==9)&&(amount&15)))return fail("invalid_unwind_alignment");
  if(details){Json row={{"code_offset",codeOffset},{"operation",name},{"operation_code",op},{"info",info},{"slots",slots}};if(op==0||op==4||op==5)row["register"]=registerName(info);if(op==8||op==9)row["register"]="xmm"+std::to_string(info);if(op!=3)row["byte_amount"]=amount;else if(info)row["reserved_info_ignored"]=true;out.detail["operations"].push_back(std::move(row));}i+=slots;
 }
 if((flags&4)!=0){if(tail>UINT32_MAX-rva)return fail("unwind_tail_overflow");auto chain=offset(b,rva+static_cast<uint32_t>(tail),12);if(!chain)return fail("truncated_unwind_chain");auto begin=b.read<uint32_t>(*chain),end=b.read<uint32_t>(*chain+4),next=b.read<uint32_t>(*chain+8);if(!validRange(b,begin,end))return fail("invalid_chained_function_range");auto child=parseUnwind(b,next,details,path,depth+1);if(!child.valid){out.reason=child.reason;return out;}if(child.prolog>uint64_t(end)-begin)return fail("chained_prolog_exceeds_function");out.handler=child.handler;if(details)out.detail["chain"]={{"begin",hex(b.base+begin)},{"end",hex(b.base+end)},{"unwind",child.detail}};
 }else if(flags&3){if(tail>UINT32_MAX-rva)return fail("unwind_tail_overflow");auto at=offset(b,rva+static_cast<uint32_t>(tail),4);if(!at)return fail("truncated_handler_rva");out.handler=b.read<uint32_t>(*at);if(!out.handler||!offset(b,out.handler,1))return fail("unmapped_exception_handler");if(details){out.detail["handler"]={{"address",hex(b.base+out.handler)},{"exception_handler",bool(flags&1)},{"termination_handler",bool(flags&2)},{"declared_executable",b.executable(b.base+out.handler)}};if(tail+4<=UINT32_MAX-rva)out.detail["language_data_address"]=hex(b.base+rva+tail+4);out.detail["language_specific_data_decoded"]=false;}}
 out.valid=true;return out;
}
std::shared_ptr<Cache> cached(Engine& e){auto it=e.runtimeSlots().find("auto_exceptions");if(it==e.runtimeSlots().end())return {};auto c=std::static_pointer_cast<Cache>(it->second);return c&&c->binary==e.binary()?c:std::shared_ptr<Cache>();}
Json page(Engine& e,const Json& a){const auto& b=binary(e);if(e.cancelled())throw std::runtime_error("Operation cancelled");auto c=cached(e);if(!c){analyzeExceptionMetadata(e);c=cached(e);}auto start=bounded(a,"offset",0,0,1000000),limit=bounded(a,"limit",100,1,1000);std::optional<Address> query;if(a.contains("address"))query=address(a.at("address"));Json rows=Json::array();size_t matched=0;
 for(size_t index=0;index<c->records.size();++index){const auto& r=c->records[index];if(query&&(*query<b.base+r.begin||*query>=b.base+r.end))continue;if(matched++<start||rows.size()>=limit)continue;Json row={{"index",index},{"begin",hex(b.base+r.begin)},{"end",hex(b.base+r.end)},{"unwind_address",hex(b.base+r.unwind)},{"provenance","PE exception directory RUNTIME_FUNCTION"},{"range_valid",r.rangeValid},{"unwind_valid",r.unwindValid},{"declared_executable",b.executable(b.base+r.begin)},{"callable_candidate",r.rangeValid&&r.unwindValid}};if(r.reason){row["reason"]=r.reason;row["classification"]=std::string_view(r.reason).starts_with("unsupported_")?"unsupported":"malformed";}if(r.rangeValid){std::set<uint32_t> path;auto u=parseUnwind(b,r.unwind,true,path,0);row["unwind"]=u.detail;}rows.push_back(std::move(row));}
 return {{"items",rows},{"total",matched},{"offset",start},{"limit",limit},{"has_more",matched>start+rows.size()},{"summary",c->summary}};
}
Json definition(const char* name,const char* description,Json props){return {{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",props},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",true},{"destructiveHint",false},{"idempotentHint",true},{"openWorldHint",false}}}};}
}
Json analyzeExceptionMetadata(Engine& e,const Json& a){const auto& b=binary(e);if(e.cancelled())throw std::runtime_error("Operation cancelled");auto budget=bounded(a,"record_budget",1000000,1,1000000),ms=bounded(a,"time_budget_ms",10000,1,600000);auto memoryBudget=bounded(a,"memory_budget_mb",128,1,512)*size_t(1024*1024);auto started=Clock::now(),deadline=started+std::chrono::milliseconds(ms);e.runtimeSlots().erase("auto_exceptions");auto c=std::make_shared<Cache>();c->binary=&b;size_t peakEstimate=sizeof(Cache)+65536;
 c->summary={{"status","absent"},{"directory_present",false},{"records_available",0},{"records_examined",0},{"valid_runtime_ranges",0},{"valid_unwind_records",0},{"handler_records",0},{"invalid_records",0},{"unsupported_records",0},{"zero_padding_records",0},{"complete",true},{"semantic_analysis_complete",false},{"language_specific_data_decoded",false},{"supported","AMD64 PE version 1 unwind operations and chained records"},{"issues",Json::array()}};
 auto finish=[&](){c->summary["elapsed_ms"]=std::chrono::duration<double,std::milli>(Clock::now()-started).count();c->summary["cache_bytes_estimate"]=c->records.capacity()*sizeof(Record)+sizeof(Cache)+65536;c->summary["memory_peak_bytes_estimate"]=peakEstimate;c->summary["memory_budget_bytes"]=memoryBudget;c->summary["memory_accounting"]="Conservative module allocation estimate, including retained rows, temporary unwind index, bucket reallocation and fixed summary/parse slack; excludes binary mapping and caller results";e.runtimeSlots()["auto_exceptions"]=c;return c->summary;};
 if(b.format!="PE"){c->summary["status"]="unsupported_format";return finish();}auto pe=b.read<uint32_t>(0x3c);auto machine=b.read<uint16_t>(uint64_t(pe)+4);if(machine!=0x8664){c->summary["status"]="unsupported_architecture";return finish();}uint64_t opt=uint64_t(pe)+24;auto optSize=b.read<uint16_t>(uint64_t(pe)+20);if(optSize<144||b.read<uint32_t>(opt+108)<=3)return finish();auto rva=b.read<uint32_t>(opt+112+3*8),size=b.read<uint32_t>(opt+116+3*8);if(!rva&&!size)return finish();c->summary["directory_present"]=true;c->summary["directory_address"]=hex(b.base+rva);c->summary["directory_size"]=size;
 auto table=offset(b,rva,size);if(!rva||!size||size%12||!table){c->summary["status"]="invalid_directory";c->summary["complete"]=false;c->summary["issues"].push_back("Exception directory is truncated, not file backed, or its size is not a multiple of 12");return finish();}
 size_t available=size/12,take=std::min(available,budget);c->summary["records_available"]=available;std::unordered_map<uint32_t,CachedUnwind> unwindCache;unwindCache.max_load_factor(1);size_t ranges=0,valid=0,handlers=0,invalid=0,unsupported=0,zero=0;bool ordered=true,cacheComplete=true;uint32_t last=0;
 constexpr size_t nodeEstimate=sizeof(std::pair<const uint32_t,CachedUnwind>)+4*sizeof(void*),fixedSlack=sizeof(Cache)+65536;
 auto memory=[&](){return fixedSlack+c->records.capacity()*sizeof(Record)+unwindCache.size()*nodeEstimate+unwindCache.bucket_count()*2*sizeof(void*);};
 for(size_t i=0;i<take;++i){if((i&255)==0){if(e.cancelled())throw std::runtime_error("Operation cancelled");if(Clock::now()>=deadline){c->summary["stop_reason"]="time_budget";break;}}
  auto at=*table+i*12;Record r;r.begin=b.read<uint32_t>(at);r.end=b.read<uint32_t>(at+4);r.unwind=b.read<uint32_t>(at+8);if(!r.begin&&!r.end&&!r.unwind){++zero;c->summary["records_examined"]=i+1;continue;}
  if(c->records.size()==c->records.capacity()){auto wanted=std::min(take,std::max<size_t>(4096,c->records.capacity()*2));auto used=memory();auto room=memoryBudget>used?(memoryBudget-used)/sizeof(Record):0;wanted=std::min(wanted,room);if(wanted<=c->records.size()){c->summary["stop_reason"]="memory_budget";break;}peakEstimate=std::max(peakEstimate,used+wanted*sizeof(Record));c->records.reserve(wanted);}
  c->summary["records_examined"]=i+1;if(r.begin<last)ordered=false;last=r.begin;r.rangeValid=validRange(b,r.begin,r.end);
  if(!r.rangeValid)r.reason="invalid_runtime_function_range";else {++ranges;CachedUnwind result;auto it=unwindCache.find(r.unwind);if(it!=unwindCache.end())result=it->second;else {std::set<uint32_t> path;auto u=parseUnwind(b,r.unwind,false,path,0);result={u.valid,u.handler,u.prolog,u.reason};
    // This index is optional acceleration. Stop caching new keys before its
    // allocation budget grows; every remaining record is still parsed.
    auto bucketGrowth=unwindCache.size()+1>unwindCache.bucket_count()?std::max<size_t>(16,unwindCache.bucket_count()*4)*2*sizeof(void*):0;auto estimated=memory()+nodeEstimate+bucketGrowth;
    if(unwindCache.size()<65536&&estimated<=memoryBudget){peakEstimate=std::max(peakEstimate,estimated);unwindCache.emplace(r.unwind,result);}else cacheComplete=false;}
   r.prolog=result.prolog;r.handler=result.handler;r.unwindValid=result.valid;r.reason=result.reason;if(r.unwindValid&&r.prolog>uint64_t(r.end)-r.begin){r.unwindValid=false;r.reason="prolog_exceeds_runtime_range";}}
  if(r.rangeValid&&r.unwindValid){++valid;if(r.handler)++handlers;}else {bool unsupportedRecord=r.reason&&std::string_view(r.reason).starts_with("unsupported_");if(unsupportedRecord)++unsupported;else ++invalid;if(c->summary["issues"].size()<64)c->summary["issues"].push_back({{"index",i},{"begin",hex(b.base+r.begin)},{"reason",r.reason},{"classification",unsupportedRecord?"unsupported":"malformed"}});}c->records.push_back(std::move(r));peakEstimate=std::max(peakEstimate,memory());
 }
 auto examined=c->summary["records_examined"].get<size_t>();bool complete=examined==available;c->summary["complete"]=complete;c->summary["status"]=complete?"parsed":"partial";if(!complete&&!c->summary.contains("stop_reason"))c->summary["stop_reason"]="record_budget";c->summary["valid_runtime_ranges"]=ranges;c->summary["valid_unwind_records"]=valid;c->summary["handler_records"]=handlers;c->summary["invalid_records"]=invalid;c->summary["unsupported_records"]=unsupported;c->summary["zero_padding_records"]=zero;c->summary["directory_sorted"]=ordered;c->summary["cached_unwind_addresses"]=unwindCache.size();c->summary["unwind_cache_complete"]=cacheComplete;c->summary["records_retained"]=c->records.size();return finish();
}
std::vector<Function> exceptionCallableRanges(Engine& e){const auto& b=binary(e);auto c=cached(e);if(!c){analyzeExceptionMetadata(e);c=cached(e);}std::vector<Function> out;out.reserve(c->records.size());for(const auto& r:c->records)if(r.rangeValid&&r.unwindValid)out.push_back({b.base+r.begin,b.base+r.end,"sub_"+hex(b.base+r.begin).substr(2),"PE runtime function metadata"});return out;}
Json autoExceptionTools(){Json n={{"type","integer"},{"minimum",1},{"maximum",1000000}},t={{"type","integer"},{"minimum",1},{"maximum",600000}};return Json::array({definition("analyze_exceptions","Validate AMD64 PE exception function bounds, version 1 unwind operations, chains and handlers within explicit record, time and memory budgets. Reserved frame-operation info bits are ignored. Language-specific EH3/EH4 data remains undecoded.",{{"record_budget",n},{"time_budget_ms",t},{"memory_budget_mb",{{"type","integer"},{"minimum",1},{"maximum",512}}}}),definition("get_exception_info","Page validated runtime function and unwind evidence, optionally containing an address. Metadata does not prove decoded machine code or full C++ exception semantics.",{{"offset",{{"type","integer"},{"minimum",0},{"maximum",1000000}}},{"limit",{{"type","integer"},{"minimum",1},{"maximum",1000}}},{"address",{{"type","string"},{"format","address"}}}})});}
std::optional<Json> callAutoExceptionTool(Engine& e,const std::string& name,const Json& a){if(name=="analyze_exceptions")return analyzeExceptionMetadata(e,a);if(name=="get_exception_info")return page(e,a);return std::nullopt;}
}
