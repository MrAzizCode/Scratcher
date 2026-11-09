#include "feature_auto_code.hpp"
#include "feature_flow_constants.hpp"
#include "feature_advanced_analysis.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <thread>
#include <tuple>
#include <numeric>
#include <array>
#include <unordered_map>
#include <unordered_set>

namespace scratcher {
namespace {
using Clock=std::chrono::steady_clock;
constexpr const char* slot="auto.code_paths.v1";
struct Span {Address begin,end;};
struct Record {Address entry=0,boundary=0,observedBegin=0,observedEnd=0;bool controlFlow=false,provenEnd=false;uint32_t instructions=0,bytes=0,invalid=0,returns=0,indirect=0,resolvedIndirect=0,resolvedRegister=0,resolvedSwitch=0,externalEdges=0,overlap=0;bool limited=false,boundaryHit=false;};
enum class StopReason : uint8_t {InvalidDecode,OperandDecode,Unavailable,IndirectCall,IndirectJump,ResidualCall,ResidualJump,ScopeBoundary,TargetOutsideScope,Overlap,FunctionLimit,TimeLimit,InstructionLimit,ByteLimit,Terminator};
const char* stopReasonName(StopReason reason){switch(reason){case StopReason::InvalidDecode:return "invalid_decode";case StopReason::OperandDecode:return "operand_decode_failure";case StopReason::Unavailable:return "unavailable_bytes";case StopReason::IndirectCall:return "unresolved_indirect_call";case StopReason::IndirectJump:return "unresolved_indirect_jump";case StopReason::ResidualCall:return "residual_indirect_call";case StopReason::ResidualJump:return "residual_indirect_jump";case StopReason::ScopeBoundary:return "scope_boundary";case StopReason::TargetOutsideScope:return "target_outside_scope";case StopReason::Overlap:return "overlap";case StopReason::FunctionLimit:return "per_function_limit";case StopReason::TimeLimit:return "time_budget";case StopReason::InstructionLimit:return "instruction_budget";case StopReason::ByteLimit:return "byte_budget";case StopReason::Terminator:return "explicit_terminator";}return "unknown";}
struct Stop {Address seed=0,address=0,pathStart=0,boundary=0,target=0;uint32_t instructions=0,pathInstructions=0;StopReason reason=StopReason::InvalidDecode;uint8_t byteCount=0;bool hasTarget=false;std::array<uint8_t,15> bytes{};};
static_assert(sizeof(Stop)<=96,"Stop evidence must remain compact and separately bounded");
struct Cache {uint64_t key=0,transferFingerprint=0;Json summary;std::vector<Record> records;std::vector<Span> spans;std::vector<CodeAnalysisTransfer> transfers;std::vector<Stop> stops;};
size_t integer(const Json& a,const char* k,size_t fallback,size_t low,size_t high){if(!a.contains(k))return fallback;const auto& j=a.at(k);if(!j.is_number_integer()||(!j.is_number_unsigned()&&j.get<int64_t>()<0))throw std::runtime_error(std::string(k)+" must be a nonnegative integer");auto v=j.get<uint64_t>();if(v<low||v>high)throw std::runtime_error(std::string(k)+" is outside its supported range");return static_cast<size_t>(v);}
uint64_t hashBytes(uint64_t h,const void* p,size_t size){auto b=static_cast<const uint8_t*>(p);for(size_t i=0;i<size;++i){h^=b[i];h*=1099511628211ULL;}return h;}
uint64_t cacheKey(const Engine& e,const Json& options){const auto& b=*e.binary();uint64_t h=14695981039346656037ULL;auto hash=[&](auto v){h=hashBytes(h,&v,sizeof(v));};hash(b.size());hash(b.bits);hash(b.entry);for(const auto& s:b.sections){hash(s.va);hash(s.fileSize);hash(s.memorySize);hash(s.offset);hash(s.executable);hash(s.writable);}for(const auto& range:b.analysisRanges){hash(range.first);hash(range.second);}for(const auto& i:b.imports)hash(i.va);for(const auto& f:b.functions){hash(f.va);hash(f.end);h=hashBytes(h,f.source.data(),f.source.size());}auto manual=e.advancedState().value("manual",Json::object()).dump();h=hashBytes(h,manual.data(),manual.size());auto text=options.dump();return hashBytes(h,text.data(),text.size());}
bool inData(Address va,const std::vector<Span>& ranges){auto i=std::upper_bound(ranges.begin(),ranges.end(),va,[](Address at,const Span& s){return at<s.begin;});return i!=ranges.begin()&&va<std::prev(i)->end;}
void normalizeSpans(std::vector<Span>& spans){std::sort(spans.begin(),spans.end(),[](const Span& a,const Span& b){return a.begin<b.begin||(a.begin==b.begin&&a.end<b.end);});size_t count=0;for(const auto& span:spans){if(span.end<=span.begin)continue;if(count&&span.begin<=spans[count-1].end)spans[count-1].end=std::max(spans[count-1].end,span.end);else spans[count++]=span;}spans.resize(count);}
const uint8_t* fileCode(const Binary& b,Address at,size_t& available){available=0;if(!b.analysisCode(at))return nullptr;auto s=b.section(at);if(!s)return nullptr;auto delta=at-s->va,extent=std::min(s->fileSize,s->memorySize);if(delta>=extent||s->offset>UINT64_MAX-delta)return nullptr;available=static_cast<size_t>(std::min<uint64_t>(15,extent-delta));return b.has(s->offset+delta,available)?b.bytes()+s->offset+delta:nullptr;}
bool reserve(std::atomic_size_t& count,size_t amount,size_t maximum){auto old=count.load(std::memory_order_relaxed);while(old<=maximum&&amount<=maximum-old){if(count.compare_exchange_weak(old,old+amount,std::memory_order_relaxed))return true;}return false;}
// Candidate scope is the union of original executable and validated metadata regions,
// clipped to immutable file-backed bytes. It is independent of recovered coverage.
std::vector<Span> candidateScope(const Binary& b){
 std::vector<Span> ranges;
 for(const auto& s:b.sections){
  auto extent=std::min(s.fileSize,s.memorySize);
  if(s.offset>b.size()||s.va>UINT64_MAX-extent)continue;
  extent=std::min(extent,b.size()-s.offset);
  if(s.executable&&extent)ranges.push_back({s.va,s.va+extent});
  for(const auto& r:b.analysisRanges){auto begin=std::max(s.va,r.first),end=std::min(s.va+extent,r.second);if(begin<end)ranges.push_back({begin,end});}
 }
 normalizeSpans(ranges);return ranges;
}
Address candidateEnd(Address at,const std::vector<Span>& ranges){
 auto i=std::upper_bound(ranges.begin(),ranges.end(),at,[](Address va,const Span& s){return va<s.begin;});
 return i!=ranges.begin()&&at<std::prev(i)->end?std::prev(i)->end:0;
}
Address scanAddress(const Json& value){
 if(!value.is_string())throw std::runtime_error("scan_ranges addresses must be hexadecimal strings");
 const auto text=value.get<std::string>();if(text.size()<3||text.size()>18||text[0]!='0'||(text[1]!='x'&&text[1]!='X'))throw std::runtime_error("scan_ranges addresses must use 0x hexadecimal notation");
 Address result=0;for(size_t i=2;i<text.size();++i){auto c=text[i];unsigned digit;if(c>='0'&&c<='9')digit=c-'0';else if(c>='a'&&c<='f')digit=c-'a'+10;else if(c>='A'&&c<='F')digit=c-'A'+10;else throw std::runtime_error("scan_ranges contains an invalid hexadecimal address");result=(result<<4)|digit;}return result;
}
// A capture allowlist restricts decoding, never the original coverage denominator.
// Empty lists intentionally supply no readable code evidence. Ranges outside the
// original candidate scope are clipped away rather than promoting new code.
std::vector<Span> scanScope(const Json& args,const std::vector<Span>& candidates){
 if(!args.contains("scan_ranges"))return candidates;
 const auto& input=args.at("scan_ranges");if(!input.is_array()||input.size()>4096)throw std::runtime_error("scan_ranges must be an array containing at most 4096 ranges");
 std::vector<Span> requested;requested.reserve(input.size());for(const auto& row:input){if(!row.is_object()||row.size()!=2||!row.contains("start")||!row.contains("end"))throw std::runtime_error("Each scan_ranges item must contain exactly start and end");auto begin=scanAddress(row.at("start")),end=scanAddress(row.at("end"));if(begin>=end)throw std::runtime_error("scan_ranges start must precede its exclusive end");requested.push_back({begin,end});}normalizeSpans(requested);
 std::vector<Span> clipped;size_t a=0,c=0;while(a<requested.size()&&c<candidates.size()){auto begin=std::max(requested[a].begin,candidates[c].begin),end=std::min(requested[a].end,candidates[c].end);if(begin<end)clipped.push_back({begin,end});if(requested[a].end<candidates[c].end)++a;else ++c;}normalizeSpans(clipped);return clipped;
}
bool firstScanDecodes(const Binary& b,Address at,const std::vector<Span>& scope,const std::vector<Span>& manualData){size_t n=0;auto end=candidateEnd(at,scope);if(!end)return false;auto p=fileCode(b,at,n);if(!p)return false;n=static_cast<size_t>(std::min<uint64_t>(n,end-at));ZydisDecoder d{};ZydisDecoderInit(&d,b.bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32,b.bits==64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32);ZydisDecoderContext c{};ZydisDecodedInstruction i{};if(!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&d,&c,p,n,&i)))return false;for(unsigned offset=0;offset<i.length;++offset)if(inData(at+offset,manualData))return false;return true;}
std::optional<uint64_t> readonlyPointer(const Binary& b,Address slotAddress,size_t width,const std::unordered_set<Address>& importSlots,const std::vector<Span>* readableScope){
 if((width!=4&&width!=8)||slotAddress>UINT64_MAX-width)return std::nullopt;
 // Reject overlap with the entire runtime slot, including unaligned reads
 // beginning before or inside it. At most fifteen hash lookups are needed.
 if(!importSlots.empty()){
  for(size_t byte=0;byte<width;++byte)if(importSlots.contains(slotAddress+byte))return std::nullopt;
  for(size_t back=1;back<static_cast<size_t>(b.bits/8)&&slotAddress>=back;++back)if(importSlots.contains(slotAddress-back))return std::nullopt;
 }
 if(readableScope){auto end=candidateEnd(slotAddress,*readableScope);if(!end||width>end-slotAddress)return std::nullopt;}
 auto section=b.section(slotAddress);if(!section||section->writable)return std::nullopt;
 auto delta=slotAddress-section->va,extent=std::min(section->fileSize,section->memorySize);
 if(delta>extent||width>extent-delta||section->offset>UINT64_MAX-delta||!b.has(section->offset+delta,width))return std::nullopt;
 return width==8?b.read<uint64_t>(section->offset+delta):static_cast<uint64_t>(b.read<uint32_t>(section->offset+delta));
}
Json transferJson(const CodeAnalysisTransfer& row){return {{"source",hex(row.source)},{"target",hex(row.target)},{"call",row.call},{"provenance",row.provenance},{"readonly_source_slot",row.readonlySlot?Json(hex(*row.readonlySlot)):Json(nullptr)},{"path_local",row.pathLocal},{"residual_unknown",row.residualUnknown},{"semantic_analysis_complete",false}};}
Json stopJson(const Stop& row){static constexpr char digits[]="0123456789abcdef";std::string bytes;bytes.reserve(row.byteCount*2);for(size_t n=0;n<row.byteCount;++n){bytes.push_back(digits[row.bytes[n]>>4]);bytes.push_back(digits[row.bytes[n]&15]);}return {{"seed",hex(row.seed)},{"address",hex(row.address)},{"path_start",hex(row.pathStart)},{"traversal_boundary",hex(row.boundary)},{"target",row.hasTarget?Json(hex(row.target)):Json(nullptr)},{"reason",stopReasonName(row.reason)},{"instructions_before_stop",row.instructions},{"path_instructions_before_stop",row.pathInstructions},{"first_instruction",row.instructions==0},{"bytes_supplied_to_decoder",row.byteCount},{"bytes",bytes},{"byte_source","original_file"},{"semantic_analysis_complete",false}};}

Json recordJson(const Record& r){return {{"address",hex(r.entry)},{"traversal_boundary",hex(r.boundary)},{"boundary_policy",r.controlFlow?"control_flow":"next_seed"},{"indexed_end_enforced",r.provenEnd},{"observed_reachable_begin",hex(r.observedBegin)},{"observed_reachable_end",hex(r.observedEnd)},{"instructions",r.instructions},{"reachable_bytes",r.bytes},{"invalid_stops",r.invalid},{"returns",r.returns},{"unresolved_indirect_edges",r.indirect},{"resolved_readonly_indirect_edges",r.resolvedIndirect},{"resolved_register_indirect_edges",r.resolvedRegister},{"resolved_switch_dispatches",r.resolvedSwitch},{"edges_outside_boundary",r.externalEdges},{"overlapping_targets",r.overlap},{"limit_reached",r.limited},{"boundary_reached",r.boundaryHit},{"traversal_closed",r.instructions>0&&!r.invalid&&!r.indirect&&!r.externalEdges&&!r.overlap&&!r.limited&&!r.boundaryHit},{"semantic_analysis_complete",false}};}
Json analyze(Engine& e,const Json& args){if(!e.binary())throw std::runtime_error("Open a binary first");if(e.cancelled())throw std::runtime_error("Operation cancelled");auto& b=*e.editableBinary();if(!b.language.starts_with("x86:"))throw std::runtime_error("Code-path recovery currently supports x86 and x64");auto started=Clock::now();
 const size_t maxInstructions=integer(args,"instruction_budget",20000000,1,100000000),maxBytes=integer(args,"byte_budget",128*1024*1024,1,512*1024*1024),maxTime=integer(args,"time_budget_ms",30000,1,300000),perFunction=integer(args,"per_function_instruction_budget",4096,1,100000),maxFunctions=integer(args,"function_budget",1000000,1,1000000),maxSpans=integer(args,"coverage_span_budget",1000000,1,4000000),workerCount=integer(args,"workers",std::min<size_t>(8,std::max(1u,std::thread::hardware_concurrency())),1,32),maxRounds=integer(args,"discovery_rounds",3,1,32),transferLimit=integer(args,"transfer_limit",262144,1,1000000),stopLimit=integer(args,"stop_limit",0,0,1000000),switchInstructions=integer(args,"switch_instruction_budget",4096,1,20000),switchTime=integer(args,"switch_time_budget_ms",100,1,5000),switchLimit=integer(args,"switch_transfer_limit",4096,1,1000000);
 auto boundaryPolicy=args.value("boundary_policy",std::string("next_seed"));if(boundaryPolicy!="next_seed"&&boundaryPolicy!="control_flow")throw std::runtime_error("boundary_policy must be next_seed or control_flow");const bool controlFlow=boundaryPolicy=="control_flow";
 auto candidates=candidateScope(b);uint64_t candidateBytes=0;for(const auto& range:candidates)candidateBytes+=range.end-range.begin;const bool restricted=args.contains("scan_ranges");auto scope=scanScope(args,candidates);uint64_t scanBytes=0;for(const auto& range:scope)scanBytes+=range.end-range.begin;
 std::vector<Address> switchEntries;
 if(args.contains("switch_functions")){
  const auto& values=args.at("switch_functions");if(!values.is_array()||values.size()>256)throw std::runtime_error("switch_functions must contain at most 256 explicit indexed addresses");
  for(const auto& value:values)switchEntries.push_back(scanAddress(value));
  std::sort(switchEntries.begin(),switchEntries.end());switchEntries.erase(std::unique(switchEntries.begin(),switchEntries.end()),switchEntries.end());
 }
 if(!switchEntries.empty()&&(!controlFlow||restricted))throw std::runtime_error("Selected switch preparation requires control_flow and unrestricted original-file evidence");
 auto deadline=started+std::chrono::milliseconds(maxTime);
 Json options={{"boundary_policy",boundaryPolicy},{"instruction_budget",maxInstructions},{"byte_budget",maxBytes},{"time_budget_ms",maxTime},{"per_function_instruction_budget",perFunction},{"function_budget",maxFunctions},{"coverage_span_budget",maxSpans},{"workers",workerCount},{"discovery_rounds",maxRounds},{"transfer_limit",transferLimit},{"stop_limit",stopLimit},{"switch_instruction_budget",switchInstructions},{"switch_time_budget_ms",switchTime},{"switch_transfer_limit",switchLimit},{"switch_functions",Json::array()}};for(auto entry:switchEntries)options["switch_functions"].push_back(hex(entry));if(restricted){options["scan_ranges"]=Json::array();for(const auto& range:scope)options["scan_ranges"].push_back({{"start",hex(range.begin)},{"end",hex(range.end)}});}auto key=cacheKey(e,options);auto found=e.runtimeSlots().find(slot);if(args.value("use_cache",true)&&found!=e.runtimeSlots().end()){auto c=std::static_pointer_cast<Cache>(found->second);if(c->key==key){auto r=c->summary;r["cache_hit"]=true;r["elapsed_ms"]=std::chrono::duration<double,std::milli>(Clock::now()-started).count();return r;}}
 std::vector<Span> manualData;std::unordered_set<Address> deleted;const auto manual=e.advancedState().value("manual",Json::object());for(const auto& row:manual.value("ranges",Json::array()))if(row.value("kind",std::string())=="data")manualData.push_back({address(row.at("start")),address(row.at("end"))});normalizeSpans(manualData);for(const auto& row:manual.value("deleted_functions",Json::array()))deleted.insert(address(row));
 std::unordered_set<Address> importSlots;for(const auto& imp:b.imports)importSlots.insert(imp.va);
 std::unordered_map<Address,std::vector<Address>> manualSwitches;if(controlFlow)for(const auto& row:manual.value("switches",Json::array())){auto& targets=manualSwitches[address(row.at("address"))];for(const auto& target:row.at("targets"))targets.push_back(address(target));}
 std::vector<Address> seeds;seeds.reserve(std::min(maxFunctions,b.functions.size()+1));for(const auto& f:b.functions)if(candidateEnd(f.va,scope)&&!deleted.contains(f.va)&&!inData(f.va,manualData))seeds.push_back(f.va);if(candidateEnd(b.entry,scope)&&!deleted.contains(b.entry)&&!inData(b.entry,manualData))seeds.push_back(b.entry);std::sort(seeds.begin(),seeds.end());seeds.erase(std::unique(seeds.begin(),seeds.end()),seeds.end());const size_t inputSeeds=seeds.size();auto originalBoundaries=seeds;bool seedLimited=seeds.size()>maxFunctions;if(seedLimited)seeds.resize(maxFunctions);std::unordered_set<Address> known(seeds.begin(),seeds.end());std::unordered_map<Address,Address> indexedEnds;for(const auto& f:b.functions)if(f.end>f.va)indexedEnds.emplace(f.va,f.end);
 // Prepare selected entries serially before worker reads. The guarded proof is
 // tied to its entry; a different seed reaching the dispatch cannot borrow it.
 std::unordered_map<Address,std::unordered_map<Address,std::vector<Address>>> switchTargets;
 Json switchReports=Json::array();size_t switchRows=0,switchProcessed=0;bool switchPreparationTimedOut=false,switchStorageComplete=true,switchSelectionComplete=true;
 for(auto entry:switchEntries){
  if(e.cancelled())throw std::runtime_error("Operation cancelled");
  auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
  if(remaining<=0){switchPreparationTimedOut=true;switchSelectionComplete=false;break;}
  if(switchRows>=switchLimit){switchSelectionComplete=false;switchStorageComplete=false;break;}
  auto prepared=prepareBoundedSwitchSnapshot(e,{entry},switchInstructions,std::min<size_t>(switchTime,static_cast<size_t>(remaining)),switchLimit-switchRows);
  switchRows+=prepared.transfers.size();switchProcessed+=prepared.processedFunctions;switchStorageComplete&=prepared.storageComplete;switchSelectionComplete&=prepared.selectedFunctionsComplete;
  for(const auto& transfer:prepared.transfers)switchTargets[entry][transfer.source].push_back(transfer.target);
  switchReports.push_back(std::move(prepared.metadata));
 }
 Json switchPreparation={{"enabled",!switchEntries.empty()},{"requested_functions",switchEntries.size()},{"processed_functions",switchProcessed},{"transfer_count",switchRows},{"storage_complete",switchStorageComplete},{"selected_functions_complete",switchSelectionComplete},{"time_budget_exhausted",switchPreparationTimedOut},{"functions",std::move(switchReports)},{"scope","Explicit selected entry contexts; guarded readonly table candidates retain residual unknown in bulk traversal"},{"capture_restricted_supported",false},{"semantic_analysis_complete",false}};
 auto cache=std::make_shared<Cache>();std::atomic_size_t instructions=0,bytes=0,spanCount=0,transferCount=0,stopEvents=0;std::atomic_bool instructionStop=false,byteStop=false,timeStop=switchPreparationTimedOut,coverageStop=false,transferStop=false;size_t rounds=0;std::vector<Address> additions;std::vector<Address> allBoundaries=std::move(originalBoundaries);size_t skippedSeeds=0;
 while(!seeds.empty()&&rounds<maxRounds&&!instructionStop&&!byteStop&&!timeStop){++rounds;const size_t activeWorkers=std::min(workerCount,seeds.size());std::atomic_size_t next=0;struct WorkerResult{std::vector<Record> rows;std::vector<Span> spans;std::vector<Address> calls;std::vector<CodeAnalysisTransfer> transfers;std::vector<Stop> stops;size_t skipped=0;};std::vector<WorkerResult> results(activeWorkers);std::vector<std::future<void>> tasks;
 for(size_t w=0;w<activeWorkers;++w)tasks.push_back(std::async(std::launch::async,[&,w]{
  auto& out=results[w];ZydisDecoder decoder{};
  ZydisDecoderInit(&decoder,b.bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32,b.bits==64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32);
  std::unordered_map<Address,uint8_t> seen;seen.reserve(std::min<size_t>(perFunction,4096));
  std::vector<Address> pending;pending.reserve(32);FlowConstants constants(b.bits);std::unordered_set<Address> traceLeaders;
  FlowPointerReader readPointer=[&](Address pointerSlot,size_t width){return readonlyPointer(b,pointerSlot,width,importSlots,restricted?&scope:nullptr);};
  for(;;){
   if(instructionStop||byteStop||timeStop||e.cancelled())break;
   if(Clock::now()>=deadline){timeStop=true;break;}
   auto index=next.fetch_add(1);if(index>=seeds.size())break;
   auto at=seeds[index];auto section=b.section(at);if(!section){++out.skipped;continue;}
   auto extent=std::min(section->fileSize,section->memorySize);if(at-section->va>=extent||extent>UINT64_MAX-section->va){++out.skipped;continue;}
   Record r;r.entry=at;r.observedBegin=at;r.observedEnd=at;r.controlFlow=controlFlow;r.boundary=section->va+extent;
   auto boundary=std::upper_bound(allBoundaries.begin(),allBoundaries.end(),at);if(!controlFlow&&boundary!=allBoundaries.end())r.boundary=std::min(r.boundary,*boundary);
   auto explicitEnd=indexedEnds.find(at);if(explicitEnd!=indexedEnds.end()){r.provenEnd=true;r.boundary=controlFlow?explicitEnd->second:std::min(r.boundary,explicitEnd->second);}
   auto allowed=[&](Address pc){if(!candidateEnd(pc,scope)||inData(pc,manualData))return false;if(!controlFlow)return pc>=at&&pc<r.boundary;return !r.provenEnd||(pc>=at&&pc<r.boundary);};
   auto stop=[&](StopReason reason,Address pc,Address pathStart,uint32_t pathCount,uint32_t seedCount,const uint8_t* data=nullptr,size_t available=0,std::optional<Address> target={}){
    if(!stopLimit)return; // Normal recovery retains no diagnostic corpus or counter traffic.
    auto event=stopEvents.fetch_add(1,std::memory_order_relaxed);if(event>=stopLimit)return;
    Stop row;row.seed=at;row.address=pc;row.pathStart=pathStart;row.boundary=r.boundary;row.target=target.value_or(0);row.hasTarget=bool(target);
    row.instructions=seedCount;row.pathInstructions=pathCount;row.reason=reason;row.byteCount=data?static_cast<uint8_t>(std::min<size_t>(15,available)):0;
    if(row.byteCount)std::copy_n(data,row.byteCount,row.bytes.begin());out.stops.push_back(row);
   };
   seen.clear();pending.clear();pending.push_back(at);traceLeaders.clear();
   auto addSpan=[&](Address begin,Address end){if(begin>=end)return;if(!out.spans.empty()&&out.spans.back().end==begin){out.spans.back().end=end;return;}if(reserve(spanCount,1,maxSpans))out.spans.push_back({begin,end});else coverageStop=true;};
   while(!pending.empty()&&!r.limited){
    Address pc=pending.back();pending.pop_back();constants.reset();bool overlapped=false;
    for(Address back=1;back<15&&pc>=back;++back){auto v=seen.find(pc-back);if(v!=seen.end()&&v->second>back){overlapped=true;break;}}
    if(overlapped){++r.overlap;stop(StopReason::Overlap,pc,pc,0,r.instructions);continue;}
    Address runBegin=pc,runEnd=pc;uint32_t pathInstructions=0;
    for(;;){
     if(controlFlow&&(traceLeaders.contains(pc)||std::binary_search(allBoundaries.begin(),allBoundaries.end(),pc)))constants.reset();
     if(!allowed(pc)){r.boundaryHit=true;stop(StopReason::ScopeBoundary,pc,runBegin,pathInstructions,r.instructions);break;}
     if(seen.contains(pc))break;
     if(r.instructions>=perFunction){r.limited=true;stop(StopReason::FunctionLimit,pc,runBegin,pathInstructions,r.instructions);break;}
     if((r.instructions&63)==0){if(e.cancelled())throw std::runtime_error("Operation cancelled");if(Clock::now()>=deadline){timeStop=true;r.limited=true;stop(StopReason::TimeLimit,pc,runBegin,pathInstructions,r.instructions);break;}}
     size_t available=0;auto bytesHere=fileCode(b,pc,available);
     if(!bytesHere){++r.invalid;stop(StopReason::Unavailable,pc,runBegin,pathInstructions,r.instructions);break;}
     available=static_cast<size_t>(std::min<uint64_t>(available,candidateEnd(pc,scope)-pc));
     if(!controlFlow||r.provenEnd)available=static_cast<size_t>(std::min<uint64_t>(available,r.boundary-pc));
     if(!reserve(instructions,1,maxInstructions)){instructionStop=true;r.limited=true;stop(StopReason::InstructionLimit,pc,runBegin,pathInstructions,r.instructions);break;}
     ZydisDecodedInstruction inst{};ZydisDecoderContext context{};ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
     if(!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder,&context,bytesHere,available,&inst))){++r.invalid;stop(StopReason::InvalidDecode,pc,runBegin,pathInstructions,r.instructions,bytesHere,available);break;}
     const bool needOperands=controlFlow&&constants.needsOperands(inst);
     if(needOperands&&!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder,&context,&inst,operands,inst.operand_count))){++r.invalid;stop(StopReason::OperandDecode,pc,runBegin,pathInstructions,r.instructions,bytesHere,available);break;}
     bool crosses=false;for(unsigned n=1;n<inst.length;++n)if(seen.contains(pc+n)||inData(pc+n,manualData)){crosses=true;break;}
     if(crosses){++r.overlap;stop(StopReason::Overlap,pc,runBegin,pathInstructions,r.instructions,bytesHere,available);break;}
     if(!reserve(bytes,inst.length,maxBytes)){byteStop=true;r.limited=true;stop(StopReason::ByteLimit,pc,runBegin,pathInstructions,r.instructions,bytesHere,available);break;}
     const auto before=r.instructions,pathBefore=pathInstructions;
     seen.emplace(pc,inst.length);++r.instructions;++pathInstructions;r.bytes+=inst.length;runEnd=pc+inst.length;r.observedBegin=std::min(r.observedBegin,pc);r.observedEnd=std::max(r.observedEnd,runEnd);
     auto category=inst.meta.category;
     if(category==ZYDIS_CATEGORY_CALL||category==ZYDIS_CATEGORY_UNCOND_BR||category==ZYDIS_CATEGORY_COND_BR){
      ZydisDecodedOperand operand{};std::optional<Address> target;bool registerDerived=false;std::optional<Address> sourceSlot;
      if(inst.operand_count_visible&&ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder,&context,&inst,&operand,1))&&operand.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&operand.imm.is_relative){ZyanU64 va=0;if(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst,&operand,pc,&va)))target=va;}
      else if(controlFlow&&inst.operand_count_visible){
       registerDerived=operand.type==ZYDIS_OPERAND_TYPE_REGISTER||(operand.type==ZYDIS_OPERAND_TYPE_MEMORY&&(operand.mem.index!=ZYDIS_REGISTER_NONE||(operand.mem.base!=ZYDIS_REGISTER_NONE&&operand.mem.base!=ZYDIS_REGISTER_RIP&&operand.mem.base!=ZYDIS_REGISTER_EIP)));
       auto value=constants.operandValue(inst,operand,pc,readPointer);
       if(value&&candidateEnd(value->value,scope)&&!inData(value->value,manualData)&&!deleted.contains(value->value)){
        target=value->value;sourceSlot=value->readonlySlot;
        if(registerDerived){++r.resolvedRegister;++r.indirect;stop(category==ZYDIS_CATEGORY_CALL?StopReason::ResidualCall:StopReason::ResidualJump,pc,runBegin,pathBefore,before,bytesHere,available,target);}else ++r.resolvedIndirect;
        CodeAnalysisTransfer evidence{pc,*target,category==ZYDIS_CATEGORY_CALL,registerDerived?"path_local_register_constant":"fixed_readonly_memory_pointer",sourceSlot,registerDerived,registerDerived};
        if(reserve(transferCount,1,transferLimit))out.transfers.push_back(std::move(evidence));else transferStop=true;
       }
      }
      if(category==ZYDIS_CATEGORY_CALL){
       if(target&&candidateEnd(*target,scope)&&!inData(*target,manualData)&&!deleted.contains(*target)&&!known.contains(*target))out.calls.push_back(*target);
       if(!target){++r.indirect;stop(StopReason::IndirectCall,pc,runBegin,pathBefore,before,bytesHere,available);}
      }else{
       if(target){traceLeaders.insert(*target);if(allowed(*target))pending.push_back(*target);else{++r.externalEdges;stop(StopReason::TargetOutsideScope,pc,runBegin,pathBefore,before,bytesHere,available,target);}}
       else{
        auto sw=manualSwitches.find(pc);
        if(controlFlow&&category==ZYDIS_CATEGORY_UNCOND_BR&&sw!=manualSwitches.end()){
         for(auto destination:sw->second){traceLeaders.insert(destination);if(allowed(destination))pending.push_back(destination);else{++r.externalEdges;stop(StopReason::TargetOutsideScope,pc,runBegin,pathBefore,before,bytesHere,available,destination);}}
        }else{
         auto context=switchTargets.find(at);const std::vector<Address>* targets=nullptr;
         if(controlFlow&&category==ZYDIS_CATEGORY_UNCOND_BR&&context!=switchTargets.end()){
          auto dispatch=context->second.find(pc);if(dispatch!=context->second.end())targets=&dispatch->second;
         }
         ++r.indirect; // Cross-pass targets are candidate routes, never global closure.
         if(targets&&!targets->empty()){
          ++r.resolvedSwitch;
          for(auto destination:*targets){
           traceLeaders.insert(destination);
           if(allowed(destination)&&!deleted.contains(destination)){
            pending.push_back(destination);
            CodeAnalysisTransfer evidence{pc,destination,false,"bounded_read_only_table",{},true,true};
            if(reserve(transferCount,1,transferLimit))out.transfers.push_back(std::move(evidence));else transferStop=true;
            stop(StopReason::ResidualJump,pc,runBegin,pathBefore,before,bytesHere,available,destination);
           }else{++r.externalEdges;stop(StopReason::TargetOutsideScope,pc,runBegin,pathBefore,before,bytesHere,available,destination);}
          }
         }else stop(StopReason::IndirectJump,pc,runBegin,pathBefore,before,bytesHere,available);
        }
       }
       if(category==ZYDIS_CATEGORY_UNCOND_BR)break;
      }
      if(controlFlow){constants.observe(inst,needOperands?operands:nullptr,pc,readPointer);if(category==ZYDIS_CATEGORY_COND_BR)constants.reset();}
     }else if(category==ZYDIS_CATEGORY_RET){++r.returns;break;}
     else if(category==ZYDIS_CATEGORY_INTERRUPT||inst.mnemonic==ZYDIS_MNEMONIC_HLT||inst.mnemonic==ZYDIS_MNEMONIC_UD2){r.boundaryHit=true;stop(StopReason::Terminator,pc,runBegin,pathBefore,before,bytesHere,available);break;}
     else if(controlFlow)constants.observe(inst,needOperands?operands:nullptr,pc,readPointer);
     pc=runEnd;
    }
    addSpan(runBegin,runEnd);
   }
   out.rows.push_back(r);
  }
 }));std::exception_ptr error;for(auto& t:tasks)try{t.get();}catch(...){if(!error)error=std::current_exception();}if(error)std::rethrow_exception(error);if(e.cancelled())throw std::runtime_error("Operation cancelled");std::vector<Address> candidates;for(auto& out:results){skippedSeeds+=out.skipped;cache->records.insert(cache->records.end(),out.rows.begin(),out.rows.end());cache->spans.insert(cache->spans.end(),out.spans.begin(),out.spans.end());cache->transfers.insert(cache->transfers.end(),out.transfers.begin(),out.transfers.end());cache->stops.insert(cache->stops.end(),out.stops.begin(),out.stops.end());candidates.insert(candidates.end(),out.calls.begin(),out.calls.end());}std::sort(candidates.begin(),candidates.end());candidates.erase(std::unique(candidates.begin(),candidates.end()),candidates.end());seeds.clear();for(auto target:candidates){if(known.contains(target)||deleted.contains(target)||inData(target,manualData)||!firstScanDecodes(b,target,scope,manualData))continue;if(known.size()>=maxFunctions){seedLimited=true;break;}known.insert(target);additions.push_back(target);seeds.push_back(target);}allBoundaries.insert(allBoundaries.end(),seeds.begin(),seeds.end());std::sort(allBoundaries.begin(),allBoundaries.end());
 }
 if(e.cancelled())throw std::runtime_error("Operation cancelled");std::sort(cache->records.begin(),cache->records.end(),[](const Record& a,const Record& c){return a.entry<c.entry;});std::sort(cache->spans.begin(),cache->spans.end(),[](const Span& a,const Span& c){return a.begin<c.begin||(a.begin==c.begin&&a.end<c.end);});size_t merged=0;for(const auto& s:cache->spans){if(merged&&s.begin<=cache->spans[merged-1].end)cache->spans[merged-1].end=std::max(cache->spans[merged-1].end,s.end);else cache->spans[merged++]=s;}cache->spans.resize(merged);uint64_t uniqueBytes=0;for(const auto& s:cache->spans)uniqueBytes+=s.end-s.begin;size_t invalid=0,indirect=0,resolvedIndirect=0,resolvedRegister=0,resolvedSwitch=0,externalEdges=0,closed=0,limited=0,boundaryHits=0;for(const auto& r:cache->records){invalid+=r.invalid;indirect+=r.indirect;resolvedIndirect+=r.resolvedIndirect;resolvedRegister+=r.resolvedRegister;resolvedSwitch+=r.resolvedSwitch;externalEdges+=r.externalEdges;limited+=r.limited;boundaryHits+=r.boundaryHit;closed+=r.instructions>0&&!r.invalid&&!r.indirect&&!r.externalEdges&&!r.overlap&&!r.limited&&!r.boundaryHit;}
 // Commit only after all workers finish successfully. Recovery adds entry evidence,
 // never a speculative function extent; the original section flags remain intact.
 for(auto at:additions)b.functions.push_back({at,0,"sub_"+hex(at).substr(2),controlFlow?"reachable decoded call":"reachable direct call"});if(!additions.empty()){std::sort(b.functions.begin(),b.functions.end(),[](const Function& a,const Function& c){return a.va<c.va;});e.invalidateDecompilation();}
 const bool discoveryStop=rounds>=maxRounds&&!seeds.empty();bool exhausted=instructionStop||byteStop||timeStop||seedLimited||discoveryStop;Json warnings=Json::array({"Decoded instruction paths are candidates; indirect edges, static bad bytes, unreachable regions and semantics remain unresolved.",controlFlow?"Control-flow traversal crosses heuristic starts using decoded edges or sequential fallthrough; indexed exclusive ends and manual data remain enforced. Reached bytes are not proven function ownership.":"Next indexed starts limit traversal conservatively and are not verified function ends."});if(discoveryStop)warnings.push_back("The discovery round budget stopped traversal with decoded call-entry candidates still pending; increase discovery_rounds to continue deeper recovery.");if(restricted)warnings.push_back("The scan allowlist restricts readable evidence only; excluded original candidate bytes remain in the coverage denominator. An empty allowlist decodes nothing.");warnings.push_back("Register-derived transfers are straight-line path-local candidates with residual unknown incoming routes; no whole-function indirect closure is inferred.");if(transferStop)warnings.push_back("Retained indirect transfer evidence reached its cap; transfer pages are a lower bound while decoding continues.");if(coverageStop)warnings.push_back("Coverage span storage reached its cap; covered_bytes is a lower bound.");std::sort(cache->transfers.begin(),cache->transfers.end(),[](const auto& a,const auto& c){return std::tie(a.source,a.target,a.call,a.provenance,a.readonlySlot,a.pathLocal,a.residualUnknown)<std::tie(c.source,c.target,c.call,c.provenance,c.readonlySlot,c.pathLocal,c.residualUnknown);});cache->transfers.erase(std::unique(cache->transfers.begin(),cache->transfers.end(),[](const auto& a,const auto& c){return std::tie(a.source,a.target,a.call,a.provenance,a.readonlySlot,a.pathLocal,a.residualUnknown)==std::tie(c.source,c.target,c.call,c.provenance,c.readonlySlot,c.pathLocal,c.residualUnknown);}),cache->transfers.end());cache->transferFingerprint=14695981039346656037ULL;for(const auto& row:cache->transfers){for(auto value:{row.source,row.target,static_cast<Address>(row.call),static_cast<Address>(row.pathLocal),static_cast<Address>(row.residualUnknown),static_cast<Address>(bool(row.readonlySlot)),row.readonlySlot.value_or(0)})cache->transferFingerprint=hashBytes(cache->transferFingerprint,&value,sizeof(value));cache->transferFingerprint=hashBytes(cache->transferFingerprint,row.provenance.data(),row.provenance.size());}std::sort(cache->stops.begin(),cache->stops.end(),[](const Stop& a,const Stop& c){return std::tie(a.seed,a.address,a.reason,a.pathStart,a.hasTarget,a.target,a.instructions,a.pathInstructions)<std::tie(c.seed,c.address,c.reason,c.pathStart,c.hasTarget,c.target,c.instructions,c.pathInstructions);});bool storageComplete=!transferStop.load();cache->transferFingerprint=hashBytes(cache->transferFingerprint,&storageComplete,sizeof(storageComplete));cache->summary={{"stop_evidence_enabled",stopLimit!=0},{"stop_events_observed",stopLimit?Json(stopEvents.load()):Json(nullptr)},{"stop_evidence_count",cache->stops.size()},{"stop_evidence_complete",stopLimit!=0&&cache->stops.size()==stopEvents.load()},{"stop_evidence_limit_reached",stopLimit!=0&&stopEvents.load()>stopLimit},{"stop_evidence_limit",stopLimit},{"stop_evidence_scope","Observed non-return termination and unknown-edge events; duplicate sites across seeds are retained. A capped subset is schedule-dependent, not a statistical sample."},{"transfer_evidence_count",cache->transfers.size()},{"transfer_count",cache->transfers.size()},{"transfer_evidence_limit_reached",transferStop.load()},{"transfer_evidence_complete",!transferStop.load()},{"transfer_evidence_limit",transferLimit},{"seed_functions",inputSeeds},{"processed_functions",cache->records.size()},{"skipped_seeds",skippedSeeds},{"functions_added",additions.size()},{"instructions_examined",instructions.load()},{"instructions_decoded",bytes.load()?std::accumulate(cache->records.begin(),cache->records.end(),uint64_t(0),[](uint64_t n,const Record& r){return n+r.instructions;}):uint64_t(0)},{"decoded_bytes",bytes.load()},{"covered_bytes",uniqueBytes},{"candidate_code_bytes",candidateBytes},{"scan_scope_bytes",scanBytes},{"scan_scope_restricted",restricted},{"unexamined_candidate_scope_bytes",candidateBytes-scanBytes},{"scan_scope_uncovered_bytes",scanBytes-uniqueBytes},{"coverage_percent",candidateBytes?100.0*uniqueBytes/candidateBytes:0.0},{"coverage_denominator","Union of original executable and metadata candidate regions clipped to original file-backed bytes; unchanged by traversal policy, scan allowlists or coverage."},{"boundary_policy",boundaryPolicy},{"function_ownership_proven",false},{"coverage_span_count",cache->spans.size()},{"coverage_complete",!coverageStop.load()},{"coverage_meaning","Union of decoded reachable instruction candidates, not an estimate of all code."},{"invalid_stops",invalid},{"unresolved_indirect_edges",indirect},{"resolved_readonly_indirect_edges",resolvedIndirect},{"resolved_register_indirect_edges",resolvedRegister},{"resolved_switch_dispatches",resolvedSwitch},{"switch_preparation",std::move(switchPreparation)},{"register_edge_policy","Straight-line path-local candidates; residual unknown incoming routes remain counted as unresolved."},{"edges_outside_boundary",externalEdges},{"closed_traversals",closed},{"limited_functions",limited},{"boundary_stops",boundaryHits},{"pending_discovered_seeds",seeds.size()},{"instruction_budget_exhausted",instructionStop.load()},{"byte_budget_exhausted",byteStop.load()},{"time_budget_exhausted",timeStop.load()},{"function_budget_exhausted",seedLimited},{"discovery_round_budget_exhausted",discoveryStop},{"budget_exhausted",exhausted},{"traversal_complete",!exhausted&&cache->records.size()>=inputSeeds+additions.size()&&invalid==0&&indirect==0&&closed==cache->records.size()},{"semantic_analysis_complete",false},{"workers",std::min(workerCount,std::max<size_t>(1,inputSeeds))},{"discovery_rounds",rounds},{"options",options},{"warnings",warnings},{"cache_hit",false},{"byte_source","original_file"},{"elapsed_ms",std::chrono::duration<double,std::milli>(Clock::now()-started).count()}};cache->key=cacheKey(e,options);e.runtimeSlots()[slot]=cache;e.advancedState()["auto_code_summary"]=cache->summary;return cache->summary;
}
Json page(Engine& e,const Json& args){if(!e.binary())throw std::runtime_error("Open a binary first");auto i=e.runtimeSlots().find(slot);if(i==e.runtimeSlots().end())throw std::runtime_error("Run analyze_code_paths first; detailed code coverage is held in memory");auto c=std::static_pointer_cast<Cache>(i->second);auto offset=integer(args,"offset",0,0,100000000),limit=integer(args,"limit",500,1,5000);auto view=args.value("view",std::string("functions"));if(view!="functions"&&view!="coverage"&&view!="transfers"&&view!="stops")throw std::runtime_error("view must be functions, coverage, transfers or stops");auto size=view=="functions"?c->records.size():view=="transfers"?c->transfers.size():view=="stops"?c->stops.size():c->spans.size();Json rows=Json::array();for(size_t n=offset;n<size&&n-offset<limit;++n){if(view=="functions")rows.push_back(recordJson(c->records[n]));else if(view=="transfers")rows.push_back(transferJson(c->transfers[n]));else if(view=="stops")rows.push_back(stopJson(c->stops[n]));else rows.push_back({{"start",hex(c->spans[n].begin)},{"end",hex(c->spans[n].end)},{"certainty","reachable instruction candidate"}});}return {{"summary",c->summary},{"cache_stale",c->key!=cacheKey(e,c->summary.at("options"))},{"view",view},{"offset",offset},{"limit",limit},{"total",size},{"items",rows}};}
}
Json autoCodeTools(){auto integerSchema=[](size_t lo,size_t hi){return Json{{"type","integer"},{"minimum",lo},{"maximum",hi}};};Json r=Json::array();auto add=[&](const char* name,const char* description,Json p,bool readOnly){r.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",p},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readOnly},{"destructiveHint",false},{"openWorldHint",false}}}});};add("analyze_code_paths","Recover bounded reachable x86/x64 code paths in parallel from indexed and metadata-backed seeds. Adds decoded call entry candidates; optional control_flow follows real edges across heuristic starts and readonly pointer transfers. Indexed ends and manual data are enforced; optional scan_ranges clips readable evidence without shrinking the original coverage denominator. An empty allowlist decodes nothing. Semantics remain unknown.",{{"boundary_policy",{{"type","string"},{"enum",{"next_seed","control_flow"}}}},{"instruction_budget",integerSchema(1,100000000)},{"byte_budget",integerSchema(1,512*1024*1024)},{"time_budget_ms",integerSchema(1,300000)},{"per_function_instruction_budget",integerSchema(1,100000)},{"function_budget",integerSchema(1,1000000)},{"coverage_span_budget",integerSchema(1,4000000)},{"workers",integerSchema(1,32)},{"discovery_rounds",integerSchema(1,32)},{"transfer_limit",integerSchema(1,1000000)},{"stop_limit",integerSchema(0,1000000)},{"switch_functions",{{"type","array"},{"maxItems",256},{"items",{{"type","string"},{"pattern","^0[xX][0-9a-fA-F]{1,16}$"}}}}},{"switch_instruction_budget",integerSchema(1,20000)},{"switch_time_budget_ms",integerSchema(1,5000)},{"switch_transfer_limit",integerSchema(1,1000000)},{"scan_ranges",{{"type","array"},{"maxItems",4096},{"items",{{"type","object"},{"properties",{{"start",{{"type","string"},{"pattern","^0[xX][0-9a-fA-F]{1,16}$"}}},{"end",{{"type","string"},{"pattern","^0[xX][0-9a-fA-F]{1,16}$"}}}}},{"required",{"start","end"}},{"additionalProperties",false}}}}},{"use_cache",{{"type","boolean"}}}},false);add("get_code_analysis","Read bounded pages of function path recovery or compact coverage spans and identify stale analysis results.",{{"view",{{"type","string"},{"enum",{"functions","coverage","transfers","stops"}}}},{"offset",integerSchema(0,100000000)},{"limit",integerSchema(1,5000)}},true);return r;}
std::optional<Json> callAutoCodeTool(Engine& e,const std::string& name,const Json& args){if(name=="analyze_code_paths")return analyze(e,args);if(name=="get_code_analysis")return page(e,args);return std::nullopt;}
std::shared_ptr<const std::vector<CodeAnalysisTransfer>> codeAnalysisTransfers(Engine& e){if(!e.binary())return {};auto found=e.runtimeSlots().find(slot);if(found==e.runtimeSlots().end())return {};auto cache=std::static_pointer_cast<Cache>(found->second);if(cache->key!=cacheKey(e,cache->summary.at("options")))return {};return std::shared_ptr<const std::vector<CodeAnalysisTransfer>>(cache,&cache->transfers);}

std::optional<uint64_t> codeAnalysisTransferFingerprint(Engine& e){if(!e.binary())return {};auto found=e.runtimeSlots().find(slot);if(found==e.runtimeSlots().end())return {};auto cache=std::static_pointer_cast<Cache>(found->second);if(cache->key!=cacheKey(e,cache->summary.at("options")))return {};return cache->transferFingerprint;}

std::optional<std::vector<std::pair<Address,Address>>> codeAnalysisRanges(Engine& e){
 if(!e.binary())return std::nullopt;
 auto found=e.runtimeSlots().find(slot);if(found==e.runtimeSlots().end())return std::nullopt;
 auto cache=std::static_pointer_cast<Cache>(found->second);
 if(cache->key!=cacheKey(e,cache->summary.at("options")))return std::nullopt;
 std::vector<std::pair<Address,Address>> ranges;ranges.reserve(cache->spans.size());
 for(const auto& span:cache->spans)ranges.emplace_back(span.begin,span.end);
 return ranges;
}
}
