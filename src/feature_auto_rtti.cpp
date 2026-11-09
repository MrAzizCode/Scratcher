#include "feature_auto_rtti.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace scratcher { namespace {
// MS x64 image-relative layouts: clang/lib/CodeGen/MicrosoftCXXABI.cpp.
using Clock=std::chrono::steady_clock;
constexpr const char* slot="auto_rtti.v1";
size_t bounded(const Json& args,const char* key,size_t fallback,size_t low,size_t high){
 if(!args.contains(key))return fallback;const auto& j=args.at(key);
 if(!j.is_number_unsigned()&&!(j.is_number_integer()&&j.get<int64_t>()>=0))throw std::runtime_error(std::string(key)+" must be a nonnegative integer");
 auto n=j.get<uint64_t>();if(n<low||n>high)throw std::runtime_error(std::string(key)+" is outside its supported range");return static_cast<size_t>(n);
}
const Binary& require(Engine& e){if(!e.binary())throw std::runtime_error("Open a binary first");return *e.binary();}
std::string fingerprint(const Binary& b){std::string s=pathText(b.path)+":"+std::to_string(b.size())+":"+std::to_string(b.base)+":"+b.format+":"+b.language;for(const auto& r:b.sections)s+=":"+std::to_string(r.va)+","+std::to_string(r.offset)+","+std::to_string(r.fileSize)+","+std::to_string(r.executable);for(const auto& r:b.analysisRanges)s+=":"+std::to_string(r.first)+","+std::to_string(r.second);return s;}
struct Reader {
 const Binary& b;
 bool offset(Address va,size_t size,uint64_t& out)const {
  const auto* s=b.section(va);if(!s||va<s->va)return false;auto delta=va-s->va;
  if(delta>s->fileSize||size>s->fileSize-delta||s->offset>b.size()||delta>b.size()-s->offset)return false;
  out=s->offset+delta;return b.has(out,size);
 }
 template<class T> bool read(Address va,T& out)const {uint64_t off;if(!offset(va,sizeof(T),off))return false;std::memcpy(&out,b.bytes()+off,sizeof(T));return true;}
 bool rva(uint32_t r,Address& a)const {if(!r||b.base>UINT64_MAX-r)return false;a=b.base+r;uint64_t o;return offset(a,1,o);}
 bool code(Address va)const {uint64_t ignored;return b.analysisCode(va)&&offset(va,1,ignored);}
 bool type(Address va,std::string& name)const {
  uint64_t off;if(!offset(va,20,off))return false;uint64_t typeVftable=0,spare=0;
  std::memcpy(&typeVftable,b.bytes()+off,8);std::memcpy(&spare,b.bytes()+off+8,8);
  // Static TypeDescriptor spare is zero; runtime-populated descriptors are unsupported.
  uint64_t ignored;if(!typeVftable||spare||!offset(typeVftable,8,ignored))return false;
  const auto* sec=b.section(va);auto available=std::min<uint64_t>(512,sec->fileSize-(va-sec->va)-16);
  name.clear();for(size_t i=0;i<available;++i){auto c=b.bytes()[off+16+i];if(!c)return name.size()>=7&&name.starts_with(".?A")&&(name[3]=='V'||name[3]=='U')&&name.ends_with("@@");if(c<0x20||c>0x7e)return false;name.push_back(static_cast<char>(c));}return false;
 }
};
struct Base {Address descriptor=0,type=0;uint32_t contained=0,attributes=0;int32_t mdisp=0,pdisp=0,vdisp=0;std::string name;};
struct Hierarchy {Address address=0;uint32_t attributes=0;std::vector<Base> bases;};
struct Locator {Address va=0,type=0;uint32_t offset=0,cdOffset=0;std::string name;std::shared_ptr<Hierarchy> hierarchy;};
struct Vftable {Address address=0,locator=0,method=0;uint32_t offset=0,cdOffset=0;};
struct ClassRecord {Address type=0;std::string name;std::shared_ptr<Hierarchy> hierarchy;std::vector<Vftable> tables;bool tablesTruncated=false;};
struct Cache {Json summary;std::vector<ClassRecord> rows;std::string fingerprint;};
struct MemoryBudget {
 size_t limit,used=0,peak=0;bool exhausted=false;
 bool reserve(size_t bytes){if(bytes>limit-used){exhausted=true;return false;}used+=bytes;peak=std::max(peak,used);return true;}
 void release(size_t bytes){used-=bytes;}
};
struct MemoryLease {
 MemoryBudget& budget;size_t bytes=0;bool retained=false;
 MemoryLease(MemoryBudget& b,size_t n):budget(b){if(b.reserve(n))bytes=n;}
 ~MemoryLease(){if(bytes&&!retained)budget.release(bytes);}
 explicit operator bool()const{return bytes!=0;}
};
struct Recovery {
 Reader reader;Engine& engine;Clock::time_point deadline;size_t baseLimit;MemoryBudget& memory;bool stopped=false;size_t oversizedHierarchies=0;
 std::unordered_map<Address,std::shared_ptr<Hierarchy>> hierarchyCache;
 std::unordered_map<Address,std::shared_ptr<Locator>> locatorCache;
 bool stop(){if(memory.exhausted||engine.cancelled()||Clock::now()>=deadline){stopped=true;return true;}return false;}
 std::shared_ptr<Hierarchy> hierarchy(Address va,Address expectedType){
  if(auto it=hierarchyCache.find(va);it!=hierarchyCache.end()){auto h=it->second;return h&&!h->bases.empty()&&h->bases[0].type==expectedType?h:nullptr;}
  uint32_t signature=0,attrs=0,count=0,arrayRva=0;Address array=0;
  if(!reader.read(va,signature)||signature||!reader.read(va+4,attrs)||(attrs&~7u)||!reader.read(va+8,count)||!count||count>4096||!reader.read(va+12,arrayRva)||!reader.rva(arrayRva,array))return nullptr;
  if(count>baseLimit){++oversizedHierarchies;return nullptr;}
  uint64_t off;if(!reader.offset(array,static_cast<size_t>(count)*4,off))return nullptr;
  // Reserve the maximum 512-byte name plus allocator/container slack for every child.
  // Failed speculative graphs release their charge; retained graphs share one allocation.
  MemoryLease storage(memory,256+count*(sizeof(Base)+640));if(!storage)return nullptr;
  auto h=std::make_shared<Hierarchy>();h->address=va;h->attributes=attrs;h->bases.reserve(count);
  for(uint32_t i=0;i<count;++i){if((i&31u)==0&&stop())return nullptr;uint32_t dRva=0,typeRva=0;Base base;
   if(!reader.read(array+4*i,dRva)||!reader.rva(dRva,base.descriptor)||!reader.offset(base.descriptor,24,off)||!reader.read(base.descriptor,typeRva)||!reader.rva(typeRva,base.type)||!reader.type(base.type,base.name))return nullptr;
   reader.read(base.descriptor+4,base.contained);reader.read(base.descriptor+8,base.mdisp);reader.read(base.descriptor+12,base.pdisp);reader.read(base.descriptor+16,base.vdisp);reader.read(base.descriptor+20,base.attributes);
   if(base.contained>=count||base.attributes&~0x7fu||base.pdisp < -1)return nullptr;
   if(base.attributes&0x40u){uint32_t nestedRva=0;Address nested=0;if(!reader.read(base.descriptor+24,nestedRva)||!reader.rva(nestedRva,nested)||!reader.offset(nested,16,off))return nullptr;}
   h->bases.push_back(std::move(base));
  }
  if(h->bases[0].type!=expectedType||h->bases[0].contained!=count-1)return nullptr;
  hierarchyCache.emplace(va,h);storage.retained=true;return h;
 }
 std::shared_ptr<Locator> locator(Address va){
  if(auto it=locatorCache.find(va);it!=locatorCache.end())return it->second;
  uint32_t sig=0,typeRva=0,hRva=0,self=0;uint64_t off;
  if(!reader.offset(va,24,off)||!reader.read(va,sig)||sig!=1||!reader.read(va+20,self)||self!=va-reader.b.base)return nullptr;
  MemoryLease storage(memory,sizeof(Locator)+768);if(!storage)return nullptr;
  auto l=std::make_shared<Locator>();l->va=va;reader.read(va+4,l->offset);reader.read(va+8,l->cdOffset);
  Address hierarchyVa=0;if(!reader.read(va+12,typeRva)||!reader.read(va+16,hRva)||!reader.rva(typeRva,l->type)||!reader.rva(hRva,hierarchyVa)||!reader.type(l->type,l->name))return nullptr;
  l->hierarchy=hierarchy(hierarchyVa,l->type);if(!l->hierarchy)return nullptr;locatorCache.emplace(va,l);storage.retained=true;return l;
 }
};
Json baseJson(const Base& b){return {{"descriptor",hex(b.descriptor)},{"type_descriptor",hex(b.type)},{"decorated_name",b.name},{"contained_base_count",b.contained},{"member_displacement",b.mdisp},{"vbtable_pointer_displacement",b.pdisp},{"vbtable_displacement",b.vdisp},{"attributes",b.attributes}};}
Json classJson(const ClassRecord& row){Json bases=Json::array(),tables=Json::array();for(const auto& b:row.hierarchy->bases)bases.push_back(baseJson(b));for(const auto& t:row.tables)tables.push_back({{"address",hex(t.address)},{"locator",hex(t.locator)},{"first_method",hex(t.method)},{"first_method_code_candidate",true},{"first_method_body_validated",false},{"object_offset",t.offset},{"constructor_displacement",t.cdOffset},{"entry_count_known",false}});
 return {{"type_descriptor",hex(row.type)},{"decorated_name",row.name},{"hierarchy_descriptor",hex(row.hierarchy->address)},{"hierarchy_attributes",row.hierarchy->attributes},{"bases",std::move(bases)},{"vftables",std::move(tables)},{"vftables_truncated",row.tablesTruncated},{"evidence","validated_locator_hierarchy_and_vftable"},{"object_size_known",false},{"class_fields_recovered",false}};
}
Json analyze(Engine& e,const Json& args){
 const auto& b=require(e);if(e.cancelled())throw std::runtime_error("Operation cancelled");
 if(b.format!="PE"||b.bits!=64||!b.language.starts_with("x86:"))throw std::runtime_error("RTTI recovery currently supports x64 PE images");
 auto byteBudget=bounded(args,"byte_budget",512ull*1024*1024,8,2ull*1024*1024*1024),classBudget=bounded(args,"class_budget",50000,1,100000),baseBudget=bounded(args,"base_budget",256,1,4096),timeBudget=bounded(args,"time_budget_ms",10000,1,600000),candidateBudget=bounded(args,"candidate_budget",1000000,1,2000000),memoryBudget=bounded(args,"memory_budget_bytes",256ull*1024*1024,65536,256ull*1024*1024);
 auto started=Clock::now();MemoryBudget memory{memoryBudget};
 auto layoutAllowance=8192+b.sections.size()*512+b.analysisRanges.size()*128+pathText(b.path).size()*4;
 if(!memory.reserve(layoutAllowance))throw std::runtime_error("RTTI memory budget cannot hold the image layout");
 Recovery recovery{{b},e,started+std::chrono::milliseconds(timeBudget),baseBudget,memory};auto cache=std::make_shared<Cache>();cache->fingerprint=fingerprint(b);
 struct Range{uint64_t begin,end;Address va;};std::vector<Range> ranges;uint64_t available=0;
 for(const auto& s:b.sections){auto count=std::min(s.fileSize,s.offset<=b.size()?b.size()-s.offset:0);if(count>=8){ranges.push_back({s.offset,s.offset+count,s.va});available+=count;}}
 // File ranges are visited once; overlapping section aliases are ignored after their first ownership.
 std::sort(ranges.begin(),ranges.end(),[](auto a,auto b){return a.begin<b.begin;});uint64_t previousEnd=0,scanned=0,slots=0,candidates=0,invalid=0;bool budgetHit=false,classHit=false,tableHit=false;
 std::unordered_map<Address,size_t> classes;std::set<std::pair<Address,Address>> seenTables;
 for(auto r:ranges){if(r.begin<previousEnd){auto skip=std::min(r.end,previousEnd)-r.begin;r.begin+=skip;r.va+=skip;}previousEnd=std::max(previousEnd,r.end);if(r.begin>=r.end)continue;
  auto alignment=(8-(r.va&7))&7;r.begin+=alignment;r.va+=alignment;uint64_t off=r.begin;Address va=r.va;
  for(;off+8<=r.end;off+=8,va+=8){if((slots&1023)==0&&recovery.stop())break;if(scanned+8>byteBudget){budgetHit=true;break;}scanned+=8;++slots;uint64_t pointer=0;std::memcpy(&pointer,b.bytes()+off,8);
   if(pointer<b.base||pointer-b.base>UINT32_MAX)continue;uint64_t ignored;if(!recovery.reader.offset(pointer,24,ignored))continue;
   // Signature/self fields are cheap gates before following the graph.
   uint32_t sig=0,self=0;recovery.reader.read(pointer,sig);if(sig!=1)continue;recovery.reader.read(pointer+20,self);if(self!=pointer-b.base)continue;
   if(candidates==candidateBudget){budgetHit=true;break;}++candidates;
   auto l=recovery.locator(pointer);if(!l){++invalid;continue;}uint64_t method=0;if(!recovery.reader.read(va+8,method)||!recovery.reader.code(method)){++invalid;continue;}
   if(seenTables.contains({l->type,va+8}))continue;
   // Native records stay compact; JSON is constructed only for requested output pages.
   // Include set nodes, vector geometric growth/reallocation, and final locator counts.
   if(!memory.reserve(128+sizeof(Vftable)*3))break;seenTables.emplace(l->type,va+8);
   Vftable vftable{va+8,l->va,method,l->offset,l->cdOffset};
   auto found=classes.find(l->type);if(found!=classes.end()){auto& row=cache->rows[found->second];if(row.tables.size()<128)row.tables.push_back(vftable);else{row.tablesTruncated=true;tableHit=true;}continue;}
   if(classes.size()==classBudget){budgetHit=true;classHit=true;break;}
   // Name + class lookup node + geometric vector growth + final unique-name set.
   if(!memory.reserve(2048))break;ClassRecord row{l->type,l->name,l->hierarchy,{vftable},false};
   classes.emplace(l->type,cache->rows.size());cache->rows.push_back(std::move(row));
  }if(budgetHit||recovery.stopped||memory.exhausted)break;
 }
 size_t tableCount=0,baseOccurrences=0;std::set<std::string> names;std::set<Address> locators,baseDescriptors,hierarchies;
 for(const auto& row:cache->rows){names.insert(row.name);tableCount+=row.tables.size();baseOccurrences+=row.hierarchy->bases.size();hierarchies.insert(row.hierarchy->address);for(const auto& child:row.hierarchy->bases)baseDescriptors.insert(child.descriptor);for(const auto& table:row.tables)locators.insert(table.locator);}
 cache->summary={{"version",1},{"classes",cache->rows.size()},{"class_type_descriptors",cache->rows.size()},{"unique_decorated_names",names.size()},{"complete_object_locators",locators.size()},{"vftables",tableCount},{"base_descriptors",baseDescriptors.size()},{"base_descriptor_occurrences",baseOccurrences},{"hierarchy_descriptors",hierarchies.size()},{"pointer_slots_examined",slots},{"candidate_locators_examined",candidates},{"invalid_candidates",invalid},{"bytes_scanned",scanned},{"file_section_bytes",available},{"coverage_scope","file_backed_aligned_pointer_slots"},{"scan_complete",!budgetHit&&!recovery.stopped&&!memory.exhausted},{"records_complete",!budgetHit&&!recovery.stopped&&!memory.exhausted&&!tableHit},{"budget_exhausted",budgetHit||memory.exhausted},{"class_budget_exhausted",classHit},{"vftable_count_limit_reached",tableHit},{"memory_budget_exhausted",memory.exhausted},{"memory_budget_bytes",memoryBudget},{"allocation_accounting_peak_bytes",memory.peak},{"memory_accounting","Conservative allocation allowance includes shared typed child vectors, names, locator caches, maps, and vector reallocation; not process RSS"},{"cache_representation","compact_native_records_shared_hierarchies"},{"output_budget_exhausted",false},{"cancelled",e.cancelled()},{"deadline_exceeded",Clock::now()>=recovery.deadline},{"elapsed_ms",std::chrono::duration<double,std::milli>(Clock::now()-started).count()},{"semantic_analysis_complete",false},{"class_fields_recovered",false},{"persisted_records",false},{"note","Type records consolidate by TypeDescriptor address; names can repeat, while COL/vftable counts are distinct addresses. Object fields, sizes, virtual-method boundaries, and full program semantics remain unknown."}};
 cache->summary["hierarchy_candidates_over_base_limit"]=recovery.oversizedHierarchies;
 cache->summary["base_count_limit_reached"]=recovery.oversizedHierarchies>0;
 if(recovery.oversizedHierarchies)cache->summary["records_complete"]=false;
 e.runtimeSlots()[slot]=cache;e.advancedState()["auto_rtti"]=cache->summary;return cache->summary;
}
Json get(Engine& e,const Json& args){const auto& b=require(e);auto offset=bounded(args,"offset",0,0,SIZE_MAX),limit=bounded(args,"limit",100,1,500),outputBudget=bounded(args,"max_output_bytes",2*1024*1024,1024,8*1024*1024);auto it=e.runtimeSlots().find(slot);if(it==e.runtimeSlots().end())return {{"available",false},{"items",Json::array()},{"note","Run analyze_rtti to recover records for this session"}};auto cache=std::static_pointer_cast<Cache>(it->second);if(cache->fingerprint!=fingerprint(b))return {{"available",false},{"stale",true},{"items",Json::array()}};
 auto query=args.value("query",std::string{});if(query.size()>512)throw std::runtime_error("query exceeds 512 bytes");Json rows=Json::array();size_t total=0,outputBytes=0;bool outputHit=false;for(const auto& row:cache->rows){if(!query.empty()&&row.name.find(query)==std::string::npos)continue;if(total>=offset&&rows.size()<limit&&!outputHit){auto rendered=classJson(row);auto n=rendered.dump().size()+2;if(n>outputBudget-outputBytes)outputHit=true;else{outputBytes+=n;rows.push_back(std::move(rendered));}}++total;}
 return {{"available",true},{"summary",cache->summary},{"items",rows},{"total",total},{"offset",offset},{"next_offset",std::min(total,offset>total?total:offset+rows.size())},{"truncated",offset<total&&rows.size()<total-offset},{"output_budget_exhausted",outputHit},{"first_record_exceeds_output_budget",outputHit&&rows.empty()},{"max_output_bytes",outputBudget}};
}
} // namespace
Json autoRttiTools(){auto number=[](uint64_t low,uint64_t high){return Json{{"type","integer"},{"minimum",low},{"maximum",high}};};Json result=Json::array();
 auto add=[&](const char* name,const char* description,Json properties){result.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",properties},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",true},{"destructiveHint",false},{"idempotentHint",true},{"openWorldHint",false}}}});};
 add("analyze_rtti","Recover validated x64 PE RTTI hierarchies and vftables with byte, class, candidate, base-count, memory, and elapsed-time budgets. Fields and object sizes remain unknown.",{{"byte_budget",number(8,2ull*1024*1024*1024)},{"class_budget",number(1,100000)},{"base_budget",number(1,4096)},{"candidate_budget",number(1,2000000)},{"time_budget_ms",number(1,600000)},{"memory_budget_bytes",number(65536,256ull*1024*1024)}});
 add("get_rtti","Page session RTTI evidence, including decorated type names, base displacement records, locator and vftable addresses.",{{"offset",number(0,UINT64_MAX)},{"limit",number(1,500)},{"query",{{"type","string"},{"maxLength",512}}},{"max_output_bytes",number(1024,8*1024*1024)}});return result;
}
std::optional<Json> callAutoRttiTool(Engine& e,const std::string& name,const Json& args){if(name=="analyze_rtti")return analyze(e,args);if(name=="get_rtti")return get(e,args);return std::nullopt;}
} // namespace scratcher
