#include "feature_auto_rtti.hpp"
#include <atomic>
#include <fstream>
#include <iostream>
using namespace scratcher;
namespace {
int checks=0;
void check(bool v,const char* name){++checks;if(!v)throw std::runtime_error(name);}
constexpr Address base=0x140000000ull;
template<class T> void put(std::vector<uint8_t>& bytes,size_t at,T value){std::memcpy(bytes.data()+at,&value,sizeof(value));}
void text(std::vector<uint8_t>& bytes,size_t at,const char* s){std::memcpy(bytes.data()+at,s,std::strlen(s)+1);}
std::vector<uint8_t> fixture(){std::vector<uint8_t> b(4096);b[0x40]=0xc3;b[0x50]=0xc3;
 put<uint64_t>(b,0x180,base+0x600);text(b,0x190,".?AVDerived@@");put<uint64_t>(b,0x1c0,base+0x600);text(b,0x1d0,".?AUBase@@");
 for(size_t col:{0x280,0x2a0}){put<uint32_t>(b,col,1);put<uint32_t>(b,col+4,col==0x280?0:8);put<uint32_t>(b,col+12,0x180);put<uint32_t>(b,col+16,0x300);put<uint32_t>(b,col+20,static_cast<uint32_t>(col));}
 put<uint32_t>(b,0x308,2);put<uint32_t>(b,0x30c,0x340);put<uint32_t>(b,0x328,1);put<uint32_t>(b,0x32c,0x350);
 put<uint32_t>(b,0x340,0x380);put<uint32_t>(b,0x344,0x3c0);put<uint32_t>(b,0x350,0x3c0);
 put<uint32_t>(b,0x380,0x180);put<uint32_t>(b,0x384,1);put<int32_t>(b,0x38c,-1);put<uint32_t>(b,0x394,0x40);put<uint32_t>(b,0x398,0x300);
 put<uint32_t>(b,0x3c0,0x1c0);put<int32_t>(b,0x3cc,-1);put<uint32_t>(b,0x3d4,0x40);put<uint32_t>(b,0x3d8,0x320);
 put<uint64_t>(b,0x3f8,base+0x280);put<uint64_t>(b,0x400,base+0x40);put<uint64_t>(b,0x478,base+0x2a0);put<uint64_t>(b,0x480,base+0x50);
 put<uint32_t>(b,0x500,1);put<uint32_t>(b,0x514,0x501);put<uint64_t>(b,0x578,base+0x500);put<uint64_t>(b,0x580,base+0x40);return b;}
void open(Engine& e,const std::filesystem::path& root,const char* name,const std::vector<uint8_t>& bytes){auto p=root/(std::string(name)+".bin");{std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));}e.open(p,base,64);auto* b=e.editableBinary();b->format="PE";b->language="x86:LE:64:default:windows";b->sections={{".text",base,256,0,256,true,false},{".rdata",base+256,bytes.size()-256,256,bytes.size()-256,false,false}};}
Json tool(Engine& e,const char* name,Json args=Json::object()){auto r=callAutoRttiTool(e,name,args);if(!r)throw std::runtime_error("Unknown test tool");return *r;}
Json analyze(Engine& e,Json args=Json::object()){return tool(e,"analyze_rtti",args);}
}
int main(){try{auto root=executableDir()/"auto-rtti-fixtures";std::filesystem::create_directories(root);Engine e;open(e,root,"valid",fixture());
 check(tool(e,"get_rtti")["available"]==false,"getter before recovery is explicit");auto r=analyze(e);
 check(r["classes"]==1&&r["vftables"]==2,"two locators consolidate by class type descriptor");check(r["base_descriptors"]==2,"class hierarchy retains self and base records");check(r["scan_complete"]==true,"bounded small scan completed");check(r["semantic_analysis_complete"]==false&&r["class_fields_recovered"]==false,"no full semantic or field claim");
 check(r["class_type_descriptors"]==1&&r["unique_decorated_names"]==1&&r["complete_object_locators"]==2,"type, name and locator counts distinguish identity");
 check(r["memory_budget_bytes"].get<size_t>()>0&&r["allocation_accounting_peak_bytes"].get<size_t>()<=r["memory_budget_bytes"].get<size_t>(),"default memory accounting stays within cap");
 check(r["cache_representation"]=="compact_native_records_shared_hierarchies","full scan cache holds native records instead of JSON DOM");
 auto page=tool(e,"get_rtti");check(page["items"][0]["decorated_name"]==".?AVDerived@@","decorated name recovered");check(page["items"][0]["bases"][1]["decorated_name"]==".?AUBase@@","base type recovered");check(page["items"][0]["bases"][1]["vbtable_pointer_displacement"]==-1,"signed PMD preserved");
 check(page["items"][0]["vftables"][1]["object_offset"]==8,"secondary vftable object offset");check(page["items"][0]["vftables"][0]["first_method_body_validated"]==false,"virtual method remains code candidate");
 check(e.advancedState()["auto_rtti"].dump().size()<2048,"persistent state is only compact summary");check(tool(e,"get_rtti",{{"query","Derived"}})["total"]==1,"name query");check(tool(e,"get_rtti",{{"offset",1},{"limit",1}})["items"].empty(),"bounded pagination");
 check(tool(e,"get_rtti",{{"max_output_bytes",1024}})["output_budget_exhausted"]==true,"page serialization has a separate byte cap");
 r=analyze(e,{{"byte_budget",8}});check(r["scan_complete"]==false&&r["budget_exhausted"]==true&&r["bytes_scanned"]==8,"byte budget exact");
 r=analyze(e,{{"candidate_budget",1}});check(r["vftables"]==1&&r["budget_exhausted"]==true,"candidate budget returns partial evidence");
 r=analyze(e,{{"base_budget",1}});check(r["classes"]==0&&r["invalid_candidates"]==2,"oversized hierarchy safely rejected");
 check(r["base_count_limit_reached"]==true&&r["records_complete"]==false,"hierarchy count cap is explicit despite completed pointer scan");
 auto bytes=fixture();put<uint32_t>(bytes,0x294,0x284);open(e,root,"wrong-self",bytes);r=analyze(e);check(r["vftables"]==1,"invalid locator self-relative address rejected");
 bytes=fixture();put<uint32_t>(bytes,0x380,0x1c0);open(e,root,"wrong-self-base",bytes);r=analyze(e);check(r["classes"]==0,"hierarchy self descriptor must match locator type");
 bytes=fixture();put<uint32_t>(bytes,0x308,0xffffffff);open(e,root,"large-count",bytes);r=analyze(e);check(r["classes"]==0,"malformed count cannot allocate enormous base vector");
 bytes=fixture();put<uint32_t>(bytes,0x344,0xfff);open(e,root,"truncated",bytes);r=analyze(e);check(r["classes"]==0,"truncated base descriptor rejected");
 bytes=fixture();put<uint64_t>(bytes,0x400,base+0x800);put<uint64_t>(bytes,0x480,base+0x800);open(e,root,"non-code",bytes);r=analyze(e);check(r["classes"]==0,"non-code pointer cannot prove vftable");
 e.editableBinary()->analysisRanges.push_back({base+0x800,base+0x810});r=analyze(e);check(r["classes"]==1,"trusted analysis candidate permitted without changing section flags");e.editableBinary()->analysisRanges.clear();check(tool(e,"get_rtti")["stale"]==true,"analysis range edits invalidate cache");
 bytes=fixture();bytes[0x190]='x';open(e,root,"bad-name",bytes);r=analyze(e);check(r["classes"]==0,"unrecognized decorated type name rejected");
 bytes=fixture();put<uint64_t>(bytes,0x188,1);open(e,root,"dynamic-spare",bytes);r=analyze(e);check(r["classes"]==0,"runtime-mutated TypeDescriptor explicitly unsupported");
 bytes=fixture();put<uint32_t>(bytes,0x308,100);put<uint32_t>(bytes,0x30c,0x800);put<uint32_t>(bytes,0x384,99);for(size_t i=0;i<100;++i)put<uint32_t>(bytes,0x800+i*4,i?0x3c0:0x380);open(e,root,"memory-capped",bytes);r=analyze(e,{{"memory_budget_bytes",65536}});check(r["memory_budget_exhausted"]==true&&r["scan_complete"]==false,"typed child-vector allocation obeys memory cap");check(r["allocation_accounting_peak_bytes"].get<size_t>()<=65536,"failed allocation does not exceed accounting budget");
 bytes=fixture();put<uint64_t>(bytes,0x700,base+0x600);text(bytes,0x710,".?AVDerived@@");put<uint32_t>(bytes,0x748,1);put<uint32_t>(bytes,0x74c,0x760);put<uint32_t>(bytes,0x760,0x780);put<uint32_t>(bytes,0x780,0x700);put<int32_t>(bytes,0x78c,-1);put<uint64_t>(bytes,0x7f8,base+0x820);put<uint64_t>(bytes,0x800,base+0x40);put<uint32_t>(bytes,0x820,1);put<uint32_t>(bytes,0x82c,0x700);put<uint32_t>(bytes,0x830,0x740);put<uint32_t>(bytes,0x834,0x820);open(e,root,"same-name",bytes);r=analyze(e);check(r["class_type_descriptors"]==2&&r["unique_decorated_names"]==1&&r["complete_object_locators"]==3,"distinct type descriptors with repeated names counted separately");r=analyze(e,{{"class_budget",1}});check(r["class_budget_exhausted"]==true&&r["class_type_descriptors"]==1,"class cap flag distinct from other caps");
 std::atomic_bool cancel=true;e.setCancellation(&cancel);bool rejected=false;try{analyze(e);}catch(const std::exception&){rejected=true;}e.setCancellation(nullptr);check(rejected,"pre-cancel checked");
 rejected=false;try{analyze(e,{{"time_budget_ms",0}});}catch(const std::exception&){rejected=true;}check(rejected,"invalid time budget rejected");check(autoRttiTools().size()==2,"two RTTI tools");check(!callAutoRttiTool(e,"other",Json::object()),"unowned tool ignored");
 open(e,root,"fresh",fixture());check(tool(e,"get_rtti")["available"]==false,"open clears runtime cache");e.editableBinary()->format="Raw";rejected=false;try{analyze(e);}catch(const std::exception&){rejected=true;}check(rejected,"unsupported format rejected");
 std::cout<<"PASS: "<<checks<<" RTTI recovery checks\n";return 0;
}catch(const std::exception& ex){std::cerr<<"FAIL after "<<checks<<" checks: "<<ex.what()<<'\n';return 1;}}
