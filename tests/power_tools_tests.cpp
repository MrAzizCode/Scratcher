#include "feature_power_tools.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <iterator>

using namespace scratcher;
namespace {
int checks=0;
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
template<class Callback>void rejects(Callback callback,const char* message){bool rejected=false;try{callback();}catch(const std::exception&){rejected=true;}check(rejected,message);}
Json call(Engine& engine,const std::string& name,Json args=Json::object()){auto result=callPowerTool(engine,name,args);if(!result)throw std::runtime_error("Tool was not dispatched");return *result;}
std::string read(const std::filesystem::path& path){std::ifstream file(path,std::ios::binary);return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};}
void write(const std::filesystem::path& path,const std::string& bytes){std::ofstream file(path,std::ios::binary);file.write(bytes.data(),bytes.size());}
template<class T>void field(std::string& bytes,size_t offset,T value){std::memcpy(bytes.data()+offset,&value,sizeof(value));}
std::string peFixture(){std::string bytes(0x500,'\0');bytes[0]='M';bytes[1]='Z';field<uint32_t>(bytes,0x3c,0x80);field<uint32_t>(bytes,0x80,0x4550);field<uint16_t>(bytes,0x84,0x8664);field<uint16_t>(bytes,0x86,2);field<uint16_t>(bytes,0x94,240);
 constexpr size_t opt=0x98;field<uint16_t>(bytes,opt,0x20b);field<uint32_t>(bytes,opt+16,0x1000);field<uint64_t>(bytes,opt+24,0x140000000);field<uint32_t>(bytes,opt+60,0x200);field<uint32_t>(bytes,opt+108,0);
 constexpr size_t section=opt+240;std::memcpy(bytes.data()+section,".text",5);field<uint32_t>(bytes,section+8,0x200);field<uint32_t>(bytes,section+12,0x1000);field<uint32_t>(bytes,section+16,0x200);field<uint32_t>(bytes,section+20,0x200);field<uint32_t>(bytes,section+36,0x60000000);
 std::memcpy(bytes.data()+section+40,".bss",4);field<uint32_t>(bytes,section+48,0x80);field<uint32_t>(bytes,section+52,0x2000);field<uint32_t>(bytes,section+76,0xc0000000);bytes[0x200]='\x31';bytes[0x201]='\xc0';bytes[0x202]='\xc3';return bytes;}
}
int main(){try{
 auto root=executableDir()/"power-tools-fixtures";std::filesystem::create_directories(root);auto raw=root/"power.bin";auto pe=root/"power.exe";
 write(raw,std::string("\x31\xc0\xc3",3)+std::string(29,'\x90'));write(pe,peFixture());
 Engine engine;rejects([&]{call(engine,"get_memory_map");},"Tools reject missing binary");check(!callPowerTool(engine,"unknown",Json::object()),"Unknown tool falls through");check(powerTools().size()==7,"Seven definitions");
 engine.open(raw,0,64);auto result=call(engine,"offset_to_address",{{"file_offset",0}});check(result["mapped"]==true&&result["address"]=="0x0","Virtual address zero is mapped");
 result=call(engine,"address_to_offset",{{"address","0x0"}});check(result["file_backed"]==true&&result["file_offset"]==0,"Raw address conversion");
 result=call(engine,"offset_to_address",{{"file_offset",32}});check(result["in_file"]==false&&result["mapped"]==false,"EOF is outside file");
 result=call(engine,"resolve_address",{{"query","unknown"}});check(result["resolved"]==false&&result["ambiguous"]==false&&result["location"].is_null(),"Unknown symbols remain unresolved");
 result=call(engine,"resolve_address",{{"query","entry"}});check(result["resolved"]==true&&result["location"]["address"]=="0x0","Exact function symbol resolves");
 engine.setLabel(1,"entry");result=call(engine,"resolve_address",{{"query","entry"}});check(result["ambiguous"]==true&&result["resolved"]==false&&result["location"].is_null()&&result["total"]==2,"Duplicate exact names return candidates");
 rejects([&]{call(engine,"resolve_address",{{"address","0x0"},{"query","entry"}});},"Resolver rejects both selectors");rejects([&]{call(engine,"resolve_address");},"Resolver rejects missing selector");
 result=call(engine,"get_function_details",{{"address","0x1"},{"instruction_count",2}});check(result["address"]=="0x0"&&result["requested_address"]=="0x1","Details canonicalize containing function");check(result["instructions"].size()==2&&!result.contains("pseudocode"),"Bounded instructions and pseudocode opt in");
 rejects([&]{call(engine,"get_function_details",{{"address","0x100"}});},"Unmapped function is rejected");rejects([&]{call(engine,"get_function_details",{{"address","0x0"},{"instruction_count",513}});},"Instruction limit enforced");
 std::atomic_bool flag=true;engine.setCancellation(&flag);result=call(engine,"batch_decompile",{{"addresses",{"0x0","0x1"}}});check(result["cancelled"]==true&&result["processed"]==0&&result["remaining"]==2,"Batch cancellation reports unprocessed addresses");engine.setCancellation(nullptr);
 result=call(engine,"batch_decompile",{{"addresses",{"0xffff","0xfffe"}},{"stop_on_error",true}});check(result["processed"]==1&&result["remaining"]==1&&result["stopped_on_error"]==true&&!result["items"][0]["success"].get<bool>(),"Batch stop on error is explicit");
 Json repeated=Json::array();for(int i=0;i<128;++i)repeated.push_back("0xffff");result=call(engine,"batch_decompile",{{"addresses",repeated},{"max_output_bytes",1024}});check(result["truncated"]==true&&result["remaining"].get<size_t>()>0&&result.dump().size()<=1024,"Batch preserves valid bounded JSON");check(result["next_index"]==result["processed"],"Batch cursor matches returned items");
 repeated.push_back("0xffff");rejects([&]{call(engine,"batch_decompile",{{"addresses",repeated}});},"Batch limit enforced");
 auto references=root/"references.bin";write(references,std::string("\x90\xe8\x02\x00\x00\x00\xc3\x90\xc3",9));engine.open(references);result=call(engine,"get_function_details",{{"address","0x1002"},{"instruction_count",0},{"include_references",true},{"reference_budget",32}});check(result["outgoing_references"]["total"]==1&&result["outgoing_references"]["items"][0]["from"]=="0x1001","Details include references across the function range");
 engine.open(pe);result=call(engine,"get_memory_map");check(result["sections"].size()==3,"PE memory map includes headers and sections");
 result=call(engine,"batch_decompile",{{"addresses",{"0x140001001"}}});check(result["processed"]==1&&result["items"][0]["success"]==true&&result["items"][0]["address"]=="0x140001000"&&result["items"][0]["pseudocode"]["code"].is_string(),"Batch returns pseudocode for containing function");
 result=call(engine,"address_to_offset",{{"address","0x140001002"}});check(result["file_offset"]==0x202&&result["file_backed"]==true,"PE virtual address maps to file");
 result=call(engine,"address_to_offset",{{"address","0x140002010"}});check(result["mapped"]==true&&result["zero_filled"]==true&&result["file_offset"].is_null(),"PE BSS is zero-filled without a file offset");
 result=call(engine,"address_to_offset",{{"address","0x140003000"}});check(result["mapped"]==false&&result["zero_filled"]==false,"Unmapped memory is distinct from BSS");
 result=call(engine,"offset_to_address",{{"file_offset",0x480}});check(result["in_file"]==true&&result["mapped"]==false&&result["address"].is_null(),"PE overlay is file-only");
 result=call(engine,"offset_to_address",{{"file_offset",0x202}});check(result["address"]=="0x140001002"&&result["ambiguous"]==false,"PE offset reverse conversion");
 auto report=root/(L"analysis-"+std::to_wstring(GetCurrentProcessId())+L".json");std::error_code error;std::filesystem::remove(report,error);auto original=read(pe);engine.setComment(0x140001000,"entry note");engine.stagePatch(0x140001000,"90");
 result=call(engine,"export_analysis",{{"path",pathText(report)},{"format","json"},{"addresses",{"0x140001001"}}});auto document=Json::parse(read(report));check(result["bytes"]==read(report).size()&&document["functions"].size()==1,"Report exports valid complete JSON");check(document["annotations"]["annotations"].size()==1&&document["patches"].size()==1&&document["selected_functions"][0]["address"]=="0x140001000","Report contains workspace and selected canonical function");check(read(pe)==original,"Report preserves source binary");
 rejects([&]{call(engine,"export_analysis",{{"path",pathText(report)},{"format","json"}});},"Existing report cannot be overwritten");rejects([&]{call(engine,"export_analysis",{{"path",pathText(pe)},{"format","json"}});},"Source binary cannot be overwritten");
 auto hardlink=root/(L"source-link-"+std::to_wstring(GetCurrentProcessId())+L".exe");std::filesystem::remove(hardlink,error);std::filesystem::create_hard_link(pe,hardlink);rejects([&]{call(engine,"export_analysis",{{"path",pathText(hardlink)},{"format","json"}});},"Source hardlink cannot be overwritten");check(read(pe)==original,"Rejected hardlink export preserves source");
 auto cancelledPath=root/(L"cancelled-"+std::to_wstring(GetCurrentProcessId())+L".json");std::filesystem::remove(cancelledPath,error);engine.setCancellation(&flag);rejects([&]{call(engine,"export_analysis",{{"path",pathText(cancelledPath)},{"format","json"}});},"Cancelled report export rejects operation");check(!std::filesystem::exists(cancelledPath),"Cancelled export leaves no destination");engine.setCancellation(nullptr);
 auto markdown=root/(L"analysis-"+std::to_wstring(GetCurrentProcessId())+L".md");std::filesystem::remove(markdown,error);call(engine,"export_analysis",{{"path",pathText(markdown)},{"format","markdown"}});check(read(markdown).find("# Scratcher analysis report")==0,"Markdown report exports");
 std::filesystem::remove(report,error);std::filesystem::remove(markdown,error);std::filesystem::remove(hardlink,error);
 std::cout<<"PASS: "<<checks<<" power tool checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
