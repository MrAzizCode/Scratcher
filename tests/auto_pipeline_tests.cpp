#include "core.hpp"
#include <fstream>
#include <iostream>
#include <atomic>
using namespace scratcher;
int main(){try{
 auto root=executableDir()/"pipeline-fixtures";std::filesystem::create_directories(root);auto input=root/"paths.bin";
 {std::ofstream f(input,std::ios::binary);const char bytes[]={char(0x85),char(0xc0),char(0x74),char(0x01),char(0x90),char(0xc3)};f.write(bytes,sizeof(bytes));}
 Engine e;Tools tools(e);tools.call("open_binary",{{"path",pathText(input)}});
 auto check=[](bool ok,const char* why){if(!ok)throw std::runtime_error(why);};
 check(tools.call("get_auto_analysis_report",Json::object())["status"]=="not_run","new sessions start without prior report");
 auto report=tools.call("run_auto_analysis",{{"time_budget_ms",10000},{"workers",2}});
 check(report["configured_phases_finished"]==false&&report["phases"].size()==4&&report["status"]=="partial_failure","unsupported RTTI on raw input is reported without hiding the other phase results");
 report=tools.call("run_auto_analysis",{{"phases",{"code","exceptions","references"}},{"time_budget_ms",10000},{"workers",2}});
 check(report["configured_phases_finished"]==true&&report["phases"].size()==3,"selected supported phases finish");
 check(report["phases"][0]["result"]["boundary_policy"]=="control_flow","automatic pipeline follows actual flow across heuristic seeds");
 auto conservative=tools.call("run_auto_analysis",{{"phases",{"code"}},{"phase_options",{{"code",{{"boundary_policy","next_seed"}}}}}});
 check(conservative["phases"][0]["result"]["boundary_policy"]=="next_seed","explicit conservative policy remains available");
 auto chain=root/"call-chain.bin";std::vector<unsigned char> chainBytes(12*8,0xcc);
 for(size_t i=0;i<12;++i){auto at=i*8;if(i==11)chainBytes[at]=0xc3;else{chainBytes[at]=0xe8;chainBytes[at+1]=3;chainBytes[at+2]=chainBytes[at+3]=chainBytes[at+4]=0;chainBytes[at+5]=0xc3;}}
 {std::ofstream f(chain,std::ios::binary);f.write(reinterpret_cast<const char*>(chainBytes.data()),std::streamsize(chainBytes.size()));}
 Engine chained;Tools chainTools(chained);chainTools.call("open_binary",{{"path",pathText(chain)}});
 auto chainReport=chainTools.call("run_auto_analysis",{{"phases",{"code"}},{"workers",1}});
 const auto& chainResult=chainReport["phases"][0]["result"];
 check(chainResult["processed_functions"]==12&&chainResult["covered_bytes"]==67&&chainResult["pending_discovered_seeds"]==0&&!chainResult["discovery_round_budget_exhausted"].get<bool>(),"default pipeline follows a call chain beyond eight discovery rounds");
 chainTools.call("open_binary",{{"path",pathText(chain)}});
 auto limitedChain=chainTools.call("run_auto_analysis",{{"phases",{"code"}},{"workers",1},{"phase_options",{{"code",{{"discovery_rounds",8}}}}}});
 check(limitedChain["phases"][0]["result"]["processed_functions"]==8&&limitedChain["phases"][0]["result"]["discovery_round_budget_exhausted"].get<bool>()&&!limitedChain["warnings"].empty(),"explicit discovery limit retains pending work and surfaces partial coverage");
 report=tools.call("run_auto_analysis",{{"phases",{"code","exceptions","references"}},{"time_budget_ms",10000},{"workers",2}});
 check(report["semantic_analysis_complete"]==false&&report["full_analysis_parity_established"]==false,"configured completion never asserts parity");
 check(tools.call("get_auto_analysis_report",Json::object())==report,"getter returns last report");
 auto old=e.advancedState();bool rejected=false;try{tools.call("run_auto_analysis",{{"phase_options",{{"references",{{"unknown_option",true}}}}}});}catch(const std::exception&){rejected=true;}
 check(rejected&&e.advancedState()==old,"all phase arguments validated before starting work");
 report=tools.call("run_auto_analysis",{{"phases",{"code"}},{"instruction_budget",1},{"workers",1}});
 check(report["phases"].size()==1&&report["phases"][0]["result"]["instruction_budget_exhausted"]==true&&!report["warnings"].empty(),"partial instruction coverage is surfaced");
 auto saved=root/"saved.scratcher";tools.call("save_project",{{"path",pathText(saved)}});Engine restored;Tools restoredTools(restored);restoredTools.call("load_project",{{"path",pathText(saved)}});
 check(restoredTools.call("get_auto_analysis_report",Json::object())==report,"summary persists in project");
 std::atomic_bool flag=true;e.setCancellation(&flag);report=tools.call("run_auto_analysis",{{"phases",{"code"}}});e.setCancellation(nullptr);
 check(report["status"]=="cancelled"&&report["phases"].empty()&&report["configured_phases_finished"]==false,"pre-cancelled pipelines start no phases");
 tools.call("open_binary",{{"path",pathText(input)}});check(tools.call("get_auto_analysis_report",Json::object())["status"]=="not_run","reopening resets report");
 check(tools.call("run_auto_analysis",{{"phases",{"code","references"}}})["configured_phases_finished"]==true,"new caches populated after reopen");
 check(tools.call("get_analysis_cache_stats",Json::object())["native_detail_caches"].get<size_t>()>=2,"native details counted separately from persisted caches");
 check(tools.call("clear_analysis_cache",Json::object())["native_detail_caches_removed"].get<size_t>()>=2,"clear removes native details too");
 std::cout<<"PASS: pipeline integration, validation, coverage, persistence and cancellation\n";return 0;
 }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
