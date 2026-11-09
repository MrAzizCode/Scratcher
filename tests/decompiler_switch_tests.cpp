#include "feature_graph.hpp"
#include "feature_advanced_manual.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "feature_advanced_pseudocode.hpp"
#include <algorithm>
#include <atomic>
#include <iostream>
#include <set>

using namespace scratcher;
namespace {
int checks=0;
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
Address named(const Binary& binary,const std::string& name){for(const auto& f:binary.functions)if(f.name==name)return f.va;throw std::runtime_error("Controlled fixture export not indexed");}
}
int main(){try {
    Engine session;
    auto fixture=executableDir()/"ScratcherAnalysisFixture.exe";
    check(std::filesystem::exists(fixture),"controlled fixture available");
    session.open(fixture);
    auto entry=named(*session.binary(),"fixture_switch");
    auto* architecture=session.nativeArchitecture();
    auto originalInstructions=architecture->max_instructions,originalTables=architecture->max_jumptable_size;
    auto graph=buildControlFlowGraph(session,entry,4096);
    check(graph["instruction_count"]==26,"all 26 real switch instructions recovered");
    check(graph["nodes"].size()==10,"switch has ten machine-flow basic blocks");
    check(graph["complete"]==true&&!graph["truncated"].get<bool>(),"switch reachability complete");
    check(graph["semantic_analysis_complete"]==false,"reachability does not claim semantic equivalence");
    check(graph["switch_tables"].size()==1&&graph["switch_tables"][0]["accepted"]==true,"native recovered table accepted");
    check(graph["switch_tables"][0]["targets"].size()==6,"six validated case destinations");
    std::set<std::string> destinations;
    Address branch=address(graph["switch_tables"][0]["address"]);
    for(const auto& edge:graph["edges"])if(edge["label"]=="switch") {
        check(edge["source_provenance"]=="decompiler_recovered_switch","native edge provenance");
        check(edge["unresolved"]==false&&edge["external"]==false,"case destinations decoded within bounds");
        destinations.insert(edge["target"].get<std::string>());
    }
    check(destinations==std::set<std::string>({"0x14000105c","0x140001063","0x14000106a","0x140001071","0x140001078","0x14000107f"}),"all six real case addresses represented");
    check(graph["switch_tables"][0]["folded_guard_default_targets"]==Json::array({"0x140001086"}),"folded default remains evidence at the real guard");
    bool guardDefault=false,defaultFallthrough=false;
    for(const auto& edge:graph["edges"]) {
        if(edge["source"]=="0x140001030"&&edge["target"]=="0x140001086"&&edge["label"]=="true")guardDefault=true;
        if(edge["source"]=="0x140001086"&&edge["target"]=="0x14000108b"&&edge["label"]=="fallthrough")defaultFallthrough=true;
        check(!(edge["label"]=="switch"&&edge["target"]=="0x140001086"),"folded guard does not create a false machine jump edge");
    }
    check(guardDefault&&defaultFallthrough,"default conditional and epilogue flow preserved");
    std::set<Address> instructionAddresses;
    for(const auto& node:graph["nodes"])for(const auto& instruction:node["instructions"])check(instructionAddresses.insert(address(instruction["address"])).second,"reachable instruction belongs to exactly one block");
    check(architecture->max_instructions==originalInstructions&&architecture->max_jumptable_size==originalTables,"native recovery limits restored");
    check(manualSwitchTargets(session,branch).empty(),"automatic recovery does not create manual overrides");
    auto small=buildControlFlowGraph(session,entry,3);
    check(small["instruction_count"]==3&&small["truncated"]==true,"graph traversal budget enforced");
    check(small["switch_recovery"]["inspected"]==false,"linear prefix avoids decompiler recovery");
    Engine limited;limited.open(fixture);
    callPseudocodeTool(limited,"set_pseudocode_options",{{"address",hex(entry)},{"max_instructions",1000000},{"max_jump_table_entries",65536}});
    auto* limitedArchitecture=limited.nativeArchitecture();
    auto limitedOriginalInstructions=limitedArchitecture->max_instructions,limitedOriginalTables=limitedArchitecture->max_jumptable_size;
    auto bounded=buildControlFlowGraph(limited,entry,14);
    check(bounded["switch_recovery"]["requested_function_analysis_attempted"]==true,"bounded graph reaches indirect jump");
    check(bounded["switch_recovery"]["effective_native_instruction_limit"]==14&&bounded["switch_recovery"]["effective_native_table_limit"]==14,"saved high pseudocode limits cannot raise graph action limits");
    check(bounded["complete"]==false,"14-instruction recovery cannot complete the 26-instruction function");
    check(bounded["switch_tables"].empty(),"instruction-limited native action does not publish partial switch targets");
    check(limitedArchitecture->max_instructions==limitedOriginalInstructions&&limitedArchitecture->max_jumptable_size==limitedOriginalTables,"limited action restores original global limits");
    auto recoveredAfterLimit=buildControlFlowGraph(limited,entry,4096);
    check(recoveredAfterLimit["instruction_count"]==26&&recoveredAfterLimit["complete"]==true,"failed limited action does not poison later full graph recovery");
    Engine largeBudget;largeBudget.open(fixture);
    callPseudocodeTool(largeBudget,"set_pseudocode_options",{{"address",hex(entry)},{"max_instructions",1000000},{"max_jump_table_entries",65536}});
    auto largeGraph=buildControlFlowGraph(largeBudget,entry,20000);
    check(largeGraph["instruction_count"]==26&&largeGraph["complete"]==true,"large traversal budget still requests bounded switch recovery");
    check(largeGraph["switch_tables"].size()==1&&largeGraph["switch_tables"][0]["targets"].size()==6,"large graph has six actual case destinations");
    check(largeGraph["switch_recovery"]["requested_function_analysis_attempted"]==true,"large graph invokes requested-function recovery");
    check(largeGraph["switch_recovery"]["effective_native_instruction_limit"]==4096&&largeGraph["switch_recovery"]["effective_native_table_limit"]==4096,"large graph preserves independent 4096 native recovery caps");
    auto target=address(graph["switch_tables"][0]["targets"][0]);
    callManualTool(session,"define_data",{{"address",hex(target)},{"end",hex(target+1)},{"data_type","byte"}});
    auto excluded=buildControlFlowGraph(session,entry,4096);
    check(excluded["complete"]==false,"manual data prevents claiming a complete switch graph");
    for(const auto& edge:excluded["edges"])check(edge.value("source_provenance",std::string())!="decompiler_recovered_switch","invalidated recovered table withheld atomically");
    std::atomic_bool cancelled=true;session.setCancellation(&cancelled);
    bool rejected=false;try{buildControlFlowGraph(session,entry,4096);}catch(const std::exception&){rejected=true;}
    check(rejected,"cancelled graph rejected");
    std::cout<<"PASS: "<<checks<<" recovered switch graph checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<'\n';return 1;}}
