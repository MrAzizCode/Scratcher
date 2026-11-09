#include "feature_graph.hpp"
#include "feature_project.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>

using namespace scratcher;
namespace {
int checks=0;
void check(bool condition,const char* label){++checks;if(!condition)throw std::runtime_error(label);}
void fixture(Engine& session,const std::filesystem::path& root,const std::string& name,std::initializer_list<uint8_t> code){
    auto file=root/(name+".bin");std::vector<uint8_t> bytes(64,0x90);std::copy(code.begin(),code.end(),bytes.begin());
    {std::ofstream out(file,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));}
    session.open(file);
}
const Json& node(const Json& graph,const std::string& id){for(const auto& row:graph.at("nodes"))if(row.at("id")==id)return row;throw std::runtime_error("Missing graph node");}
bool edge(const Json& graph,const std::string& from,const std::string& to,const std::string& label){for(const auto& item:graph.at("edges"))if(item.at("source")==from&&item.at("target")==to&&item.at("label")==label)return true;return false;}
}
int main(){try {
    auto root=executableDir()/"graph-fixtures";std::filesystem::create_directories(root);Engine session;
    fixture(session,root,"diamond",{0x85,0xc0,0x74,0x04,0x31,0xc0,0xeb,0x02,0xb0,0x01,0xc3});
    auto graph=buildControlFlowGraph(session,0x1000);
    check(graph["nodes"].size()==4,"diamond basic block count");
    check(graph["instruction_count"]==6,"diamond reachable instruction count");
    check(edge(graph,"0x1000","0x1008","true"),"conditional true edge");
    check(edge(graph,"0x1000","0x1004","false"),"conditional false edge");
    check(edge(graph,"0x1004","0x100a","jump"),"unconditional edge");
    check(edge(graph,"0x1008","0x100a","fallthrough"),"join splits prior trace");
    check(node(graph,"0x100a")["exit"]=="return","return exit");
    check(graph["complete"]==true&&graph["truncated"]==false,"complete diamond");
    fixture(session,root,"loop",{0x31,0xc0,0xff,0xc0,0x83,0xf8,0x03,0x7c,0xf9,0xc3});
    graph=buildControlFlowGraph(session,0x1000);
    check(graph["nodes"].size()==3,"loop basic block count");
    check(edge(graph,"0x1002","0x1002","true"),"loop backward branch");
    check(node(graph,"0x1002")["instructions"].size()==3,"loop block instruction grouping");
    fixture(session,root,"call",{0xe8,0x0b,0,0,0,0xc3});
    graph=buildControlFlowGraph(session,0x1000);
    check(graph["instruction_count"]==2,"callee not traversed");
    check(graph["calls"].size()==1&&graph["calls"][0]["target"]=="0x1010","direct call recorded");
    check(graph["nodes"].size()==1,"call remains in caller block");
    fixture(session,root,"indirect",{0xff,0x25,0x34,0x12,0,0});
    graph=buildControlFlowGraph(session,0x1000);
    check(graph["edges"].empty(),"indirect displacement is not a target");
    check(node(graph,"0x1000")["exit"]=="indirect_jump","indirect jump exit");
    check(graph["complete"]==false&&graph["truncated"]==false,"unresolved indirect graph");
    fixture(session,root,"overlap",{0xeb,0xff});
    graph=buildControlFlowGraph(session,0x1000);
    check(graph["issues"].size()==1&&graph["issues"][0]["reason"]=="overlapping_target","overlapping target rejected");
    fixture(session,root,"bounded",{0x90,0x90,0x90,0x90,0xc3});
    graph=buildControlFlowGraph(session,0x1000,3);
    check(graph["truncated"]==true&&graph["instruction_count"]==3,"instruction budget bounds traversal");
    check(graph["edges"][0]["reason"]=="instruction_budget","budget edge reason");
    bool rejected=false;try{buildControlFlowGraph(session,0x1000,0);}catch(const std::exception&){rejected=true;}
    check(rejected,"zero instruction budget rejected");
    fixture(session,root,"boundary",{0xe9,0x0b,0,0,0});
    auto project=root/"boundary.scratcher";session.saveProject(project);Json saved;
    saved=readProjectFile(project);
    saved["functions"].push_back({{"address","0x1010"},{"end","0x1020"},{"name","other"},{"source","test"}});
    writeProjectAtomic(project,saved,session.binary()->path);
    session.loadProject(project);graph=buildControlFlowGraph(session,0x1000);
    check(graph["instruction_count"]==1,"other function is not traversed");
    check(graph["edges"][0]["external"]==true&&graph["edges"][0]["reason"]=="function_boundary","external tail target recorded");
    std::cout<<"PASS: "<<checks<<" control-flow graph checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
