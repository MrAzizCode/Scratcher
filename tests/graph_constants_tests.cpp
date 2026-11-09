#include "feature_graph.hpp"
#include "feature_advanced_manual.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>

using namespace scratcher;
namespace {
int checks=0;
void check(bool ok,const char* message){++checks;if(!ok)throw std::runtime_error(message);}
void fixture(Engine& session,const std::filesystem::path& root,const std::string& name,std::initializer_list<uint8_t> code){
    std::vector<uint8_t> bytes(256,0xcc);std::copy(code.begin(),code.end(),bytes.begin());bytes[0x30]=0xc3;bytes[0x40]=0xc3;
    uint64_t target=0x1030;std::memcpy(bytes.data()+0x80,&target,8);target=0x1040;std::memcpy(bytes.data()+0x88,&target,8);
    auto path=root/(name+".bin");{std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}session.open(path);
    session.editableBinary()->sections.front().writable=false;
}
const Json* transfer(const Json& graph,const char* target){for(const auto& edge:graph["edges"])if(edge["label"]=="jump"&&edge["target"]==target&&edge.contains("source_provenance"))return &edge;return nullptr;}
void candidate(const Json& graph,const char* target,const char* message){auto* edge=transfer(graph,target);check(edge!=nullptr,message);check((*edge)["path_local"]==true&&(*edge)["residual_unknown"]==true&&(*edge)["all_paths_proven"]==false,"constant edge preserves residual paths");check(graph["complete"]==false&&graph["semantic_analysis_complete"]==false,"constant candidate does not imply complete graph");}
}
int main(){try{
    auto root=executableDir()/"graph-constants-fixtures";std::filesystem::create_directories(root);Engine session;
    fixture(session,root,"mov",{0xb8,0x30,0x10,0,0,0xff,0xe0});
    auto graph=buildControlFlowGraph(session,0x1000);candidate(graph,"0x1030","MOV EAX immediate resolves register JMP");
    check((*transfer(graph,"0x1030"))["source_provenance"]=="straight_line_register_constant_candidate","register source distinct from direct edge");
    fixture(session,root,"lea",{0x48,0x8d,0x05,0x29,0,0,0,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);candidate(graph,"0x1030","RIP-relative LEA resolves register JMP");
    fixture(session,root,"copy",{0xb8,0x30,0x10,0,0,0x89,0xc1,0xff,0xe1});
    graph=buildControlFlowGraph(session,0x1000);candidate(graph,"0x1030","register copy propagates target");
    fixture(session,root,"partial",{0xb8,0x30,0x10,0,0,0xb0,1,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"partial write kills whole register fact");
    fixture(session,root,"unknown_write",{0xb8,0x30,0x10,0,0,0x31,0xc8,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"unknown arithmetic write kills target");
    fixture(session,root,"call_kill",{0xb8,0x30,0x10,0,0,0xe8,0x26,0,0,0,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"calls clear incoming register facts");
    fixture(session,root,"register_call",{0xb8,0x30,0x10,0,0,0xff,0xd0,0xc3});
    graph=buildControlFlowGraph(session,0x1000);check(graph["calls"].size()==1&&graph["calls"][0]["target"]=="0x1030","register CALL input resolved before observe");
    check(graph["calls"][0]["indirect"]==true&&graph["calls"][0]["residual_unknown"]==true,"resolved CALL retains indirect candidate provenance");
    fixture(session,root,"readonly",{0x48,0x8b,0x05,0x79,0,0,0,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);candidate(graph,"0x1030","readonly pointer MOV then JMP");
    check((*transfer(graph,"0x1030"))["readonly_pointer_slot"]=="0x1080","readonly pointer provenance records slot");
    fixture(session,root,"fixed_readonly",{0xff,0x25,0x7a,0,0,0});
    graph=buildControlFlowGraph(session,0x1000);check(transfer(graph,"0x1030")&&(*transfer(graph,"0x1030"))["source_provenance"]=="fixed_readonly_memory_pointer","fixed RIP pointer transfer is distinct from path-local register evidence");
    check((*transfer(graph,"0x1030"))["path_local"]==false&&graph["complete"]==true,"fixed readonly pointer has no register-join dependence");
    fixture(session,root,"mutable",{0x48,0x8b,0x05,0x79,0,0,0,0xff,0xe0});session.editableBinary()->sections.front().writable=true;
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"mutable pointer slot cannot resolve");
    fixture(session,root,"iat",{0x48,0x8b,0x05,0x79,0,0,0,0xff,0xe0});session.editableBinary()->imports.push_back({0x1080,"test.dll","test"});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"IAT remains unknown despite readonly section");
    fixture(session,root,"manual_target_data",{0xb8,0x30,0x10,0,0,0xff,0xe0});
    callManualTool(session,"define_data",{{"address","0x1030"},{"end","0x1031"},{"data_type","byte"}});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"manual data destination cannot resolve");
    fixture(session,root,"manual_switch",{0xb8,0x30,0x10,0,0,0xff,0xe0});
    callManualTool(session,"define_switch_table",{{"address","0x1005"},{"table","0x1088"},{"entry_size",8},{"count",1}});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"manual switch overrides inferred register constant");
    check(graph["edges"].size()==1&&graph["edges"][0]["target"]=="0x1040"&&graph["edges"][0]["source_provenance"]=="manual_switch","manual switch destination authoritative");
    // The branch bypasses MOV and enters its JMP. The first visited path's
    // constant must never become an all-path proof after the join is found.
    fixture(session,root,"diamond_bypass",{0x85,0xc9,0x74,0x05,0xb8,0x30,0x10,0,0,0xff,0xe0});
    graph=buildControlFlowGraph(session,0x1000);check(!transfer(graph,"0x1030"),"known diamond join clears fallthrough facts");check(graph["complete"]==false,"diamond bypass remains unresolved");
    // Initially unseen backward incoming edge reaches the middle of a trace
    // that has already emitted a candidate. Preserve its residual unknown.
    fixture(session,root,"backward_join",{0x85,0xc9,0x74,0x04,0xeb,0x12,0xcc,0xcc,0xb8,0x30,0x10,0,0,0xff,0xe0,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xeb,0xf3});
    graph=buildControlFlowGraph(session,0x1000);check(graph["complete"]==false,"backward incoming join never completes constant proof");
    check(transfer(graph,"0x1030")&&(*transfer(graph,"0x1030"))["later_incoming_join"]==true,"late backward join explicitly marks first-path candidate");
    for(const auto& edge:graph["edges"])if(edge.contains("source_provenance")&&edge["source_provenance"]=="straight_line_register_constant_candidate")check(edge["residual_unknown"]==true,"late join candidate keeps residual edge");
    std::cout<<"PASS: "<<checks<<" graph constant checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
