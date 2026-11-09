#include "feature_advanced_pseudocode.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
using namespace scratcher;
static void check(bool value,const char*message){if(!value)throw std::runtime_error(message);}
static Json call(Engine&e,const char*name,Json args){auto r=callPseudocodeTool(e,name,args);check(r.has_value(),"tool exists");return *r;}
int main(){
 try{
  auto dir=executableDir()/"pseudocode-fixtures";std::filesystem::create_directories(dir);auto path=dir/"controls.bin";
  std::vector<unsigned char> bytes(128,0x90);
  const unsigned char sum[]={0x89,0xf8,0x01,0xf0,0xc3};std::copy(std::begin(sum),std::end(sum),bytes.begin());
  // sub rsp,8; mov rax,rdi; call rax; add rsp,8; ret.
  const unsigned char invoke[]={0x48,0x83,0xec,0x08,0x48,0x89,0xf8,0xff,0xd0,0x48,0x83,0xc4,0x08,0xc3};std::copy(std::begin(invoke),std::end(invoke),bytes.begin()+32);
  std::copy(std::begin(sum),std::end(sum),bytes.begin()+64);
  {std::ofstream out(path,std::ios::binary);out.write((const char*)bytes.data(),bytes.size());}
  std::cerr<<"stage: initial signature\n";Engine e;e.open(path);e.setSignature(0x1000,"int sum_values(int left, int right);");
  std::cerr<<"stage: rename\n";call(e,"rename_variable",{{"address","0x1000"},{"name","left"},{"new_name","first"}});
  auto code=e.decompile(0x1000)["code"].get<std::string>();check(code.find("first")!=std::string::npos,"rename changes recovered native symbol");
  auto types=e.functionTypes(0x1000);check(types["parameters"][0]["type"]=="int"&&types["parameters"][0]["size"]==4,"rename preserves type/storage size");
  std::cerr<<"stage: mapping\n";auto mapped=call(e,"get_pseudocode_mapping",{{"address","0x1000"},{"limit",10000}});bool instruction=false;
  for(auto&t:mapped["tokens"])if(!t["instruction_address"].is_null()){instruction=true;auto va=address(t["instruction_address"]);check(va>=0x1000&&va<0x1005,"token maps to actual function instruction");}
  check(instruction,"real instruction mappings exist");check(!mapped["code"].get<std::string>().empty(),"structured output text exists");
  auto page=call(e,"get_pseudocode_mapping",{{"address","0x1000"},{"offset",1},{"limit",2}});check(page["tokens"].size()==2&&page["tokens"][0]["index"]==1,"token pagination");
  bool rejected=false;try{call(e,"rename_variable",{{"address","0x1000"},{"name","first"},{"new_name","right"}});}catch(const std::exception&){rejected=true;}check(rejected,"duplicate variable names rejected");
  std::cerr<<"stage: options\n";auto options=call(e,"set_pseudocode_options",{{"address","0x1000"},{"max_instructions",2048},{"max_jump_table_entries",256},{"flat",true}});check(options["applied"]==true,"limits persisted");
  e.decompile(0x1000);check(call(e,"get_pseudocode_controls",{{"address","0x1000"}})["settings"]["options"]["max_instructions"]==2048,"options retrievable");
  std::cerr<<"stage: call signature\n";e.setSignature(0x1020,"int invoke(uint64_t callback, int value);");
  call(e,"set_call_site_signature",{{"address","0x1020"},{"call_address","0x1027"},{"declaration","int callback(int value);"}});
  auto calls=e.decompile(0x1020)["code"].get<std::string>();check(calls.find("int")!=std::string::npos,"call prototype reaches native output");
  rejected=false;try{call(e,"set_call_site_signature",{{"address","0x1020"},{"call_address","0x1024"},{"declaration","int callback(void);"}});}catch(const std::exception&){rejected=true;}check(rejected,"non-call site rejected");
  std::cerr<<"stage: indirect target\n";call(e,"set_indirect_call_target",{{"address","0x1020"},{"call_address","0x1027"},{"target","0x1040"}});
  auto resolved=e.decompile(0x1020)["code"].get<std::string>();check(resolved.find("sub_1040")!=std::string::npos,"indirect call resolves to actual executable target");
  std::cerr<<"stage: restore\n";auto saved=e.workspaceState();Engine restored;restored.open(path);restored.restoreWorkspaceState(saved);
  check(call(restored,"get_pseudocode_controls",{{"address","0x1020"}})["settings"]["indirect_targets"][0]["target"]=="0x1040","overrides survive workspace roundtrip");
  check(restored.decompile(0x1020)["code"].get<std::string>().find("sub_1040")!=std::string::npos,"persisted override re-applied to new native analysis");
  std::cerr<<"stage: reset\n";call(restored,"reset_pseudocode_controls",{{"address","0x1020"}});check(call(restored,"get_pseudocode_controls",{{"address","0x1020"}})["settings"].empty(),"reset removes persisted overrides");
  check(restored.decompile(0x1020)["code"].get<std::string>().find("sub_1040")==std::string::npos,"reset removes live native overrides");
  check(call(restored,"get_pseudocode_controls",{{"address","0x1000"}})["actions"]["split_variable"]==false,"unsupported split correctly reported");
  check(!callPseudocodeTool(e,"unrelated_tool",Json::object()),"unrelated tools pass through");
  std::cout<<"PASS: pseudocode native token mapping, variable rename, call-site prototypes, indirect targets, limits, persistence, validation\n";return 0;
 }catch(const std::exception&error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
