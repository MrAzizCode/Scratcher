#include "feature_auto_imports.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "type.hh"
#include <fstream>
#include <iostream>
using namespace scratcher;
namespace {
void check(bool value,const char* text){if(!value)throw std::runtime_error(text);}
std::filesystem::path fixture(bool direct){
 auto path=executableDir()/(direct?"import-direct.bin":"import-indirect.bin");std::vector<uint8_t> bytes(256,0x90);
 const uint8_t prefix[]={0x48,0x83,0xec,0x28};std::memcpy(bytes.data(),prefix,sizeof(prefix));
 if(direct){bytes[4]=0xe8;int32_t delta=0x1040-0x1009;std::memcpy(bytes.data()+5,&delta,4);const uint8_t suffix[]={0x48,0x83,0xc4,0x28,0xc3};std::memcpy(bytes.data()+9,suffix,sizeof(suffix));bytes[0x40]=0xc3;Address ptr=0x1040;std::memcpy(bytes.data()+0x80,&ptr,8);}
 else{const uint8_t call[]={0xff,0x15,0x76,0,0,0,0x48,0x83,0xc4,0x28,0xc3};std::memcpy(bytes.data()+4,call,sizeof(call));std::fill(bytes.begin()+0x80,bytes.begin()+0x88,0);}
 std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<char*>(bytes.data()),bytes.size());return path;
}
void prepare(Engine& e,const std::filesystem::path& path,const std::string& module,bool direct=false){e.open(path);auto* b=e.editableBinary();b->format="PE";b->language="x86:LE:64:default:windows";b->imports={{0x1080,module,"GetFileVersionInfoSizeW"},{0x1090,"fixture.dll","UnknownFunction"}};if(direct)b->functions.push_back({0x1040,0,"delay_GetFileVersionInfoSizeW","delay import thunk"});}
}
int main(){try{
 auto indirect=fixture(false),direct=fixture(true);
 {
  Engine e;prepare(e,indirect,"VERSION.dll");auto* a=e.nativeArchitecture();installImportSemantics(e,a);
  auto* external=a->symboltab->getGlobalScope()->queryExternalRefFunction(ghidra::Address(a->getDefaultCodeSpace(),0x1080));
  check(external&&external->getName()=="GetFileVersionInfoSizeW","IAT resolves to named external function");check(external->getFuncProto().numParams()==2,"Known API signature has two parameters");check(external->getFuncProto().getOutputType()->getSize()==4,"Windows DWORD size preserved");
  auto unknown=a->symboltab->getGlobalScope()->queryExternalRefFunction(ghidra::Address(a->getDefaultCodeSpace(),0x1090));check(unknown&&!unknown->getFuncProto().isInputLocked()&&!unknown->getFuncProto().isOutputLocked(),"Unknown import remains unlocked instead of guessed");
  auto code=e.decompile(0x1000)["code"].get<std::string>();check(code.find("GetFileVersionInfoSizeW")!=std::string::npos,"Indirect IAT call gets API name in pseudocode");
  auto info=callAutoImportTool(e,"get_import_semantics",{{"limit",1}}).value();check(info["installed"]==2&&info["known_prototypes"]==1&&info["items"].size()==1&&info["total"]==2,"Summary and pagination reflect known and unknown imports");
  installImportSemantics(e,a);check(callAutoImportTool(e,"get_import_semantics",{{"offset",1}})->at("items").size()==1,"Repeated install has stable import mappings");
 }
 {
  Engine e;prepare(e,direct,"version.dll",true);auto* a=e.nativeArchitecture();installImportSemantics(e,a);auto code=e.decompile(0x1000)["code"].get<std::string>();check(code.find("GetFileVersionInfoSizeW")!=std::string::npos,"Validated delay thunk call gets API name");check(code.find("delay_GetFileVersionInfoSizeW")==std::string::npos,"Internal delay thunk prefix not shown to caller");check(callAutoImportTool(e,"get_import_semantics",Json::object())->at("delay_thunks")==1,"Delay thunk binding reported");
 }
 {
  Engine e;prepare(e,indirect,"private.dll");installImportSemantics(e,e.nativeArchitecture());auto info=callAutoImportTool(e,"get_import_semantics",Json::object()).value();check(info["known_prototypes"]==0,"Private same-name export does not get Windows prototype");
  e.editableBinary()->imports.push_back({0x5000,"version.dll","GetFileVersionInfoSizeW"});installImportSemantics(e,e.nativeArchitecture());check(callAutoImportTool(e,"get_import_semantics",Json::object())->at("skipped")==1,"Unmapped IAT excluded");
 }
 // Match the real MSVC delay import layout: caller -> JMP-IAT stub -> delay helper.
 // The jump stub has no delay metadata provenance and must be recognized separately.
 for(bool chained:{false,true}){
  auto path=fixture(true);std::fstream file(path,std::ios::binary|std::ios::in|std::ios::out);
  if(chained){const uint8_t jump[]={0xe9,0x0b,0,0,0};file.seekp(0x40);file.write(reinterpret_cast<const char*>(jump),sizeof(jump));}
  const uint8_t stub[]={0xff,0x25,uint8_t(chained?0x2a:0x3a),0,0,0};file.seekp(chained?0x50:0x40);file.write(reinterpret_cast<const char*>(stub),sizeof(stub));file.close();
  Engine e;prepare(e,path,"version.dll",true);e.editableBinary()->functions.back().source="direct call";e.editableBinary()->functions.back().name="sub_1040";
  installImportSemantics(e,e.nativeArchitecture());auto result=e.decompile(0x1000);auto code=result["code"].get<std::string>();check(code.find("GetFileVersionInfoSizeW")!=std::string::npos,"Indexed exact JMP-IAT stub resolves in pseudocode");check(code.find("sub_1040")==std::string::npos,"Direct caller loses anonymous import stub name");
  check(callAutoImportTool(e,"get_import_semantics",Json::object())->at("import_jump_stubs")==1,"Exact jump stub recovery reported");
 }
 {
  auto path=fixture(true);std::fstream file(path,std::ios::binary|std::ios::in|std::ios::out);const uint8_t stub[]={0xff,0x25,0x80,0x10,0,0};file.seekp(0x40);file.write(reinterpret_cast<const char*>(stub),sizeof(stub));file.close();
  Engine e;e.open(path,0x1000,32);auto* b=e.editableBinary();b->format="PE";b->language="x86:LE:32:default:windows";b->imports={{0x1080,"version.dll","GetFileVersionInfoSizeW"}};b->functions.push_back({0x1040,0,"sub_1040","direct call"});
  auto* a=e.nativeArchitecture();installImportSemantics(e,a);auto* f=a->symboltab->getGlobalScope()->queryFunction(ghidra::Address(a->getDefaultCodeSpace(),0x1040));check(f&&f->getName()=="GetFileVersionInfoSizeW"&&f->getFuncProto().numParams()==2,"x86 absolute JMP-IAT stub matches");check(f->getFuncProto().getModelName()=="__stdcall","x86 Windows API uses stdcall");
 }
 std::filesystem::remove(indirect);std::filesystem::remove(direct);std::cout<<"PASS: import IAT labels, native prototypes, unknown signature preservation, validated delay thunks, pagination and malformed mappings\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
