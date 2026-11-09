#include "feature_auto_imports.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <set>
#include <unordered_map>

namespace scratcher {
namespace {
struct SemanticsState { Json summary; Json entries=Json::array(); };
std::string lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
std::string identifier(std::string s){for(char& c:s)if(!std::isalnum((unsigned char)c)&&c!='_')c='_';if(s.empty())s="imported_function";if(std::isdigit((unsigned char)s[0]))s="import_"+s;return s.substr(0,512);}
std::string declaration(const Import& i,int bits){
 const auto module=lower(i.module);
 const bool windows=module=="kernel32.dll"||module=="kernelbase.dll"||module.starts_with("api-ms-win-core-");
 const bool crt=module=="msvcrt.dll"||module=="ucrtbase.dll"||module.starts_with("api-ms-win-crt-");
 // Names alone are insufficient evidence: a similarly named private export is not a Windows API.
 if(module=="version.dll"&&i.name=="GetFileVersionInfoSizeW")return "uint GetFileVersionInfoSizeW(uint16_t *filename, uint *handle);";
 if(module=="version.dll"&&i.name=="GetFileVersionInfoSizeA")return "uint GetFileVersionInfoSizeA(char *filename, uint *handle);";
 if(windows){
  if(i.name=="LoadLibraryW")return "void *LoadLibraryW(uint16_t *filename);";
  if(i.name=="LoadLibraryA")return "void *LoadLibraryA(char *filename);";
  if(i.name=="FreeLibrary")return "int FreeLibrary(void *module);";
  if(i.name=="GetProcAddress")return "void *GetProcAddress(void *module, char *name);";
  if(i.name=="GetCurrentProcessId")return "uint GetCurrentProcessId(void);";
  if(i.name=="GetCurrentThreadId")return "uint GetCurrentThreadId(void);";
  if(i.name=="GetLastError")return "uint GetLastError(void);";
  if(i.name=="SetLastError")return "void SetLastError(uint error);";
  if(i.name=="Sleep")return "void Sleep(uint milliseconds);";
  if(i.name=="CloseHandle")return "int CloseHandle(void *handle);";
  if(i.name=="VirtualAlloc")return "void *VirtualAlloc(void *address, size_t size, uint allocation_type, uint protection);";
  if(i.name=="VirtualFree")return "int VirtualFree(void *address, size_t size, uint free_type);";
 }
 if(crt){
  if(i.name=="malloc")return "void *malloc(size_t size);";
  if(i.name=="calloc")return "void *calloc(size_t count, size_t size);";
  if(i.name=="realloc")return "void *realloc(void *memory, size_t size);";
  if(i.name=="free")return "void free(void *memory);";
  if(i.name=="memcpy")return "void *memcpy(void *destination, void *source, size_t count);";
  if(i.name=="memmove")return "void *memmove(void *destination, void *source, size_t count);";
  if(i.name=="memset")return "void *memset(void *destination, int value, size_t count);";
  if(i.name=="strlen")return "size_t strlen(char *text);";
 }
 return {};
}
void applyPrototype(ghidra::Architecture* a,ghidra::Funcdata* f,const std::string& text,int bits){
 ghidra::PrototypePieces pieces{};std::istringstream in(text);ghidra::parse_protopieces(pieces,in,a);
 // Windows APIs use stdcall on x86; CRT imports retain the architecture default C convention.
 if(bits==32&&text.find("malloc(")==std::string::npos&&text.find("calloc(")==std::string::npos&&text.find("realloc(")==std::string::npos&&text.find("free(")==std::string::npos&&text.find("memcpy(")==std::string::npos&&text.find("memmove(")==std::string::npos&&text.find("memset(")==std::string::npos&&text.find("strlen(")==std::string::npos){auto it=a->protoModels.find("__stdcall");if(it!=a->protoModels.end())pieces.model=it->second;}
 std::vector<ghidra::ParameterPieces> assigned;pieces.model->assignParameterStorage(pieces,assigned,false);
 f->getFuncProto().setPieces(pieces);
 for(int j=0;j<f->getFuncProto().numParams();++j)f->getFuncProto().getParam(j)->setNameLock(true);
}
// Accept only exact tail jumps, never register-target guesses or arbitrary calls.
Address importStubIat(const Binary& b,Address start,const std::unordered_map<Address,const Import*>& imports){
 Address visited[8]{};
 for(unsigned depth=0;depth<8;++depth){
  if(!b.analysisCode(start)||std::find(visited,visited+depth,start)!=visited+depth)return 0;visited[depth]=start;
  auto* s=b.section(start);if(!s||start-s->va>s->fileSize||s->fileSize-(start-s->va)<6)return 0;
  uint8_t bytes[6];b.load(start,bytes,sizeof(bytes));
  if(bytes[0]==0xff&&bytes[1]==0x25){
   Address iat=0;
   if(b.bits==64){int32_t delta;std::memcpy(&delta,bytes+2,4);if(start>UINT64_MAX-6)return 0;Address next=start+6;if(delta<0){auto magnitude=uint64_t(-int64_t(delta));if(magnitude>next)return 0;iat=next-magnitude;}else{if(uint64_t(delta)>UINT64_MAX-next)return 0;iat=next+uint64_t(delta);}}
   else{uint32_t absolute;std::memcpy(&absolute,bytes+2,4);iat=absolute;}
   return imports.contains(iat)?iat:0;
  }
  if(bytes[0]!=0xe9)return 0;
  int32_t delta;std::memcpy(&delta,bytes+1,4);if(start>UINT64_MAX-5)return 0;Address next=start+5;
  if(delta<0){auto magnitude=uint64_t(-int64_t(delta));if(magnitude>next)return 0;start=next-magnitude;}
  else{if(uint64_t(delta)>UINT64_MAX-next)return 0;start=next+uint64_t(delta);}
 }
 return 0;
}
}
void installImportSemantics(Engine& e,ghidra::Architecture* a){
 if(!a||!e.binary())return;const auto& b=*e.binary();
 auto state=std::make_shared<SemanticsState>();auto start=std::chrono::steady_clock::now();
 size_t installed=0,known=0,thunks=0,stubs=0,skipped=0;Json errors=Json::array();
 if(b.format!="PE"||!b.language.starts_with("x86:")){
  state->summary={{"supported",false},{"reason","Import prototypes currently support PE x86 and x64"},{"import_count",b.imports.size()}};
  e.runtimeSlots()["auto_import_semantics"]=state;return;
 }
 auto* scope=a->symboltab->getGlobalScope();auto* space=a->getDefaultCodeSpace();
 std::unordered_map<Address,const Function*> indexed;indexed.reserve(b.functions.size());for(auto& f:b.functions)indexed.emplace(f.va,&f);
 std::set<Address> iats;for(auto& i:b.imports)iats.insert(i.va);
 std::unordered_map<Address,const Import*> boundImports;
 Address synthetic=space->getHighest()-0x1000; // Private metadata-only addresses, never loaded or executed.
 for(const auto& i:b.imports){
  if(e.cancelled())break;
  try{
   auto* section=b.section(i.va);const size_t width=b.bits/8;
   if(!section||i.va-section->va>=section->fileSize||width>section->fileSize-(i.va-section->va)||i.name.empty()||i.name.size()>512){++skipped;continue;}
   auto iat=ghidra::Address(space,i.va);auto* fn=scope->queryExternalRefFunction(iat);
   if(!fn){
    while(synthetic>0x1000&&(b.section(synthetic)||indexed.contains(synthetic)||iats.contains(synthetic)||scope->queryFunction(ghidra::Address(space,synthetic))))synthetic-=16;
    if(synthetic<=0x1000)throw std::runtime_error("No metadata address available");
    auto ref=ghidra::Address(space,synthetic);synthetic-=16;
    fn=scope->addFunction(ref,identifier(i.name))->getFunction();scope->addExternalRef(iat,ref,identifier(i.name));
   }
   const auto signature=declaration(i,b.bits);if(!signature.empty())applyPrototype(a,fn,signature,b.bits);
   // A file's unresolved delay-IAT value is authoritative only when the loader recorded that same thunk.
   Address pointer=0;b.load(i.va,reinterpret_cast<uint8_t*>(&pointer),width);auto found=indexed.find(pointer);Address thunk=0;
   if(found!=indexed.end()&&found->second->source=="delay import thunk"&&found->second->name=="delay_"+i.name){
    auto at=ghidra::Address(space,pointer);auto* tf=scope->queryFunction(at);if(!tf)tf=scope->addFunction(at,identifier(i.name))->getFunction();
    else scope->renameSymbol(tf->getSymbol(),identifier(i.name));
    if(!signature.empty())applyPrototype(a,tf,signature,b.bits);thunk=pointer;++thunks;
   }
   ++installed;if(!signature.empty())++known;boundImports.emplace(i.va,&i);
   state->entries.push_back({{"iat_address",hex(i.va)},{"module",i.module},{"name",i.name},{"prototype_known",!signature.empty()},{"declaration",signature.empty()?Json(nullptr):Json(signature)},{"delay_thunk",thunk?Json(hex(thunk)):Json(nullptr)},{"evidence","validated PE import metadata"}});
  }catch(const ghidra::LowlevelError& error){++skipped;if(errors.size()<64)errors.push_back({{"iat_address",hex(i.va)},{"error",error.explain}});}
  catch(const std::exception& error){++skipped;if(errors.size()<64)errors.push_back({{"iat_address",hex(i.va)},{"error",error.what()}});}
 }
 // Import jump stubs can be separate from the unresolved delay-load helper.
 // An indexed start and exact encoded IAT target are both required.
 for(const auto& f:b.functions){
  if(e.cancelled())break;
  try{
   const Address iat=importStubIat(b,f.va,boundImports);if(!iat)continue;const auto& i=*boundImports.at(iat);
   auto at=ghidra::Address(space,f.va);auto* fn=scope->queryFunction(at);if(!fn)fn=scope->addFunction(at,identifier(i.name))->getFunction();
   if(f.name.starts_with("sub_")||f.name=="delay_"+i.name)scope->renameSymbol(fn->getSymbol(),identifier(i.name));
   const auto signature=declaration(i,b.bits);if(!signature.empty()&&!fn->getFuncProto().isInputLocked()&&!fn->getFuncProto().isOutputLocked())applyPrototype(a,fn,signature,b.bits);
   ++stubs;state->entries.push_back({{"stub_address",hex(f.va)},{"iat_address",hex(iat)},{"module",i.module},{"name",i.name},{"prototype_known",!signature.empty()},{"evidence","Indexed start with an exact unconditional jump chain to a validated import IAT slot"}});
  }catch(const ghidra::LowlevelError& error){if(errors.size()<64)errors.push_back({{"stub_address",hex(f.va)},{"error",error.explain}});}
  catch(const std::exception& error){if(errors.size()<64)errors.push_back({{"stub_address",hex(f.va)},{"error",error.what()}});}
 }
 state->summary={{"supported",true},{"import_count",b.imports.size()},{"installed",installed},{"known_prototypes",known},{"unknown_prototypes",installed-known},{"delay_thunks",thunks},{"import_jump_stubs",stubs},{"skipped",skipped},{"cancelled",e.cancelled()},{"errors",errors},{"prototype_library","Curated Windows and C runtime signatures matched by module and exact export name"},{"elapsed_ms",std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count()}};
 e.runtimeSlots()["auto_import_semantics"]=std::move(state);
}
Json autoImportTools(){return Json::array({{{"name","get_import_semantics"},{"description","Get native import names, validated delay thunk bindings and the status of known versus unknown prototypes."},{"inputSchema",{{"type","object"},{"properties",{{"offset",{{"type","integer"},{"minimum",0}}},{"limit",{{"type","integer"},{"minimum",1},{"maximum",10000}}}}},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",true},{"destructiveHint",false},{"openWorldHint",false}}}}});}
std::optional<Json> callAutoImportTool(Engine& e,const std::string& name,const Json& args){
 if(name!="get_import_semantics")return std::nullopt;
 const size_t offset=args.value("offset",size_t(0)),limit=args.value("limit",size_t(500));if(!limit||limit>10000)throw std::runtime_error("Import semantics limit must be between 1 and 10000");
 auto* a=e.nativeArchitecture();auto found=e.runtimeSlots().find("auto_import_semantics");if(found==e.runtimeSlots().end()){installImportSemantics(e,a);found=e.runtimeSlots().find("auto_import_semantics");}
 auto state=std::static_pointer_cast<SemanticsState>(found->second);auto result=state->summary;Json items=Json::array();for(size_t j=offset;j<state->entries.size()&&items.size()<limit;++j)items.push_back(state->entries[j]);result["items"]=std::move(items);result["total"]=state->entries.size();result["offset"]=offset;return result;
}
}
