#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <sstream>
#include <cstring>
#include <atomic>
#include "json.hpp"
namespace ghidra { class Architecture; }
namespace scratcher {
using Json=nlohmann::json;
using Address=uint64_t;
std::string hex(Address value);
Address address(const Json& value);
std::string pathText(const std::filesystem::path& path);
std::filesystem::path executableDir();
struct Section { std::string name; Address va=0; uint64_t memorySize=0,offset=0,fileSize=0; bool executable=false,writable=false; };
struct Function { Address va=0,end=0; std::string name,source; };
struct Import { Address va=0; std::string module,name; };
struct String { Address va=0,offset=0; std::string text; };
class Binary {
 void* file_=nullptr; void* mapping_=nullptr; const uint8_t* bytes_=nullptr; uint64_t size_=0;
 void parsePE(); void parseELF(); void parseMiniDump(); void parseMachO();
public:
 std::filesystem::path path; std::string format,language; Address base=0,entry=0; int bits=64;
 std::vector<Section> sections; std::vector<Function> functions; std::vector<Import> imports;
 Json peMetadata=Json::object();
 // Candidate code regions established by validated loader metadata. Original permissions stay intact.
 std::vector<std::pair<Address,Address>> analysisRanges;
 explicit Binary(const std::filesystem::path& path,Address rawBase=0x1000,int rawBits=64);
 ~Binary(); Binary(const Binary&)=delete; Binary& operator=(const Binary&)=delete;
 uint64_t size() const {return size_;} const uint8_t* bytes()const{return bytes_;}
 bool has(uint64_t off,uint64_t count) const {return off<=size_ && count<=size_-off;}
 void readFileBytes(uint64_t off,uint8_t* out,size_t count)const;
 template<class T> T read(uint64_t off)const { if(!has(off,sizeof(T)))throw std::runtime_error("Truncated executable header"); T v; std::memcpy(&v,bytes_+off,sizeof(T));return v; }
 std::string cstring(uint64_t off,size_t limit=1024)const;
 const Section* section(Address va)const;
 bool executable(Address va)const;
 bool analysisCode(Address va)const {
  if(executable(va))return true;
  for(const auto& range:analysisRanges)if(va>=range.first&&va<range.second)return true;
  return false;
 }
 void load(Address va,uint8_t* out,size_t count)const;
 Address fileToVA(uint64_t off)const;
 std::vector<String> strings(size_t minimum=5,size_t maximum=100000)const;
 Json info()const;
};
struct Instruction { Address va=0; int length=0; std::string mnemonic,operands,bytes,prefixes; };
class NativeArchitecture;
class SessionFeatures;
class Engine {
 std::shared_ptr<Binary> binary_;
 std::unique_ptr<NativeArchitecture> arch_;
 std::map<Address,std::string> decompiled_;
 std::vector<String> strings_; bool stringsReady_=false;
 std::ostringstream* log_=nullptr;
 std::unique_ptr<SessionFeatures> features_;
 std::atomic_bool* cancellation_=nullptr;
 Json advancedState_=Json::object();
 std::map<std::string,std::shared_ptr<void>> runtimeSlots_;
 void ensureArchitecture(); void require()const;
 void resetFeatures();
public:
 Engine(); ~Engine(); Engine(const Engine&)=delete;
 Json open(const std::filesystem::path& path,Address rawBase=0x1000,int bits=64);
 const Binary* binary()const{return binary_.get();}
 Binary* editableBinary(){return binary_.get();}
 Json& advancedState(){return advancedState_;}
 const Json& advancedState()const{return advancedState_;}
 std::map<std::string,std::shared_ptr<void>>& runtimeSlots(){return runtimeSlots_;}
 void rebuildArchitecture();
 Json analysisState()const;
 void restoreAnalysisState(const Json& state);
 ghidra::Architecture* nativeArchitecture();
 void invalidateDecompilation();
 void setCancellation(std::atomic_bool* flag) { cancellation_=flag; }
 bool cancelled()const { return cancellation_ && cancellation_->load(); }
 Json controlFlow(Address va,size_t budget=4096);
 Json crossReferences(Address va,bool outgoing=false,size_t budget=100000);
 Json callGraph(size_t budget=100000);
 Json setComment(Address va,const std::string& text);
 Json setBookmark(Address va,const std::string& name);
 Json removeBookmark(Address va);
 Json setLabel(Address va,const std::string& name);
 Json annotations()const;
 Json setSignature(Address va,const std::string& declaration);
 Json functionTypes(Address va);
 Json setVariableType(Address va,const std::string& name,const std::string& declaration);
 Json searchPattern(const std::string& pattern,size_t offset=0,size_t limit=500);
 Json discoverText(size_t minimum=5,size_t offset=0,size_t limit=500,const std::string& query="");
 Json stagePatch(Address va,const std::string& bytes);
 Json listPatches()const;
 Json removePatch(Address va);
 Json exportPatched(const std::filesystem::path& path);
 Json workspaceState()const;
 void restoreWorkspaceState(const Json& state);
 std::vector<Instruction> disassemble(Address va,size_t count=100);
 Json decompile(Address va);
 Json analyze(size_t instructionBudget=100000,bool fullScan=false);
 Json listFunctions(size_t offset=0,size_t limit=500,const std::string& query="")const;
 Json listStrings(size_t offset=0,size_t limit=500,const std::string& query="");
 Json readBytes(Address va,size_t count);
 Json rename(Address va,const std::string& name);
 Json saveProject(const std::filesystem::path& path)const;
 Json loadProject(const std::filesystem::path& path);
};
class ToolBackend;
class Tools {
 Engine& engine_;
 ToolBackend* backend_=nullptr;
 bool initialized_=false,ready_=false;
 bool resourcesEnabled_=false,promptsEnabled_=false;
public:
 explicit Tools(Engine& engine):engine_(engine){}
 void setBackend(ToolBackend* backend) { backend_=backend; }
 Json localList()const;
 Json list()const;
 void validate(const std::string& name,const Json& args)const;
 void validateLocal(const std::string& name,const Json& args)const;
 Json callLocal(const std::string& name,const Json& args);
 Json call(const std::string& name,const Json& args);
 Json rpc(const Json& request);
};
int runMCP(const std::string& desktopId="");
}
