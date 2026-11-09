#include "core.hpp"
#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "database.hh"
#include "funcdata.hh"
#include "type.hh"
#include "printlanguage.hh"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <cctype>
#include "session.hpp"
#include "feature_project.hpp"
#include <set>
#include "feature_decode.hpp"
#include <unordered_map>
#include "feature_advanced_type_library.hpp"
#include "feature_advanced_manual.hpp"
#include "feature_advanced_pseudocode.hpp"
#include "feature_advanced_sdk.hpp"
#include "feature_auto_imports.hpp"
namespace scratcher {
namespace {
std::once_flag libraryOnce;
Json pseudocodeResult(Address va,const std::string& code,bool cached,double elapsed){
 Json signals=Json::array();
 for(const char* pattern:{"halt_baddata","Bad instruction","bad instruction","unimplemented instruction","Could not recover jumptable","Too many instructions"})if(code.find(pattern)!=std::string::npos)signals.push_back(pattern);
 return {{"address",hex(va)},{"code",code},{"cached",cached},{"elapsed_ms",elapsed},{"decompilation_completed",true},{"semantic_analysis_complete",false},{"warning_signals",signals},{"quality_assessment","Text warning signals only; no behavioral equivalence or type accuracy established"}};
}
class Image : public ghidra::LoadImage {
 const Binary& binary_;
public:
 explicit Image(const Binary& b):LoadImage(pathText(b.path)),binary_(b){}
 void loadFill(ghidra::uint1* ptr,ghidra::int4 size,const ghidra::Address& addr) override{
  try{binary_.load(addr.getOffset(),ptr,(size_t)size);}catch(const std::exception&e){throw ghidra::DataUnavailError(e.what());}
 }
 std::string getArchType()const override{return binary_.language;}
 void adjustVma(long)override{throw ghidra::LowlevelError("Image rebasing is not supported");}
 void getReadonly(ghidra::RangeList& list)const override{for(auto&s:binary_.sections)if(!s.writable&&s.memorySize)list.insertRange(space_,s.va,s.va+s.memorySize-1);}
 ghidra::AddrSpace* space_=nullptr;
};
class Assembly : public ghidra::AssemblyEmit {
public:
 std::string mnemonic,operands;
 void dump(const ghidra::Address&,const std::string&m,const std::string&o)override{mnemonic=m;operands=o;}
};
class IndexedScope : public ghidra::ScopeInternal {
 const Binary& binary_;ghidra::Architecture* architecture_;
public:
 IndexedScope(const Binary& binary,ghidra::Architecture* architecture):ScopeInternal(0,"",architecture),binary_(binary),architecture_(architecture){}
 ghidra::Funcdata* findFunction(const ghidra::Address& addr)const override {
  if(auto* function=ScopeInternal::findFunction(addr))return function;
  if(addr.getSpace()!=architecture_->getDefaultCodeSpace())return nullptr;
  auto va=addr.getOffset();auto found=std::lower_bound(binary_.functions.begin(),binary_.functions.end(),va,[](const Function&f,Address value){return f.va<value;});
  if(found==binary_.functions.end()||found->va!=va||!binary_.analysisCode(va))return nullptr;
  return const_cast<IndexedScope*>(this)->addFunction(addr,found->name)->getFunction();
 }
};
}
class NativeArchitecture : public ghidra::SleighArchitecture {
 const Binary& binary_;
protected:
 ghidra::Scope* buildDatabase(ghidra::DocumentStorage&)override{symboltab=new ghidra::Database(this,true);auto*scope=new IndexedScope(binary_,this);symboltab->attachScope(scope,nullptr);return scope;}
 void buildLoader(ghidra::DocumentStorage&)override{collectSpecFiles(*errorstream);loader=new Image(binary_);}
 void resolveArchitecture()override{archid=getTarget();SleighArchitecture::resolveArchitecture();}
 void postSpecFile()override{ghidra::Architecture::postSpecFile();static_cast<Image*>(loader)->space_=getDefaultCodeSpace();}
 ghidra::Translate* buildTranslator(ghidra::DocumentStorage&)override{ownsTranslator=true;return new ghidra::Sleigh(loader,context);}
 void buildCoreTypes(ghidra::DocumentStorage&store)override{
  SleighArchitecture::buildCoreTypes(store);
  auto integer=[this](const char*name,int size,ghidra::type_metatype kind){types->setCoreType(name,size,kind,false);};
  integer("int",4,ghidra::TYPE_INT);integer("uint",4,ghidra::TYPE_UINT);integer("short",2,ghidra::TYPE_INT);integer("ushort",2,ghidra::TYPE_UINT);
  int longSize=(binary_.format=="ELF"||binary_.format.starts_with("Mach-O"))&&binary_.bits==64?8:4;
  integer("long",longSize,ghidra::TYPE_INT);integer("ulong",longSize,ghidra::TYPE_UINT);integer("__int64",8,ghidra::TYPE_INT);integer("uint64_t",8,ghidra::TYPE_UINT);integer("schar",1,ghidra::TYPE_INT);integer("uchar",1,ghidra::TYPE_UINT);
  integer("size_t",binary_.bits/8,ghidra::TYPE_UINT);integer("int8_t",1,ghidra::TYPE_INT);integer("int16_t",2,ghidra::TYPE_INT);integer("int32_t",4,ghidra::TYPE_INT);integer("int64_t",8,ghidra::TYPE_INT);integer("uint8_t",1,ghidra::TYPE_UINT);integer("uint16_t",2,ghidra::TYPE_UINT);integer("uint32_t",4,ghidra::TYPE_UINT);
  types->setCoreType("float",4,ghidra::TYPE_FLOAT,false);types->setCoreType("double",8,ghidra::TYPE_FLOAT,false);types->cacheCoreTypes();
 }
public:
 NativeArchitecture(const Binary& b,std::ostream& log):SleighArchitecture(pathText(b.path),b.language,&log),binary_(b){}
};
Engine::Engine(){log_=new std::ostringstream();resetFeatures();}
Engine::~Engine(){arch_.reset();delete log_;}
ghidra::Architecture* Engine::nativeArchitecture(){ensureArchitecture();return arch_.get();}
void Engine::invalidateDecompilation(){decompiled_.clear();if(features_){features_->references=nullptr;features_->referenceBudget=0;features_->decoded=Json::object();features_->graphs=Json::object();features_->decodedBytes=features_->graphBytes=0;}}
void Engine::rebuildArchitecture(){arch_.reset();invalidateDecompilation();if(features_){features_->analysisReport=nullptr;features_->analysisBudget=0;}advancedState_.erase("analysis");}
void Engine::require()const{if(!binary_)throw std::runtime_error("Open a binary first");}
Json Engine::open(const std::filesystem::path& path,Address rawBase,int bits){
 auto start=std::chrono::steady_clock::now();auto candidate=std::make_shared<Binary>(path,rawBase,bits);
 for(auto it=runtimeSlots_.begin();it!=runtimeSlots_.end();)if(it->first=="scratcher.sdk"||it->first=="native_debugger")++it;else it=runtimeSlots_.erase(it);advancedState_=Json::object();arch_.reset();binary_=std::move(candidate);resetFeatures();decompiled_.clear();strings_.clear();stringsReady_=false;log_->str("");
 auto result=binary_->info();result["load_ms"]=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();notifySdkEvent(*this,"binary_opened",result);return result;
}
void Engine::ensureArchitecture(){
 require();if(arch_)return;
 try{
  std::call_once(libraryOnce,[]{auto specs=executableDir()/"data"/"languages";if(!std::filesystem::exists(specs/"x86-64.sla"))throw std::runtime_error("Missing processor data beside executable");ghidra::startDecompilerLibrary(std::vector<std::string>{pathText(specs)});});
  auto candidate=std::make_unique<NativeArchitecture>(*binary_,*log_);ghidra::DocumentStorage storage;candidate->init(storage);candidate->allacts.setCurrent("decompile");candidate->max_instructions=50000;
  arch_=std::move(candidate);restoreTypeLibrary(*this);installImportSemantics(*this,arch_.get());
 }catch(const ghidra::LowlevelError&e){throw std::runtime_error(e.explain);}
}
std::vector<Instruction> Engine::disassemble(Address va,size_t count){
 if(count>10000)throw std::runtime_error("Instruction count exceeds 10000");
 require();const auto key=hex(va)+":"+std::to_string(count);
 if(features_->decoded.contains(key)){std::vector<Instruction> rows;for(auto& row:features_->decoded[key])rows.push_back({address(row.at("address")),row.at("length"),row.at("mnemonic"),row.at("operands"),row.at("bytes"),row.value("prefixes",std::string())});return rows;}
 auto rows=decodeListing(*binary_,va,count,[this]{return cancelled();});Json cached=Json::array();for(auto& row:rows)cached.push_back({{"address",hex(row.va)},{"length",row.length},{"mnemonic",row.mnemonic},{"operands",row.operands},{"bytes",row.bytes},{"prefixes",row.prefixes}});
 auto bytes=cached.dump().size();if(bytes<=8*1024*1024){if(features_->decodedBytes+bytes>8*1024*1024){features_->decoded=Json::object();features_->decodedBytes=0;}features_->decoded[key]=std::move(cached);features_->decodedBytes+=bytes;}return rows;
}
Json Engine::decompile(Address va){
 require();if(!binary_->analysisCode(va))throw std::runtime_error("Address is not in executable memory");auto start=std::chrono::steady_clock::now();if(auto it=decompiled_.find(va);it!=decompiled_.end())return pseudocodeResult(va,it->second,true,0);
 ensureArchitecture();
 try{auto addr=ghidra::Address(arch_->getDefaultCodeSpace(),va);auto*scope=arch_->symboltab->getGlobalScope();auto*fn=scope->queryFunction(addr);if(!fn)fn=scope->addFunction(addr,"sub_"+hex(va).substr(2))->getFunction();
  if(fn->isProcStarted())arch_->clearAnalysis(fn);applyPseudocodeOptions(*this,va);arch_->allacts.getCurrent()->reset(*fn);arch_->allacts.getCurrent()->perform(*fn);if(features_){features_->graphs=Json::object();features_->graphBytes=0;}std::ostringstream code;arch_->print->setOutputStream(&code);arch_->print->docFunction(fn);arch_->print->setOutputStream(log_);decompiled_[va]=code.str();
  return pseudocodeResult(va,code.str(),false,std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count());
 }catch(const ghidra::LowlevelError&e){arch_->print->setOutputStream(log_);throw std::runtime_error(e.explain);}
}
Json Engine::analyze(size_t budget,bool fullScan){
 if(budget>1000000)throw std::runtime_error("Analysis budget exceeds 1000000 instructions");require();
 auto analysisStart=std::chrono::steady_clock::now();
 if(fullScan)budget=SIZE_MAX;
 if(cancelled())throw std::runtime_error("Operation cancelled");
 if(!features_->analysisReport.is_null()&&(features_->analysisBudget==budget||features_->analysisReport.value("complete",false))){
  auto report=features_->analysisReport;report["cached"]=true;report["elapsed_ms"]=0;return report;
 }
 std::vector<Function> discovered;auto report=scanDirectCalls(*binary_,budget,discovered,[this]{return cancelled();},fullScan);discovered.erase(std::remove_if(discovered.begin(),discovered.end(),[this](const Function& f){return manuallyDeletedFunction(*this,f.va)||manualClassification(*this,f.va).value_or("undefined")=="data";}),discovered.end());report["functions_added"]=discovered.size();
 if(cancelled())throw std::runtime_error("Operation cancelled");
 if(!discovered.empty()){auto previous=binary_->functions.size();binary_->functions.insert(binary_->functions.end(),std::make_move_iterator(discovered.begin()),std::make_move_iterator(discovered.end()));std::inplace_merge(binary_->functions.begin(),binary_->functions.begin()+previous,binary_->functions.end(),[](auto&a,auto&b){return a.va<b.va;});}
 if(!discovered.empty())invalidateDecompilation();
 report["scan_ms"]=report["elapsed_ms"];report["elapsed_ms"]=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-analysisStart).count();
 features_->analysisReport=report;features_->analysisBudget=budget;notifySdkEvent(*this,"analysis_completed",report);return report;
}
Json Engine::listFunctions(size_t offset,size_t limit,const std::string&q)const{require();if(limit>10000)throw std::runtime_error("Limit exceeds 10000");Json rows=Json::array();size_t n=0;for(auto&f:binary_->functions)if(q.empty()||f.name.find(q)!=std::string::npos||hex(f.va).find(q)!=std::string::npos){if(n++>=offset&&rows.size()<limit)rows.push_back({{"address",hex(f.va)},{"end",hex(f.end)},{"name",f.name},{"source",f.source}});}return {{"items",rows},{"total",n},{"offset",offset}};}
Json Engine::listStrings(size_t offset,size_t limit,const std::string&q){require();if(limit>10000)throw std::runtime_error("Limit exceeds 10000");if(!stringsReady_){strings_=binary_->strings();stringsReady_=true;}Json rows=Json::array();size_t n=0;for(auto&s:strings_)if(q.empty()||s.text.find(q)!=std::string::npos){if(n++>=offset&&rows.size()<limit)rows.push_back({{"address",hex(s.va)},{"file_offset",s.offset},{"text",s.text}});}return {{"items",rows},{"total",n},{"offset",offset},{"scan_limit",100000}};}
Json Engine::readBytes(Address va,size_t count){require();if(count>65536)throw std::runtime_error("Read exceeds 65536 bytes");std::vector<uint8_t> data(count);binary_->load(va,data.data(),count);std::ostringstream out;for(auto b:data)out<<std::hex<<std::setfill('0')<<std::setw(2)<<(unsigned)b;return {{"address",hex(va)},{"hex",out.str()},{"count",count}};}
Json Engine::rename(Address va,const std::string& name){require();if(name.empty()||name.size()>128||!std::all_of(name.begin(),name.end(),[](unsigned char c){return std::isalnum(c)||c=='_';})||std::isdigit((unsigned char)name[0]))throw std::runtime_error("Use a C identifier up to 128 characters");auto it=std::find_if(binary_->functions.begin(),binary_->functions.end(),[&](auto&f){return f.va==va;});if(it==binary_->functions.end())throw std::runtime_error("Function is not indexed");if(arch_){auto*scope=arch_->symboltab->getGlobalScope();auto*fn=scope->queryFunction(ghidra::Address(arch_->getDefaultCodeSpace(),va));if(fn)scope->renameSymbol(fn->getSymbol(),name);}if(auto signature=features_->signatures.find(va);signature!=features_->signatures.end()){auto at=signature->second.find(it->name);if(at!=std::string::npos)signature->second.replace(at,it->name.size(),name);}it->name=name;invalidateDecompilation();return {{"address",hex(va)},{"name",name}};}
Json Engine::analysisState()const{
 require();Json code=Json::object();size_t bytes=0;bool truncated=false;for(auto&[va,text]:decompiled_){if(bytes+text.size()>16*1024*1024){truncated=true;break;}code[hex(va)]=text;bytes+=text.size();}
 return {{"cache_version",1},{"pseudocode",code},{"pseudocode_truncated",truncated},{"decoded",features_->decoded},{"graphs",features_->graphs},{"references",features_->references},{"reference_budget",features_->referenceBudget},{"linear_report",features_->analysisReport},{"linear_budget",features_->analysisBudget}};
}
void Engine::restoreAnalysisState(const Json& state){
 require();if(!state.is_object()||state.value("cache_version",0)!=1)throw std::runtime_error("Unsupported analysis cache");
 const auto& code=state.at("pseudocode");if(!code.is_object()||code.dump().size()>20*1024*1024)throw std::runtime_error("Invalid pseudocode cache");
 std::map<Address,std::string> restored;for(auto it=code.begin();it!=code.end();++it){auto va=address(it.key());if(!binary_->analysisCode(va)||!it->is_string())throw std::runtime_error("Invalid pseudocode cache address");restored[va]=it->get<std::string>();}
 const auto decoded=state.value("decoded",Json::object()),graphs=state.value("graphs",Json::object());if(!decoded.is_object()||!graphs.is_object()||decoded.dump().size()>8*1024*1024||graphs.dump().size()>8*1024*1024)throw std::runtime_error("Invalid instruction or graph cache");
 for(auto it=decoded.begin();it!=decoded.end();++it){auto colon=it.key().find(':');if(colon==std::string::npos)throw std::runtime_error("Invalid cache key");address(it.key().substr(0,colon));size_t used=0;auto count=std::stoull(it.key().substr(colon+1),&used);if(used!=it.key().size()-colon-1||count>10000||!it->is_array()||it->size()>count)throw std::runtime_error("Invalid decoded cache");for(auto& row:*it){auto va=address(row.at("address"));int length=row.at("length");if(!binary_->section(va)||length<1||length>16||!row.at("mnemonic").is_string()||!row.at("operands").is_string()||!row.at("bytes").is_string())throw std::runtime_error("Invalid cached instruction");}}
 for(auto& graph:graphs)if(!graph.is_object()||!graph.contains("nodes")||!graph["nodes"].is_array()||!graph.contains("edges")||!graph["edges"].is_array())throw std::runtime_error("Invalid cached graph");
 auto refs=state.value("references",Json());if(!refs.is_null()&&(!refs.is_object()||!refs.contains("items")||!refs["items"].is_array()))throw std::runtime_error("Invalid reference cache");
 auto report=state.value("linear_report",Json());if(!report.is_null()&&!report.is_object())throw std::runtime_error("Invalid linear scan cache");
 decompiled_=std::move(restored);features_->decoded=decoded;features_->graphs=graphs;features_->decodedBytes=decoded.dump().size();features_->graphBytes=graphs.dump().size();features_->references=refs;features_->referenceBudget=state.value("reference_budget",size_t(0));features_->analysisReport=report;features_->analysisBudget=state.value("linear_budget",size_t(0));
}
Json Engine::saveProject(const std::filesystem::path& path)const{
 require();Json functions=Json::array();for(auto&f:binary_->functions)functions.push_back({{"address",hex(f.va)},{"end",hex(f.end)},{"name",f.name},{"source",f.source}});
 Json sections=Json::array();for(auto&s:binary_->sections)sections.push_back({{"name",s.name},{"va",hex(s.va)},{"memory_size",s.memorySize},{"offset",s.offset},{"file_size",s.fileSize},{"executable",s.executable},{"writable",s.writable}});
 Json project={{"scratcher_project",3},{"binary",pathText(binary_->path)},{"fingerprint",binaryFingerprint(*binary_)},{"raw_base",hex(binary_->base)},{"bits",binary_->bits},{"language",binary_->language},{"functions",functions},{"sections",sections},{"workspace",workspaceState()},{"analysis_cache",analysisState()}};
 writeProjectAtomic(path,project,binary_->path);return {{"path",pathText(std::filesystem::absolute(path))}};
}
Json Engine::loadProject(const std::filesystem::path& path){
 auto project=readProjectFile(path);int version=project.at("scratcher_project");if(version<1||version>3)throw std::runtime_error("Unsupported project version");auto binaryPath=std::filesystem::u8path(project.at("binary").get<std::string>());auto rawBase=address(project.at("raw_base"));int bits=project.at("bits");
 Engine candidate;candidate.open(binaryPath,rawBase,bits);if(version==3){auto language=project.value("language",candidate.binary_->language);if(language.size()>128||language.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_.")!=std::string::npos)throw std::runtime_error("Invalid processor language");candidate.binary_->language=language;}if(version>=2)validateBinaryFingerprint(*candidate.binary_,project.at("fingerprint"));else if(project.at("size")!=candidate.binary_->size())throw std::runtime_error("Project binary changed");
 if(version==3){const auto& saved=project.at("sections");if(!saved.is_array()||saved.size()!=candidate.binary_->sections.size())throw std::runtime_error("Invalid section map");for(size_t i=0;i<saved.size();++i){auto& s=candidate.binary_->sections[i];auto& j=saved[i];if(address(j.at("va"))!=s.va||j.at("memory_size")!=s.memorySize||j.at("offset")!=s.offset||j.at("file_size")!=s.fileSize)throw std::runtime_error("Project section mappings changed");s.name=j.at("name");s.executable=j.at("executable");s.writable=j.at("writable");}candidate.binary_->functions.clear();}
 if(!project.at("functions").is_array()||project["functions"].size()>1000000)throw std::runtime_error("Invalid project function index");
 std::unordered_map<Address,size_t> restoredIndex;restoredIndex.reserve(candidate.binary_->functions.size()+project["functions"].size());for(size_t i=0;i<candidate.binary_->functions.size();++i)restoredIndex[candidate.binary_->functions[i].va]=i;
 for(auto&f:project.at("functions")){auto va=address(f.at("address"));if(!candidate.binary_->analysisCode(va)){if(version==3)throw std::runtime_error("Invalid project function address");continue;}auto end=address(f.at("end"));auto name=f.at("name").get<std::string>();if(name.empty()||name.size()>1024||(end!=0&&end<va))throw std::runtime_error("Invalid function in project");auto found=restoredIndex.find(va);if(found==restoredIndex.end()){restoredIndex[va]=candidate.binary_->functions.size();candidate.binary_->functions.push_back({va,end,name,f.at("source")});}else {auto& old=candidate.binary_->functions[found->second];old.name=name;old.end=end;old.source=f.at("source");}}
 std::sort(candidate.binary_->functions.begin(),candidate.binary_->functions.end(),[](auto&a,auto&b){return a.va<b.va;});if(version>=2)candidate.restoreWorkspaceState(project.at("workspace"));if(version==3)candidate.restoreAnalysisState(project.at("analysis_cache"));
 for(auto it=runtimeSlots_.begin();it!=runtimeSlots_.end();)if(it->first=="scratcher.sdk"||it->first=="native_debugger")++it;else it=runtimeSlots_.erase(it);std::swap(binary_,candidate.binary_);std::swap(arch_,candidate.arch_);std::swap(log_,candidate.log_);std::swap(decompiled_,candidate.decompiled_);std::swap(strings_,candidate.strings_);std::swap(stringsReady_,candidate.stringsReady_);std::swap(features_,candidate.features_);std::swap(advancedState_,candidate.advancedState_);return binary_->info();
}
}
