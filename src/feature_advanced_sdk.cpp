#include "feature_advanced_sdk.hpp"
#include "plugin_api.h"
#include <windows.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <regex>
#include <set>

namespace scratcher {
namespace {
constexpr size_t maxResult=4*1024*1024;
thread_local unsigned sdkDepth=0;
struct DepthGuard {DepthGuard(){if(sdkDepth>=8)throw std::runtime_error("Extension recursion exceeds eight calls");++sdkDepth;}~DepthGuard(){--sdkDepth;}};
std::string boundedText(const char* text,size_t max,const char* field){if(!text)throw std::runtime_error(std::string("Missing plugin ")+field);size_t n=0;while(n<=max&&text[n])++n;if(n>max)throw std::runtime_error(std::string("Plugin ")+field+" exceeds limit");return std::string(text,n);}
void checkSchema(const Json& schema,size_t depth=0){
 if(depth>16)throw std::runtime_error("Extension schema exceeds sixteen nesting levels");if(schema.is_boolean())return;if(!schema.is_object())throw std::runtime_error("Extension schema nodes must be objects or booleans");
 static const std::set<std::string> keys={"type","title","description","properties","required","additionalProperties","items","minItems","maxItems","uniqueItems","minLength","maxLength","pattern","format","enum","const","oneOf","anyOf","allOf","minProperties","maxProperties","minimum","maximum","exclusiveMinimum","exclusiveMaximum","default","$schema"};
 for(auto it=schema.begin();it!=schema.end();++it)if(!keys.contains(it.key()))throw std::runtime_error("Unsupported extension schema keyword: "+it.key());
 if(schema.contains("type")){auto valid=[](const Json& t){return t.is_string()&&(t=="object"||t=="array"||t=="string"||t=="number"||t=="integer"||t=="boolean"||t=="null");};const auto& t=schema["type"];if(t.is_array()){if(t.empty()||t.size()>7)throw std::runtime_error("Invalid extension schema type union");for(auto& one:t)if(!valid(one))throw std::runtime_error("Invalid extension schema type");}else if(!valid(t))throw std::runtime_error("Invalid extension schema type");}
 for(const char* key:{"title","description","pattern","format","$schema"})if(schema.contains(key)&&!schema[key].is_string())throw std::runtime_error("Extension schema text field must be a string");
 if(schema.contains("format")&&schema["format"]!="address")throw std::runtime_error("Only the address schema format is supported");if(schema.contains("pattern")){auto p=schema["pattern"].get<std::string>();if(p.size()>1024)throw std::runtime_error("Extension schema pattern exceeds limit");std::regex validPattern(p);}
 for(const char* key:{"minItems","maxItems","minLength","maxLength","minProperties","maxProperties"})if(schema.contains(key)&&(!schema[key].is_number_integer()||schema[key].get<int64_t>()<0||schema[key].get<uint64_t>()>1048576))throw std::runtime_error("Extension schema bound must be an integer from zero to 1048576");
 for(const char* key:{"minimum","maximum","exclusiveMinimum","exclusiveMaximum"})if(schema.contains(key)&&!schema[key].is_number())throw std::runtime_error("Extension schema numeric bound must be a number");
 if(schema.contains("uniqueItems")&&!schema["uniqueItems"].is_boolean())throw std::runtime_error("Extension schema uniqueItems must be boolean");
 if(schema.contains("properties")){if(!schema["properties"].is_object()||schema["properties"].size()>256)throw std::runtime_error("Invalid extension schema properties");for(auto& p:schema["properties"])checkSchema(p,depth+1);}
 if(schema.contains("required")){if(!schema["required"].is_array()||schema["required"].size()>256)throw std::runtime_error("Invalid extension required list");std::set<std::string> seen;for(auto& p:schema["required"])if(!p.is_string()||!seen.insert(p.get<std::string>()).second)throw std::runtime_error("Invalid or duplicate extension required key");}
 if(schema.contains("enum")&&(!schema["enum"].is_array()||schema["enum"].empty()||schema["enum"].size()>1024))throw std::runtime_error("Invalid extension schema enum");
 for(const char* key:{"items","additionalProperties"})if(schema.contains(key))checkSchema(schema[key],depth+1);
 for(const char* key:{"oneOf","anyOf","allOf"})if(schema.contains(key)){if(!schema[key].is_array()||schema[key].empty()||schema[key].size()>16)throw std::runtime_error("Invalid extension schema branches");for(auto& branch:schema[key])checkSchema(branch,depth+1);}
}
struct Plugin {
 HMODULE module=nullptr;ScratcherPluginV1 descriptor{};std::string id,version,path;
 Json declarations=Json::array();std::vector<ScratcherToolCallbackV1> callbacks;
 size_t active=0;bool notifying=false,accepted=false;
 ~Plugin(){if(module){try{if(accepted&&descriptor.shutdown)descriptor.shutdown(descriptor.user);}catch(...){}FreeLibrary(module);}}
};
struct Registry {std::map<std::string,std::shared_ptr<Plugin>> plugins;Json events=Json::array();bool eventDispatch=false;};
std::shared_ptr<Registry> registry(Engine& e,bool create=true){auto& slots=e.runtimeSlots();auto it=slots.find("scratcher.sdk");if(it!=slots.end())return std::static_pointer_cast<Registry>(it->second);if(!create)return {};auto r=std::make_shared<Registry>();slots["scratcher.sdk"]=r;return r;}
Json describe(const Plugin& p){return {{"id",p.id},{"version",p.version},{"path",p.path},{"tool_count",p.declarations.size()},{"tools",p.declarations},{"abi",SCRATCHER_PLUGIN_ABI_V1},{"trusted_native_code",true}};}
struct HostContext {Engine* engine;Registry* registry;bool event=false;};
void* SCRATCHER_PLUGIN_CALL hostAllocate(void*,size_t bytes){return bytes&&bytes<=maxResult+1?std::malloc(bytes):nullptr;}
void SCRATCHER_PLUGIN_CALL hostRelease(void*,void* memory){std::free(memory);}
char* hostString(const std::string& text){if(text.size()>maxResult)throw std::runtime_error("Extension output exceeds four MiB");auto* buffer=static_cast<char*>(hostAllocate(nullptr,text.size()+1));if(!buffer)throw std::bad_alloc();std::memcpy(buffer,text.c_str(),text.size()+1);return buffer;}
int SCRATCHER_PLUGIN_CALL hostCancelled(void* ctx){return static_cast<HostContext*>(ctx)->engine->cancelled()?1:0;}
int SCRATCHER_PLUGIN_CALL hostCall(void* ctx,const char* name,const char* args,char** result,char** error){
 if(!result||!error)return 0;*result=nullptr;*error=nullptr;
 try{auto& c=*static_cast<HostContext*>(ctx);if(c.event)throw std::runtime_error("Host tool calls are disabled during extension events");if(c.engine->cancelled())throw std::runtime_error("Extension cancelled");DepthGuard depth;auto n=boundedText(name,192,"tool name");auto a=Json::parse(boundedText(args,1024*1024,"arguments"));Tools tools(*c.engine);auto out=tools.callLocal(n,a).dump();*result=hostString(out);return 1;}
 catch(const std::exception& ex){try{*error=hostString(ex.what());}catch(...){}return 0;}catch(...){return 0;}
}
ScratcherHostV1 hostApi(HostContext& context){return {sizeof(ScratcherHostV1),SCRATCHER_PLUGIN_ABI_V1,&context,hostAllocate,hostRelease,hostCall,hostCancelled};}
void persistMetadata(Engine& e,const Registry& r){Json rows=Json::array();for(auto& [id,p]:r.plugins)rows.push_back({{"id",id},{"version",p->version},{"path",p->path},{"tool_count",p->declarations.size()}});e.advancedState()["extensions"]={{"loaded",rows},{"autoload",false}};}
Json loadPlugin(Engine& e,const Json& args){
 auto r=registry(e);if(r->plugins.size()>=32)throw std::runtime_error("At most 32 native extensions may be loaded");
 auto path=std::filesystem::u8path(args.at("path").get<std::string>());if(!path.is_absolute()||!std::filesystem::is_regular_file(path)||path.extension()!=L".dll")throw std::runtime_error("Native extension must be an absolute path to a DLL");
 auto p=std::make_shared<Plugin>();p->path=pathText(std::filesystem::weakly_canonical(path));
 p->module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!p->module)throw std::runtime_error("Unable to load native extension (Windows error "+std::to_string(GetLastError())+")");
 auto entry=reinterpret_cast<ScratcherPluginEntryV1>(GetProcAddress(p->module,"scratcher_plugin_v1"));if(!entry)throw std::runtime_error("DLL does not export scratcher_plugin_v1");
 const auto* d=entry();if(!d||d->struct_size!=sizeof(ScratcherPluginV1)||d->abi_version!=SCRATCHER_PLUGIN_ABI_V1)throw std::runtime_error("Unsupported native extension ABI");
 p->descriptor=*d;p->id=boundedText(d->id,64,"id");p->version=boundedText(d->version,64,"version");
 if(!std::regex_match(p->id,std::regex("[A-Za-z][A-Za-z0-9_]{0,63}")))throw std::runtime_error("Plugin id must be a simple identifier");
 if(r->plugins.contains(p->id))throw std::runtime_error("Native extension id is already loaded");
 if(d->tool_count>128||(d->tool_count&&!d->tools))throw std::runtime_error("Invalid extension tool count");
 std::set<std::string> names;
 for(uint32_t i=0;i<d->tool_count;++i){const auto& t=d->tools[i];if(t.struct_size!=sizeof(ScratcherToolV1)||!t.invoke)throw std::runtime_error("Invalid extension tool descriptor");auto n=boundedText(t.name,64,"tool name");if(!std::regex_match(n,std::regex("[A-Za-z][A-Za-z0-9_]{0,63}"))||!names.insert(n).second)throw std::runtime_error("Invalid or duplicate extension tool name");
  auto schema=Json::parse(boundedText(t.input_schema_json,65536,"schema"));checkSchema(schema);if(!schema.is_object()||schema.value("type",Json())!="object")throw std::runtime_error("Extension schema must describe an object");
  p->declarations.push_back({{"name","plugin."+p->id+"."+n},{"description",boundedText(t.description,1024,"description")},{"inputSchema",schema},{"annotations",{{"readOnlyHint",bool(t.read_only)},{"destructiveHint",false},{"openWorldHint",false}}}});p->callbacks.push_back(t.invoke);
 }
 if(p->declarations.dump().size()>1024*1024)throw std::runtime_error("Combined native tool schemas exceed one MiB");
 p->accepted=true;r->plugins[p->id]=p;persistMetadata(e,*r);return describe(*p);
}
Json invokePlugin(Engine& e,const std::string& name,const Json& args){
 DepthGuard depth;auto r=registry(e,false);if(!r)throw std::runtime_error("Native extension is not loaded");
 for(auto& [id,p]:r->plugins)for(size_t i=0;i<p->declarations.size();++i)if(p->declarations[i]["name"]==name){
  if(e.cancelled())throw std::runtime_error("Extension cancelled");struct Active{std::shared_ptr<Plugin> p;Active(std::shared_ptr<Plugin> a):p(std::move(a)){++p->active;}~Active(){--p->active;}} active(p);
  HostContext context{&e,r.get()};auto host=hostApi(context);char* out=nullptr;char* error=nullptr;
  struct Buffers{char*& a;char*& b;~Buffers(){hostRelease(nullptr,a);if(b!=a)hostRelease(nullptr,b);}} buffers{out,error};
  auto input=args.dump();int success=p->callbacks[i](p->descriptor.user,&host,input.c_str(),&out,&error);
  if(!success)throw std::runtime_error(error?boundedText(error,maxResult,"error"):"Native extension failed");
  auto result=Json::parse(boundedText(out,maxResult,"output"));if(e.cancelled())throw std::runtime_error("Extension cancelled");return result;
 }
 throw std::runtime_error("Unknown native extension tool");
}

char nullMarker;
struct ScriptContext {
 Engine* engine=nullptr;size_t memory=0,peak=0,memoryLimit=64*1024*1024;uint64_t instructions=0,instructionLimit=10000000;size_t calls=0;
 std::chrono::steady_clock::time_point deadline;std::string log;bool stopped=false;std::string stopReason;
};
void* scriptAllocate(void* user,void* ptr,size_t old,size_t next){auto& c=*static_cast<ScriptContext*>(user);if(!ptr)old=0;if(!next){std::free(ptr);c.memory-=std::min(c.memory,old);return nullptr;}if(next>c.memoryLimit||c.memory-old>c.memoryLimit-next)return nullptr;auto* allocation=std::realloc(ptr,next);if(allocation){c.memory=c.memory-old+next;c.peak=std::max(c.peak,c.memory);}return allocation;}
ScriptContext& scriptContext(lua_State* L){return **static_cast<ScriptContext**>(lua_getextraspace(L));}
void scriptCheck(ScriptContext& c){if(c.stopped)throw std::runtime_error(c.stopReason);if(c.engine->cancelled()){c.stopped=true;c.stopReason="Script cancelled";}else if(std::chrono::steady_clock::now()>=c.deadline){c.stopped=true;c.stopReason="Script time limit exceeded";}else if(c.instructions>=c.instructionLimit){c.stopped=true;c.stopReason="Script instruction limit exceeded";}if(c.stopped)throw std::runtime_error(c.stopReason);}
void scriptHook(lua_State* L,lua_Debug*){auto& c=scriptContext(L);c.instructions+=1000;try{scriptCheck(c);}catch(const std::exception& ex){lua_pushstring(L,ex.what());lua_error(L);}}
void pushJson(lua_State* L,const Json& j,size_t depth=0){if(depth>32)throw std::runtime_error("Tool result exceeds script nesting limit");if(j.is_null()){lua_pushlightuserdata(L,&nullMarker);return;}if(j.is_boolean()){lua_pushboolean(L,j.get<bool>());return;}if(j.is_number_integer()){if(j.is_number_unsigned()&&j.get<uint64_t>()>INT64_MAX){auto s=std::to_string(j.get<uint64_t>());lua_pushlstring(L,s.data(),s.size());}else lua_pushinteger(L,j.get<int64_t>());return;}if(j.is_number_float()){lua_pushnumber(L,j.get<double>());return;}if(j.is_string()){const auto& s=j.get_ref<const std::string&>();lua_pushlstring(L,s.data(),s.size());return;}
 if(!lua_checkstack(L,8))throw std::runtime_error("Script stack limit reached");lua_createtable(L,j.is_array()?static_cast<int>(j.size()):0,j.is_object()?static_cast<int>(j.size()):0);if(j.is_array()){luaL_getmetatable(L,"scratcher.array");lua_setmetatable(L,-2);for(size_t i=0;i<j.size();++i){pushJson(L,j[i],depth+1);lua_rawseti(L,-2,static_cast<lua_Integer>(i+1));}}else for(auto it=j.begin();it!=j.end();++it){lua_pushlstring(L,it.key().data(),it.key().size());pushJson(L,it.value(),depth+1);lua_rawset(L,-3);}}
Json fromLua(lua_State* L,int index,std::set<const void*>& seen,size_t& items,size_t depth=0){if(depth>32||++items>100000)throw std::runtime_error("Script JSON exceeds nesting or element limit");if(!lua_checkstack(L,8))throw std::runtime_error("Script stack limit reached");index=lua_absindex(L,index);auto type=lua_type(L,index);
 if(type==LUA_TNIL||(type==LUA_TLIGHTUSERDATA&&lua_touserdata(L,index)==&nullMarker))return nullptr;if(type==LUA_TBOOLEAN)return bool(lua_toboolean(L,index));if(type==LUA_TNUMBER){if(lua_isinteger(L,index))return Json(lua_tointeger(L,index));auto n=lua_tonumber(L,index);if(!std::isfinite(n))throw std::runtime_error("JSON numbers must be finite");return Json(n);}if(type==LUA_TSTRING){size_t n=0;const char* s=lua_tolstring(L,index,&n);if(n>maxResult)throw std::runtime_error("Script string exceeds output limit");return std::string(s,n);}if(type!=LUA_TTABLE)throw std::runtime_error("Script returned a value that cannot be represented as JSON");
 auto identity=lua_topointer(L,index);if(!seen.insert(identity).second)throw std::runtime_error("Cyclic script table cannot be represented as JSON");struct Visit{std::set<const void*>& seen;const void* p;~Visit(){seen.erase(p);}} visit{seen,identity};
 bool tagged=false;if(lua_getmetatable(L,index)){luaL_getmetatable(L,"scratcher.array");tagged=lua_rawequal(L,-1,-2)!=0;lua_pop(L,2);}size_t count=0,maxIndex=0;bool numbers=true,strings=true;
 lua_pushnil(L);while(lua_next(L,index)){++count;if(lua_isinteger(L,-2)&&lua_tointeger(L,-2)>0&&uint64_t(lua_tointeger(L,-2))<=100000){maxIndex=std::max(maxIndex,static_cast<size_t>(lua_tointeger(L,-2)));strings=false;}else if(lua_type(L,-2)==LUA_TSTRING)numbers=false;else{lua_pop(L,2);throw std::runtime_error("JSON table keys must be strings or contiguous positive integers");}lua_pop(L,1);if(count>100000)throw std::runtime_error("Script table exceeds element limit");}
 bool array=count?numbers:tagged;if((!numbers&&!strings)||(array&&count!=maxIndex))throw std::runtime_error("Mixed or sparse Lua tables cannot be represented as JSON");Json j=array?Json::array():Json::object();
 if(array)for(size_t i=1;i<=count;++i){lua_rawgeti(L,index,static_cast<lua_Integer>(i));j.push_back(fromLua(L,-1,seen,items,depth+1));lua_pop(L,1);}else{lua_pushnil(L);while(lua_next(L,index)){size_t n=0;const char* k=lua_tolstring(L,-2,&n);j[std::string(k,n)]=fromLua(L,-1,seen,items,depth+1);lua_pop(L,1);}}return j;
}
Json scriptJson(lua_State* L,int index){std::set<const void*> seen;size_t count=0;return fromLua(L,index,seen,count);}
int scriptCall(lua_State* L){try{auto& c=scriptContext(L);scriptCheck(c);if(++c.calls>1000)throw std::runtime_error("Script exceeds 1000 host tool calls");size_t n=0;auto* name=luaL_checklstring(L,1,&n);if(n>192)throw std::runtime_error("Tool name exceeds limit");auto args=lua_gettop(L)>=2?scriptJson(L,2):Json::object();if(!args.is_object())throw std::runtime_error("Tool arguments must be an object");DepthGuard depth;Tools tools(*c.engine);auto result=tools.callLocal(std::string(name,n),args);scriptCheck(c);if(result.dump().size()>maxResult)throw std::runtime_error("Tool result exceeds script output limit");pushJson(L,result);return 1;}catch(const std::exception& ex){lua_pushstring(L,ex.what());return lua_error(L);}}
int scriptPrint(lua_State* L){try{auto& c=scriptContext(L);for(int i=1,n=lua_gettop(L);i<=n;++i){size_t len=0;auto* s=luaL_tolstring(L,i,&len);if(c.log.size()+len+2>65536)throw std::runtime_error("Script log exceeds 64 KiB");if(i>1)c.log+='\t';c.log.append(s,len);lua_pop(L,1);}c.log+='\n';return 0;}catch(const std::exception& ex){lua_pushstring(L,ex.what());return lua_error(L);}}
int scriptArray(lua_State* L){if(lua_gettop(L)==0)lua_newtable(L);else luaL_checktype(L,1,LUA_TTABLE);lua_settop(L,1);luaL_getmetatable(L,"scratcher.array");lua_setmetatable(L,1);return 1;}
int scriptDecode(lua_State* L){try{size_t n=0;auto* s=luaL_checklstring(L,1,&n);if(n>maxResult)throw std::runtime_error("JSON input exceeds limit");auto j=Json::parse(std::string(s,n));pushJson(L,j);return 1;}catch(const std::exception& ex){lua_pushstring(L,ex.what());return lua_error(L);}}
int scriptEncode(lua_State* L){try{auto text=scriptJson(L,1).dump();if(text.size()>maxResult)throw std::runtime_error("JSON output exceeds limit");lua_pushlstring(L,text.data(),text.size());return 1;}catch(const std::exception& ex){lua_pushstring(L,ex.what());return lua_error(L);}}
int setupScript(lua_State* L){luaL_requiref(L,LUA_GNAME,luaopen_base,1);lua_pop(L,1);luaL_requiref(L,LUA_TABLIBNAME,luaopen_table,1);lua_pop(L,1);luaL_requiref(L,LUA_STRLIBNAME,luaopen_string,1);lua_pop(L,1);luaL_requiref(L,LUA_MATHLIBNAME,luaopen_math,1);lua_pop(L,1);luaL_requiref(L,LUA_UTF8LIBNAME,luaopen_utf8,1);lua_pop(L,1);
 for(const char* name:{"dofile","loadfile","load","collectgarbage","pcall","xpcall","warn"}){lua_pushnil(L);lua_setglobal(L,name);}lua_pushcfunction(L,scriptPrint);lua_setglobal(L,"print");luaL_newmetatable(L,"scratcher.array");lua_pushliteral(L,"array");lua_setfield(L,-2,"__metatable");lua_pop(L,1);lua_newtable(L);lua_pushcfunction(L,scriptCall);lua_setfield(L,-2,"call");lua_pushcfunction(L,scriptArray);lua_setfield(L,-2,"array");lua_pushcfunction(L,scriptDecode);lua_setfield(L,-2,"json_decode");lua_pushcfunction(L,scriptEncode);lua_setfield(L,-2,"json_encode");lua_pushlightuserdata(L,&nullMarker);lua_setfield(L,-2,"null");lua_pushliteral(L,LUA_RELEASE);lua_setfield(L,-2,"runtime");lua_setglobal(L,"scratcher");return 0;}
Json executeScript(Engine& e,const Json& args){DepthGuard depth;std::string source;if(args.contains("source")==args.contains("path"))throw std::runtime_error("Provide exactly one of source or path");if(args.contains("source"))source=args.at("source").get<std::string>();else{auto path=std::filesystem::u8path(args.at("path").get<std::string>());if(!path.is_absolute())throw std::runtime_error("Script path must be absolute");auto size=std::filesystem::file_size(path);if(size>262144)throw std::runtime_error("Script exceeds 256 KiB");std::ifstream in(path,std::ios::binary);if(!in)throw std::runtime_error("Cannot read script");source.assign(std::istreambuf_iterator<char>(in),{});}if(source.empty()||source.size()>262144)throw std::runtime_error("Script must contain 1 to 262144 bytes");
 ScriptContext c;c.engine=&e;c.instructionLimit=args.value("instruction_limit",uint64_t(10000000));if(c.instructionLimit<1000||c.instructionLimit>100000000)throw std::runtime_error("Script instruction limit must be 1000 to 100000000");auto ms=args.value("timeout_ms",5000u);if(ms<1||ms>60000)throw std::runtime_error("Script timeout must be 1 to 60000 ms");auto mem=args.value("memory_limit_mb",64u);if(mem<4||mem>128)throw std::runtime_error("Script memory limit must be 4 to 128 MiB");c.memoryLimit=size_t(mem)*1024*1024;auto begin=std::chrono::steady_clock::now();c.deadline=begin+std::chrono::milliseconds(ms);scriptCheck(c);
 auto* L=lua_newstate(scriptAllocate,&c,static_cast<unsigned>(GetTickCount64()));if(!L)throw std::runtime_error("Unable to create script state");struct State{lua_State* L;~State(){lua_close(L);}} state{L};*static_cast<ScriptContext**>(lua_getextraspace(L))=&c;lua_sethook(L,scriptHook,LUA_MASKCOUNT,1000);
 lua_pushcfunction(L,setupScript);int status=lua_pcall(L,0,0,0);if(status==LUA_OK)status=luaL_loadbufferx(L,source.data(),source.size(),"Scratcher script","t");if(status==LUA_OK)status=lua_pcall(L,0,1,0);
 if(status!=LUA_OK){const char* message=lua_tostring(L,-1);throw std::runtime_error(message?message:"Script memory limit exceeded or runtime error");}scriptCheck(c);auto result=scriptJson(L,-1);if(result.dump().size()>maxResult)throw std::runtime_error("Script result exceeds four MiB");auto elapsed=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-begin).count();
 e.advancedState()["scripting"]={{"runtime",LUA_RELEASE},{"last_host_calls",c.calls},{"last_elapsed_ms",elapsed},{"last_peak_bytes",c.peak}};
 return {{"result",result},{"log",c.log},{"host_calls",c.calls},{"instruction_checks",c.instructions},{"peak_memory_bytes",c.peak},{"elapsed_ms",elapsed},{"runtime",LUA_RELEASE},{"transactional",false}};
}
}
Json sdkTools(){Json out=Json::array();auto add=[&](const char* n,const char* d,Json p,Json req,bool ro){out.push_back({{"name",n},{"description",d},{"inputSchema",{{"type","object"},{"properties",p},{"required",req},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",ro},{"destructiveHint",false},{"openWorldHint",false}}}});};auto text=Json{{"type","string"},{"maxLength",32768}};
 add("exec_script","Run a bounded embedded Lua script with scratcher.call access to local analysis tools. Native extension loading and host-tool side effects are explicit. Earlier edits remain if a later statement fails.",{{"source",{{"type","string"},{"maxLength",262144}}},{"path",text},{"timeout_ms",{{"type","integer"},{"minimum",1},{"maximum",60000}}},{"instruction_limit",{{"type","integer"},{"minimum",1000},{"maximum",100000000}}},{"memory_limit_mb",{{"type","integer"},{"minimum",4},{"maximum",128}}}},Json::array(),false);
 add("load_plugin","Explicitly load a trusted native DLL implementing the Scratcher C ABI. Publishes plugin.<id>.<tool> tools for this workspace; native code is not sandboxed.",{{"path",text}},{"path"},false);
 add("unload_plugin","Unload an idle native extension and remove its tool declarations.",{{"id",{{"type","string"},{"maxLength",64}}}},{"id"},false);
 add("list_plugins","List loaded native extensions, tool schemas and bounded event history.",Json::object(),Json::array(),true);
 auto id=Json{{"type","string"},{"minLength",1},{"maxLength",64},{"pattern","^[A-Za-z][A-Za-z0-9_]{0,63}$"}};
 add("call_plugin","Invoke a loaded native extension tool by id and tool name. Validates the extension's input schema in the target workspace; also works through attached desktop sessions.",{{"id",id},{"tool",id},{"arguments",{{"type","object"}}}},{"id","tool"},false);
 add("get_scripting_info","Read embedded scripting capabilities and resource limits.",Json::object(),Json::array(),true);
 return out;
}
Json sdkPluginTools(Engine& e){Json out=Json::array();if(auto r=registry(e,false))for(auto& [id,p]:r->plugins)for(auto& d:p->declarations)out.push_back(d);return out;}
std::optional<Json> callSdkTool(Engine& e,const std::string& name,const Json& args){
 if(name=="exec_script")return executeScript(e,args);if(name=="load_plugin")return loadPlugin(e,args);
 if(name=="call_plugin"){auto id=args.at("id").get<std::string>(),tool=args.at("tool").get<std::string>();std::regex identifier("[A-Za-z][A-Za-z0-9_]{0,63}");if(!std::regex_match(id,identifier)||!std::regex_match(tool,identifier))throw std::runtime_error("Invalid native extension id or tool name");Tools tools(e);return tools.callLocal("plugin."+id+"."+tool,args.value("arguments",Json::object()));}
 if(name=="unload_plugin"){auto r=registry(e,false);auto id=args.at("id").get<std::string>();if(!r||!r->plugins.contains(id))throw std::runtime_error("Native extension is not loaded");auto p=r->plugins.at(id);if(p->active||p->notifying)throw std::runtime_error("Cannot unload an extension during a callback");r->plugins.erase(id);persistMetadata(e,*r);return Json{{"id",id},{"unloaded",true}};}
 if(name=="list_plugins"){auto rows=Json::array();auto r=registry(e,false);if(r)for(auto& [id,p]:r->plugins)rows.push_back(describe(*p));return Json{{"plugins",rows},{"count",rows.size()},{"events",r?r->events:Json::array()},{"autoload",false}};}
 if(name=="get_scripting_info")return Json{{"runtime",LUA_RELEASE},{"api",{"scratcher.call","scratcher.array","scratcher.json_encode","scratcher.json_decode","scratcher.null","print"}},{"libraries",{"base","table","string","math","utf8"}},{"disabled",{"os","io","package","debug","coroutine","load","loadfile","dofile","pcall","xpcall","collectgarbage"}},{"max_source_bytes",262144},{"max_host_calls",1000},{"max_recursion",8},{"max_output_bytes",maxResult},{"native_extension_abi",SCRATCHER_PLUGIN_ABI_V1},{"native_extensions_trusted",true},{"tool_side_effects_allowed",true},{"automatic_rollback",false}};
 if(name.starts_with("plugin."))return invokePlugin(e,name,args);return std::nullopt;
}
void notifySdkEvent(Engine& e,const std::string& event,const Json& payload){auto r=registry(e,false);if(!r||r->eventDispatch)return;persistMetadata(e,*r);r->eventDispatch=true;struct Dispatch{Registry& r;~Dispatch(){r.eventDispatch=false;}} dispatch{*r};auto text=payload.dump();if(text.size()>65536)text=Json{{"truncated",true},{"event",event}}.dump();
 r->events.push_back({{"event",event},{"payload",Json::parse(text)}});while(r->events.size()>64)r->events.erase(r->events.begin());
 std::vector<std::shared_ptr<Plugin>> live;for(auto& [id,p]:r->plugins)live.push_back(p);for(auto& p:live)if(p->descriptor.on_event){p->notifying=true;struct Notify{Plugin& p;~Notify(){p.notifying=false;}} notify{*p};HostContext context{&e,r.get(),true};auto host=hostApi(context);try{p->descriptor.on_event(p->descriptor.user,&host,event.c_str(),text.c_str());}catch(...){r->events.push_back({{"event","extension_event_error"},{"plugin",p->id}});}}while(r->events.size()>64)r->events.erase(r->events.begin());
}
}
