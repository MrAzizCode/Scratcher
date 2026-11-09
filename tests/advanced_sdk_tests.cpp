#include "feature_advanced_sdk.hpp"
#include <fstream>
#include <functional>
#include <iostream>
using namespace scratcher;
namespace {
int checks=0;
void check(bool ok,const char* message){++checks;if(!ok)throw std::runtime_error(message);}
void reject(const std::function<void()>& call,const char* message){bool failed=false;try{call();}catch(const std::exception&){failed=true;}check(failed,message);}
Json sdk(Engine& e,const std::string& name,Json args=Json::object()){auto result=callSdkTool(e,name,args);if(!result)throw std::runtime_error("Missing SDK tool");return *result;}
}
int main(){try{
 auto dir=executableDir()/"sdk-fixtures";std::filesystem::create_directories(dir);auto path=dir/"sample.bin";{std::ofstream out(path,std::ios::binary);char code[]={char(0xb8),1,0,0,0,char(0xc3)};out.write(code,sizeof(code));}
 Engine e;e.open(path);Tools tools(e);
 auto script=[&](const std::string& source,Json options=Json::object()){options["source"]=source;return sdk(e,"exec_script",options);};
 auto info=sdk(e,"get_scripting_info");check(info["native_extension_abi"]==1,"ABI version");
 auto result=script("local f = scratcher.call('list_functions', {limit=10}); scratcher.call('rename_function', {address='0x1000', name='script_entry'}); scratcher.call('set_comment', {address='0x1000', text='written by script'}); print('renamed'); return {count=#f.items, name=scratcher.call('list_functions', {limit=10}).items[1].name}");
 check(result["result"]["name"]=="script_entry","Lua real rename via host API");check(result["host_calls"]==4,"host call accounting");check(result["log"]=="renamed\n","captured script print");check(e.annotations().dump().find("written by script")!=std::string::npos,"Lua comment reaches annotation storage");
 auto table=script("return {a=scratcher.array(), b=scratcher.null, c=scratcher.json_decode('[1,true,\"hello\"]'), d=scratcher.json_encode({x=7})}")["result"];
 check(table["a"].is_array()&&table["a"].empty(),"empty array marker");check(table["b"].is_null(),"JSON null preserved");check(table["c"][2]=="hello","JSON decode");check(Json::parse(table["d"].get<std::string>())["x"]==7,"JSON encode");
 check(script("return os == nil and io == nil and package == nil and debug == nil and coroutine == nil and pcall == nil")["result"]==true,"restricted libraries unavailable");
 reject([&]{script("while true do end",{{"instruction_limit",2000}});},"infinite loop bounded");
 reject([&]{script("local a={}; a.self=a; return a");},"cyclic table rejected");
 reject([&]{script("return {[1]=1,[3]=3}");},"sparse array rejected");
 reject([&]{script("return {[1]=1,hello=2}");},"mixed table rejected");
 reject([&]{script("return math.huge");},"non-finite JSON value rejected");
 reject([&]{script("return string.rep('x', 64*1024*1024)",{{"memory_limit_mb",4}});},"Lua memory bounded");
 reject([&]{script("return scratcher.call('rename_function',{address='0x1000',name='invalid name'})");},"host schema validation preserved");
 std::atomic_bool cancelled=true;e.setCancellation(&cancelled);reject([&]{script("return 1");},"script cancellation honored");e.setCancellation(nullptr);
 auto scriptFile=dir/"script.lua";{std::ofstream out(scriptFile);out<<"return scratcher.call('read_bytes',{address='0x1000',count=2})";}auto read=sdk(e,"exec_script",{{"path",pathText(scriptFile)}});check(read["host_calls"]==1,"file script executed");
 auto dll=executableDir()/"ScratcherPluginSample.dll";check(std::filesystem::exists(dll),"native sample DLL built");
 auto loaded=sdk(e,"load_plugin",{{"path",pathText(dll)}});check(loaded["id"]=="sample"&&loaded["tool_count"]==3,"plugin ABI descriptor loaded");check(sdkPluginTools(e).size()==3,"dynamic extension schemas exposed");
 auto echo=tools.callLocal("plugin.sample.echo",{{"message","native hello"}});check(echo["message"]=="native hello","native callback returns JSON");
 check(tools.callLocal("call_plugin",{{"id","sample"},{"tool","echo"},{"arguments",{{"message","routed hello"}}}})["message"]=="routed hello","static plugin dispatcher validates in target workspace");
 reject([&]{tools.callLocal("plugin.sample.echo",{{"message",123}});},"plugin schema validates before callback");
 auto binary=tools.callLocal("plugin.sample.inspect_binary",Json::object());check(binary["size"]==6,"native host callback reads binary");
 notifySdkEvent(e,"workspace_edited",{{"operation","rename_function"}});check(tools.callLocal("plugin.sample.event_count",Json::object())["events"].get<int>()>=1,"plugin receives event");
 check(script("return scratcher.call('plugin.sample.echo',{message='Lua to native'})")["result"]["message"]=="Lua to native","script invokes native dynamic tool");
 reject([&]{sdk(e,"load_plugin",{{"path",pathText(dll)}});},"duplicate plugin rejected");
 e.open(path);check(sdk(e,"list_plugins")["count"]==1,"native extension persists across binary changes");
 sdk(e,"unload_plugin",{{"id","sample"}});check(sdkPluginTools(e).empty(),"unload removes dynamic schemas");reject([&]{tools.callLocal("plugin.sample.echo",{{"message","gone"}});},"unloaded plugin cannot execute");
 sdk(e,"load_plugin",{{"path",pathText(dll)}});check(sdk(e,"list_plugins")["count"]==1,"plugin reload after unload");sdk(e,"unload_plugin",{{"id","sample"}});
 std::cout<<"PASS: "<<checks<<" embedded Lua, host edits, limits/cancellation, JSON conversion, native ABI, dynamic schema, host callback, event and unload checks\n";return 0;
}catch(const std::exception& ex){std::cerr<<"FAIL: "<<ex.what()<<'\n';return 1;}}
