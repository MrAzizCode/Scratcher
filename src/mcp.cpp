#include "core.hpp"
#include "tools_extra.hpp"
#include "feature_power_tools.hpp"
#include "feature_mcp_control.hpp"
#include "feature_mcp_batch.hpp"
#include "feature_advanced.hpp"
#include "feature_advanced_database.hpp"
#include "feature_advanced_manual.hpp"
#include "feature_advanced_sdk.hpp"
#include "tool_backend.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <regex>
#include <set>
#include <cctype>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include "error.hh"
namespace scratcher {
namespace {
size_t unicodeLength(const std::string& string) {
 size_t count=0;
 for(size_t i=0;i<string.size();++count) {
  const auto lead=static_cast<unsigned char>(string[i]);size_t width=0;uint32_t code=0;
  if(lead<0x80){width=1;code=lead;}else if(lead>=0xc2&&lead<=0xdf){width=2;code=lead&0x1f;}else if(lead>=0xe0&&lead<=0xef){width=3;code=lead&0x0f;}else if(lead>=0xf0&&lead<=0xf4){width=4;code=lead&7;}else throw std::runtime_error("Arguments must contain valid UTF-8");
  if(width>string.size()-i)throw std::runtime_error("Arguments must contain valid UTF-8");
  for(size_t j=1;j<width;++j){const auto next=static_cast<unsigned char>(string[i+j]);if((next&0xc0)!=0x80)throw std::runtime_error("Arguments must contain valid UTF-8");code=(code<<6)|(next&0x3f);}
  if((width==2&&code<0x80)||(width==3&&code<0x800)||(width==4&&code<0x10000)||code>0x10ffff||(code>=0xd800&&code<=0xdfff))throw std::runtime_error("Arguments must contain valid UTF-8");
  i+=width;
 }
 return count;
}
void validateArgument(const Json& value,const Json& schema,const std::string& label,size_t depth=0) {
 if(depth>64)throw std::runtime_error("Arguments exceed nesting limit: "+label);
 if(schema.is_boolean()){if(!schema.get<bool>())throw std::runtime_error("Argument is not permitted: "+label);return;}
 if(schema.contains("oneOf")||schema.contains("anyOf")) {
  const auto& branches=schema.contains("oneOf")?schema["oneOf"]:schema["anyOf"];size_t matches=0;
  for(const auto& branch:branches)try{validateArgument(value,branch,label,depth+1);++matches;}catch(const std::exception&){}
  if(matches==0||(schema.contains("oneOf")&&matches!=1))throw std::runtime_error("Argument does not match schema: "+label);
 }
 if(schema.contains("allOf"))for(const auto& branch:schema["allOf"])validateArgument(value,branch,label,depth+1);
 if(schema.contains("type")) {
  auto matches=[&](const std::string& type){return type=="string"?value.is_string():type=="integer"?value.is_number_integer():
   type=="number"?value.is_number():type=="boolean"?value.is_boolean():type=="object"?value.is_object():
   type=="array"?value.is_array():type=="null"?value.is_null():false;};
  bool valid=false;if(schema["type"].is_array()){for(const auto& type:schema["type"])valid=valid||matches(type.get<std::string>());}else valid=matches(schema["type"].get<std::string>());
  if(!valid)throw std::runtime_error("Unexpected argument type: "+label);
 }
 if(schema.contains("const")&&value!=schema["const"])throw std::runtime_error("Unsupported value: "+label);
 if(schema.contains("enum")&&std::find(schema["enum"].begin(),schema["enum"].end(),value)==schema["enum"].end())
  throw std::runtime_error("Unsupported value: "+label);
 if(value.is_number()) {
  const auto number=value.get<long double>();
  if(!std::isfinite(number))throw std::runtime_error("Argument must be finite: "+label);
  if(schema.contains("minimum")&&number<schema["minimum"].get<long double>())throw std::runtime_error("Argument below minimum: "+label);
  if(schema.contains("maximum")&&number>schema["maximum"].get<long double>())throw std::runtime_error("Argument exceeds limit: "+label);
  if(schema.contains("exclusiveMinimum")&&number<=schema["exclusiveMinimum"].get<long double>())throw std::runtime_error("Argument below exclusive minimum: "+label);
  if(schema.contains("exclusiveMaximum")&&number>=schema["exclusiveMaximum"].get<long double>())throw std::runtime_error("Argument exceeds exclusive limit: "+label);
 }
 if(value.is_string()) {
  const auto& string=value.get_ref<const std::string&>();
  if(string.size()>1024*1024)throw std::runtime_error("Argument exceeds string limit: "+label);
  const auto length=unicodeLength(string);
  if(string.find('\0')!=std::string::npos)throw std::runtime_error("Argument contains a null character: "+label);
  if(schema.contains("minLength")&&length<schema["minLength"].get<size_t>())throw std::runtime_error("Argument too short: "+label);
  if(schema.contains("maxLength")&&length>schema["maxLength"].get<size_t>())throw std::runtime_error("Argument too long: "+label);
  const auto format=schema.value("format",std::string());
  if(format=="address"||format=="virtual-address") {if(length>32)throw std::runtime_error("Address exceeds limit: "+label);address(value);}
  if(schema.contains("pattern")&&!std::regex_search(string,std::regex(schema["pattern"].get<std::string>())))throw std::runtime_error("Argument does not match pattern: "+label);
 }
 if(value.is_object()) {
  if(schema.contains("minProperties")&&value.size()<schema["minProperties"].get<size_t>())throw std::runtime_error("Too few properties: "+label);
  if(schema.contains("maxProperties")&&value.size()>schema["maxProperties"].get<size_t>())throw std::runtime_error("Too many properties: "+label);
  if(schema.contains("required"))for(const auto& key:schema["required"])if(!value.contains(key.get<std::string>()))throw std::runtime_error("Missing argument: "+key.get<std::string>());
  const auto properties=schema.value("properties",Json::object());
  for(auto it=value.begin();it!=value.end();++it) {
   if(properties.contains(it.key()))validateArgument(*it,properties[it.key()],label.empty()?it.key():label+"."+it.key(),depth+1);
   else if(schema.contains("additionalProperties")&&schema["additionalProperties"]==false)throw std::runtime_error("Unknown argument: "+it.key());
   else if(schema.contains("additionalProperties")&&schema["additionalProperties"].is_object())validateArgument(*it,schema["additionalProperties"],it.key(),depth+1);
  }
 }
 if(value.is_array()) {
  if(schema.contains("minItems")&&value.size()<schema["minItems"].get<size_t>())throw std::runtime_error("Too few items: "+label);
  if(schema.contains("maxItems")&&value.size()>schema["maxItems"].get<size_t>())throw std::runtime_error("Too many items: "+label);
  if(schema.value("uniqueItems",false)){std::set<std::string> seen;for(const auto& item:value)if(!seen.insert(item.dump()).second)throw std::runtime_error("Duplicate array item: "+label);}
  if(schema.contains("items"))for(const auto& item:value)validateArgument(item,schema["items"],label+"[]",depth+1);
 }
}
void boundSchema(Json& schema,const std::string& key="") {
 if(!schema.is_object())return;
 if(schema.value("type",Json())=="string") {
  if(!schema.contains("maxLength"))schema["maxLength"]=65536;
  if(key=="path"){schema["maxLength"]=32768;schema["minLength"]=1;}
  if(key=="address"||key=="base"||schema.value("description",std::string()).starts_with("Virtual address")){schema["maxLength"]=32;schema["minLength"]=1;schema["format"]="address";}
 }
 if(schema.contains("properties"))for(auto it=schema["properties"].begin();it!=schema["properties"].end();++it)boundSchema(*it,it.key());
 for(const char* branch:{"items","additionalProperties"})if(schema.contains(branch))boundSchema(schema[branch]);
 for(const char* branch:{"oneOf","anyOf","allOf"})if(schema.contains(branch))for(auto& item:schema[branch])boundSchema(item,key);
}
void validateDefinition(const Json& definitions,const std::string& name,const Json& args) {
 if(!args.is_object())throw std::runtime_error("Tool arguments must be an object");
 auto definition=std::find_if(definitions.begin(),definitions.end(),[&](const Json& tool){return tool["name"]==name;});
 if(definition==definitions.end())throw std::runtime_error("Unknown tool: "+name);
 validateArgument(args,(*definition)["inputSchema"],"");
}
bool validResourceUri(const std::string& uri) {
 if(uri.empty()||uri.size()>4096)return false;
 const auto colon=uri.find(':');if(colon==std::string::npos||colon==0)return false;
 const std::string punctuation="-._~:/?#[]@!$&'()*+,;=%";
 for(size_t i=0;i<uri.size();++i){const auto ch=static_cast<unsigned char>(uri[i]);if(ch>=127||(!std::isalnum(ch)&&punctuation.find(static_cast<char>(ch))==std::string::npos))return false;if(i<colon&&!(std::isalpha(ch)||(i>0&&(std::isdigit(ch)||ch=='+'||ch=='-'||ch=='.'))))return false;if(ch=='%'&&(i+2>=uri.size()||!std::isxdigit(static_cast<unsigned char>(uri[i+1]))||!std::isxdigit(static_cast<unsigned char>(uri[i+2]))))return false;}
 return true;
}
Json rpcError(const Json& id,int code,const std::string& message) {
 return {{"jsonrpc","2.0"},{"id",id},{"error",{{"code",code},{"message",message}}}};
}
// Drain an oversized message without allocating its complete contents.
bool readMessage(std::istream& input,std::string& line,bool& oversized) {
 constexpr size_t maximum=1024*1024;
 line.clear();oversized=false;char ch=0;bool received=false;
 while(input.get(ch)) {
  received=true;if(ch=='\n')break;
  if(line.size()<maximum)line.push_back(ch);else oversized=true;
 }
 if(!line.empty()&&line.back()=='\r')line.pop_back();
 return received;
}
}
Json Tools::localList()const{
 static const Json base=[](){
 Json tools=Json::array();
 auto str=[](const char* description){return Json{{"type","string"},{"description",description}};};
 auto num=[](unsigned maximum){return Json{{"type","integer"},{"minimum",0},{"maximum",maximum}};};
 auto addr=Json{{"type","string"},{"description","Virtual address, for example 0x140001000"}};
 auto add=[&](const char* name,const char* description,Json props,Json required,bool readonly){tools.push_back({{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",props},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readonly},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("open_binary","Open a local x86/x64 PE, ELF, or raw binary.",{{"path",str("Absolute file path")},{"base",addr},{"bits",{{"type","integer"},{"enum",{32,64}}}}},{"path"},false);
 add("get_binary_info","Read executable metadata and memory sections.",Json::object(),Json::array(),true);
 add("list_functions","List indexed functions with pagination and optional name/address filtering.",{{"offset",num(1000000000)},{"limit",num(10000)},{"query",str("Case-sensitive name or address substring")}},Json::array(),true);
 add("disassemble","Read decoded instructions at a virtual address.",{{"address",addr},{"count",num(10000)}},{"address"},true);
 add("decompile","Read C pseudocode for a function. Repeated requests use the session cache.",{{"address",addr}},{"address"},true);
 add("analyze","Discover direct call targets. Default scans honor instruction_budget; full_scan scans all file-backed executable sections using parallel workers when indexed boundaries are available. Reports include exact byte coverage; this does not recover pseudocode for every function.",{{"instruction_budget",num(1000000)},{"full_scan",{{"type","boolean"}}}},Json::array(),false);
 add("list_strings","Scan printable ASCII strings on demand, with pagination and filtering (first 100000 strings).",{{"offset",num(1000000000)},{"limit",num(10000)},{"query",str("Case-sensitive substring")}},Json::array(),true);
 add("list_imports","List imported PE symbols and their import address table locations.",Json::object(),Json::array(),true);
 add("read_bytes","Read up to 65536 mapped bytes as hexadecimal without modifying the binary.",{{"address",addr},{"count",num(65536)}},{"address"},true);
 add("rename_function","Rename an indexed function in this session using a C identifier.",{{"address",addr},{"name",str("C identifier, up to 128 characters")}},{"address","name"},false);
 add("save_project","Save indexed functions, names, signatures, annotations, and staged patches to a local .scratcher project.",{{"path",str("Absolute destination project path")}},{"path"},false);
 add("load_project","Open a .scratcher project, verify its binary identity, and restore the saved workspace.",{{"path",str("Absolute project path")}},{"path"},false);
 for(auto& tool:extraTools())tools.push_back(std::move(tool));
 for(auto& tool:powerTools())tools.push_back(std::move(tool));
 for(auto& tool:advancedTools())tools.push_back(std::move(tool));
 tools.push_back(batchToolDefinition());
 for(auto& tool:tools)boundSchema(tool["inputSchema"]);
 return tools;
 }();
 auto tools=base;for(auto& tool:sdkPluginTools(engine_)){boundSchema(tool["inputSchema"]);tools.push_back(std::move(tool));}
 return tools;
}
Json Tools::list()const {auto tools=localList();if(backend_)for(auto tool:backend_->toolDefinitions()){boundSchema(tool["inputSchema"]);tools.push_back(std::move(tool));}return tools;}
namespace {
const std::map<std::string,Json>& localSchemas(){static const auto schemas=[](){Engine probe;Tools tools(probe);std::map<std::string,Json> result;for(auto& tool:tools.localList())result.emplace(tool.at("name").get<std::string>(),tool.at("inputSchema"));return result;}();return schemas;}
}
void Tools::validate(const std::string& name,const Json& args)const {if(localSchemas().contains(name)||name.starts_with("plugin.")){validateLocal(name,args);return;}if(backend_){validateDefinition(backend_->toolDefinitions(),name,args);return;}throw std::runtime_error("Unknown tool: "+name);}
void Tools::validateLocal(const std::string& name,const Json& args)const {if(!args.is_object())throw std::runtime_error("Tool arguments must be an object");if(auto it=localSchemas().find(name);it!=localSchemas().end()){validateArgument(args,it->second,"");return;}validateDefinition(sdkPluginTools(engine_),name,args);}
Json Tools::call(const std::string& name,const Json& args) {validate(name,args);if(backend_)if(auto result=backend_->invoke(name,args))return *result;return callLocal(name,args);}
Json Tools::callLocal(const std::string&name,const Json&a) try {
 validateLocal(name,a);
 EditHistoryGuard editGuard(engine_,name);
 if(name=="batch_tools")return executeToolBatch(engine_,*this,a);
 if(name=="open_binary")return engine_.open(std::filesystem::u8path(a.at("path").get<std::string>()),a.contains("base")?address(a["base"]):0x1000,a.value("bits",64));
 if(name=="load_project")return engine_.loadProject(std::filesystem::u8path(a.at("path").get<std::string>()));
 if(name=="save_project")return engine_.saveProject(std::filesystem::u8path(a.at("path").get<std::string>()));
 if(auto result=callAdvancedTool(engine_,name,a))return *result;
 if(!engine_.binary())throw std::runtime_error("Open a binary first");
 if(name=="get_binary_info")return engine_.binary()->info();
 if(name=="list_functions")return engine_.listFunctions(a.value("offset",size_t(0)),a.value("limit",size_t(500)),a.value("query",std::string()));
 if(name=="list_strings")return engine_.listStrings(a.value("offset",size_t(0)),a.value("limit",size_t(500)),a.value("query",std::string()));
 if(name=="disassemble"){Json out=Json::array();for(auto&i:engine_.disassemble(address(a.at("address")),a.value("count",size_t(100))))out.push_back({{"address",hex(i.va)},{"length",i.length},{"mnemonic",i.mnemonic},{"operands",i.operands},{"display_operands",manualDisplayedOperands(engine_,i)},{"classification",manualClassification(engine_,i.va).value_or("undefined")},{"bytes",i.bytes},{"prefixes",i.prefixes}});return {{"instructions",out}};}
 if(name=="decompile")return engine_.decompile(address(a.at("address")));
 if(name=="analyze")return engine_.analyze(a.value("instruction_budget",size_t(100000)),a.value("full_scan",false));
 if(name=="read_bytes")return engine_.readBytes(address(a.at("address")),a.value("count",size_t(256)));
 if(name=="rename_function")return engine_.rename(address(a.at("address")),a.at("name"));
 if(name=="list_imports"){Json rows=Json::array();for(auto&i:engine_.binary()->imports)rows.push_back({{"address",hex(i.va)},{"module",i.module},{"name",i.name}});return {{"items",rows}};}
 if(auto result=callExtraTool(engine_,name,a))return *result;
 if(auto result=callPowerTool(engine_,name,a))return *result;
 throw std::runtime_error("Unknown tool");
}catch(const ghidra::LowlevelError&e){throw std::runtime_error(e.explain);}
Json Tools::rpc(const Json& request) {
 Json id=nullptr;
 if(request.is_object()&&request.contains("id")&&(request["id"].is_string()||request["id"].is_number_integer()))id=request["id"];
 auto error=[&](int code,const std::string& message){return rpcError(id,code,message);};
 if(!request.is_object()||!request.contains("jsonrpc")||request["jsonrpc"]!="2.0"||
    !request.contains("method")||!request["method"].is_string()||
    (request.contains("id")&&id.is_null()))return error(-32600,"Invalid JSON-RPC request");
 const auto method=request["method"].get<std::string>();
 const bool notification=!request.contains("id");
 if(request.contains("params")&&!request["params"].is_object())return notification?Json():error(-32602,"Parameters must be an object");
 const auto params=request.value("params",Json::object());
 if(notification) {
  if(method=="notifications/initialized"&&initialized_)ready_=true;
  // Requests run sequentially. A cancellation received after a result is
  // complete has no active request to cancel, as permitted by MCP.
  return Json();
 }
 if(method!="initialize"&&method!="ping"&&!ready_)return error(-32002,"Complete MCP initialization first");
 Json result;
 try {
  if(method=="initialize") {
   if(initialized_)return error(-32600,"This session is already initialized");
   if(!params.contains("protocolVersion")||!params["protocolVersion"].is_string())return error(-32602,"protocolVersion must be a string");
   if(params.contains("capabilities")&&!params["capabilities"].is_object())return error(-32602,"capabilities must be an object");
   if(params.contains("clientInfo")&&(!params["clientInfo"].is_object()||
      !params["clientInfo"].contains("name")||!params["clientInfo"]["name"].is_string()||
      !params["clientInfo"].contains("version")||!params["clientInfo"]["version"].is_string()))return error(-32602,"clientInfo requires name and version strings");
   auto version=params["protocolVersion"].get<std::string>();
   if(version!="2025-11-25"&&version!="2025-06-18"&&version!="2025-03-26"&&version!="2024-11-05")version="2025-11-25";
   Json capabilities={{"tools",{{"listChanged",false}}}};
   resourcesEnabled_=backend_&&!backend_->resourcesList().value("resources",Json::array()).empty();
   promptsEnabled_=backend_&&!backend_->promptsList().value("prompts",Json::array()).empty();
   if(resourcesEnabled_)capabilities["resources"]={{"subscribe",false},{"listChanged",false}};
   if(promptsEnabled_)capabilities["prompts"]={{"listChanged",false}};
   initialized_=true;ready_=false;
   result={{"protocolVersion",version},{"capabilities",capabilities},
    {"serverInfo",{{"name","Scratcher"},{"version","0.8.0"}}},
    {"instructions","Use get_session and get_workspace_state to inspect your workspace. Open a binary or load a project, then inspect functions, pseudocode, references, and graphs. Add names, comments, bookmarks, and types; save the project to keep changes. Use discover_sessions and attach_session to control an open Scratcher workspace. Submit long operations as jobs and poll their status; cancellation is cooperative. Use absolute local file paths."}};
  }
  else if(method=="ping")result=Json::object();
  else if(method=="tools/list") {
   if(params.contains("cursor"))return error(-32602,"Tool discovery does not use pagination cursors");
   result={{"tools",list()}};
  }
  else if(method=="resources/list"||method=="resources/templates/list") {
   if(!resourcesEnabled_||!backend_)return error(-32601,"Resources are unavailable");
   if(params.contains("cursor"))return error(-32602,"Resource discovery does not use pagination cursors");
   result=method=="resources/list"?backend_->resourcesList():Json{{"resourceTemplates",Json::array()}};
  }
  else if(method=="resources/read") {
   if(!resourcesEnabled_||!backend_)return error(-32601,"Resources are unavailable");
   if(!params.contains("uri")||!params["uri"].is_string()||!validResourceUri(params["uri"].get<std::string>()))return error(-32602,"Expected a valid absolute resource URI");
   try{result=backend_->resourceRead(params["uri"].get<std::string>());}
   catch(const ToolBackendError& exception){return error(exception.code(),exception.what());}
   catch(const std::exception& exception){return error(-32603,exception.what());}
  }
  else if(method=="prompts/list") {
   if(!promptsEnabled_||!backend_)return error(-32601,"Prompts are unavailable");
   if(params.contains("cursor"))return error(-32602,"Prompt discovery does not use pagination cursors");
   result=backend_->promptsList();
  }
  else if(method=="prompts/get") {
   if(!promptsEnabled_||!backend_)return error(-32601,"Prompts are unavailable");
   if(!params.contains("name")||!params["name"].is_string())return error(-32602,"Prompt name must be a string");
   const auto name=params["name"].get<std::string>();
   const auto arguments=params.value("arguments",Json::object());
   if(!arguments.is_object())return error(-32602,"Prompt arguments must be an object of strings");
   const auto prompts=backend_->promptsList().value("prompts",Json::array());
   auto prompt=std::find_if(prompts.begin(),prompts.end(),[&](const Json& candidate){return candidate["name"]==name;});
   if(prompt==prompts.end())return error(-32602,"Unknown prompt: "+name);
   Json properties=Json::object(),required=Json::array();
   for(const auto& argument:prompt->value("arguments",Json::array())){const auto key=argument.at("name").get<std::string>();properties[key]={{"type","string"},{"maxLength",65536}};if(argument.value("required",false))required.push_back(key);}
   validateArgument(arguments,{{"type","object"},{"properties",properties},{"required",required},{"additionalProperties",false}},"arguments");
   result=backend_->promptGet(name,arguments);
  }
  else if(method=="tools/call") {
   if(!params.contains("name")||!params["name"].is_string())return error(-32602,"Tool name must be a string");
   if(params.contains("arguments")&&!params["arguments"].is_object())return error(-32602,"Tool arguments must be an object");
   const auto name=params["name"].get<std::string>();
   const auto definitions=list();
   if(std::none_of(definitions.begin(),definitions.end(),[&](const Json& tool){return tool["name"]==name;}))return error(-32602,"Unknown tool: "+name);
   try {
    auto value=call(name,params.value("arguments",Json::object()));
    const auto structured=value.is_object()?value:Json{{"items",value}};
    result={{"content",Json::array({{{"type","text"},{"text",value.dump()}}})},{"structuredContent",structured},{"isError",false}};
   }catch(const std::exception& exception) {
    result={{"content",Json::array({{{"type","text"},{"text",exception.what()}}})},{"isError",true}};
   }
  }
  else return error(-32601,"Method not found");
 }catch(const std::exception& exception){return error(-32602,exception.what());}
 return {{"jsonrpc","2.0"},{"id",id},{"result",result}};
}
int runMCP(const std::string& desktopId) {
#ifdef _WIN32
 _setmode(_fileno(stdin),_O_BINARY);
 _setmode(_fileno(stdout),_O_BINARY);
#endif
 std::ios::sync_with_stdio(false);
 std::cin.tie(nullptr);
 Engine engine;Tools tools(engine);auto backend=createAutomationBackend(engine,tools,desktopId);tools.setBackend(backend.get());std::string line;line.reserve(4096);bool oversized=false;
 auto write=[](const Json& response){if(!response.is_null())std::cout<<response.dump()<<'\n'<<std::flush;};
 while(readMessage(std::cin,line,oversized)) {
  if(oversized){write(rpcError(nullptr,-32600,"MCP message exceeds 1 MiB"));continue;}
  if(line.empty())continue;
  try {write(tools.rpc(Json::parse(line)));}
  catch(const Json::parse_error&){write(rpcError(nullptr,-32700,"Invalid JSON"));}
  catch(const std::exception&){write(rpcError(nullptr,-32603,"Unable to process request"));}
 }
 return std::cin.bad()?1:0;
}
}
