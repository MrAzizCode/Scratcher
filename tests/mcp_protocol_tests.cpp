#include "core.hpp"
#include "tool_backend.hpp"
#include <fstream>
#include <iostream>
#include <set>
#include <limits>
using namespace scratcher;
namespace {
int checks=0;
void check(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
Json request(const std::string& method,Json params=Json::object(),Json id=1){return {{"jsonrpc","2.0"},{"id",id},{"method",method},{"params",params}};}
void expectError(const Json& response,int code,const char* message){check(response.contains("error")&&response["error"]["code"]==code,message);}
Json invoke(Tools& tools,const std::string& name,Json args=Json::object()){
 auto response=tools.rpc(request("tools/call",{{"name",name},{"arguments",args}}));
 check(response.contains("result"),"tool has JSON-RPC result");
 if(response["result"].value("isError",false))throw std::runtime_error(response["result"]["content"][0]["text"].get<std::string>());
 check(response["result"]["structuredContent"].is_object(),"structured content must be an object");
 return response["result"]["structuredContent"];
}
struct StubBackend final:ToolBackend {
 int calls=0;
 Json toolDefinitions()const override {
  Json item={{"type","object"},{"required",{"amount","tag","location"}},{"additionalProperties",false}};
  item["properties"]["amount"]={{"type","number"},{"minimum",0}};
  item["properties"]["tag"]={{"type","string"},{"maxLength",3}};
  item["properties"]["location"]={{"type","string"},{"format","address"},{"maxLength",32}};
  Json array={{"type","array"},{"minItems",1},{"maxItems",3},{"uniqueItems",true},{"items",item}};
  Json schema={{"type","object"},{"required",{"items"}},{"additionalProperties",false}};
  schema["properties"]["items"]=array;
  return Json::array({Json{{"name","control_probe"},{"description","Protocol test control"},{"inputSchema",schema}}});
 }
 std::optional<Json> invoke(const std::string& name,const Json& args)override {if(name!="control_probe")return std::nullopt;++calls;return Json{{"accepted",args.at("items").size()}};}
 Json resourcesList()const override {return {{"resources",Json::array({{{"uri","scratcher://session/state"},{"name","Workspace state"},{"mimeType","application/json"},{"annotations",{{"audience",{"assistant"}},{"priority",1.0}}}}})}};}
 Json resourceRead(const std::string& uri)override {if(uri=="scratcher://internal")throw std::runtime_error("Unavailable workspace");if(uri!="scratcher://session/state")throw ToolBackendError(-32002,"Resource not found");return {{"contents",Json::array({{{"uri",uri},{"mimeType","application/json"},{"text","{\"open\":false}"}}})}};}
 Json promptsList()const override {return {{"prompts",Json::array({{{"name","inspect"},{"description","Inspect function"},{"arguments",Json::array({{{"name","address"},{"required",true}}})}}})}};}
 Json promptGet(const std::string&,const Json& args)override {
  Json content={{"type","text"},{"text","Inspect "+args.at("address").get<std::string>()},{"annotations",{{"audience",{"assistant"}}}}};
  return {{"description","Inspect function"},{"messages",Json::array({Json{{"role","user"},{"content",content}}})}};
 }
};
}
int main(){try{
 Engine session;Tools tools(session);
 expectError(tools.rpc(Json::array()),-32600,"batch is rejected");
 expectError(tools.rpc({{"jsonrpc","1.0"},{"id",1},{"method","ping"}}),-32600,"invalid version rejected");
 expectError(tools.rpc(request("ping",Json::object(),nullptr)),-32600,"null request id rejected");
 expectError(tools.rpc(request("ping",Json::object(),1.5)),-32600,"fractional request id rejected");
 expectError(tools.rpc(request("ping",Json::array())),-32602,"array params rejected");
 expectError(tools.rpc(request("tools/list")),-32002,"tools unavailable before init");
 check(tools.rpc({{"jsonrpc","2.0"},{"method","notifications/initialized"}}).is_null(),"premature notification is silent");
 expectError(tools.rpc(request("tools/list")),-32002,"premature notification does not initialize");
 expectError(tools.rpc(request("initialize",{{"protocolVersion",42}})),-32602,"bad initialize params rejected");
 auto init=tools.rpc(request("initialize",{{"protocolVersion","future-version"},{"capabilities",Json::object()},{"clientInfo",{{"name","protocol-tests"},{"version","1"}}}},"init-id"));
 check(init["id"]=="init-id","string id echoed");
 check(init["result"]["protocolVersion"]=="2025-11-25","unsupported version negotiated");
 check(init["result"]["serverInfo"]["name"]=="Scratcher","server identity");
 check(init["result"]["serverInfo"]["version"]=="0.8.0","server version");
 check(!init["result"]["capabilities"].contains("resources")&&!init["result"]["capabilities"].contains("prompts"),"unsupported capabilities omitted");
 expectError(tools.rpc(request("tools/list")),-32002,"initialized notification required");
 check(tools.rpc(request("ping"))["result"].is_object(),"ping allowed during init");
 check(tools.rpc({{"jsonrpc","2.0"},{"method","notifications/initialized"},{"params",Json::array()}}).is_null(),"invalid notification is silent");
 expectError(tools.rpc(request("tools/list")),-32002,"invalid notification does not ready session");
 tools.rpc({{"jsonrpc","2.0"},{"method","notifications/initialized"}});
 expectError(tools.rpc(request("initialize",{{"protocolVersion","2025-11-25"}})),-32600,"duplicate initialize rejected");
 expectError(tools.rpc(request("missing-method")),-32601,"unknown method rejected");
 expectError(tools.rpc(request("resources/list")),-32601,"unavailable resources rejected");
 expectError(tools.rpc(request("prompts/list")),-32601,"unavailable prompts rejected");
 expectError(tools.rpc(request("tools/call",Json::object())),-32602,"missing tool name rejected");
 expectError(tools.rpc(request("tools/call",{{"name",42}})),-32602,"non-string tool name rejected");
 expectError(tools.rpc(request("tools/call",{{"name","missing-tool"}})),-32602,"unknown tool rejected");
 expectError(tools.rpc(request("tools/call",{{"name","read_bytes"},{"arguments",nullptr}})),-32602,"null tool args rejected");
 expectError(tools.rpc(request("tools/list",{{"cursor","invalid"}})),-32602,"unsupported discovery cursor rejected");
 const auto definitions=tools.rpc(request("tools/list"))["result"]["tools"];
 check(definitions.size()>=37,"all local tools discovered");
 std::set<std::string> names;
 for(const auto& tool:definitions){check(names.insert(tool["name"].get<std::string>()).second,"unique tool names");check(tool["inputSchema"].is_object(),"tool schema is an object");}
 for(const auto* name:{"open_binary","decompile","get_control_flow","get_cross_references","get_call_graph","set_comment","list_annotations","set_function_signature","get_function_types","stage_patch","search_bytes","batch_tools"})check(names.contains(name),"expected tool discovered");
 auto missing=tools.rpc(request("tools/call",{{"name","read_bytes"},{"arguments",Json::object()}}));
 check(missing["result"]["isError"]==true,"schema failure returns tool error");
 auto fixture=executableDir()/"test-fixtures"/"mcp-protocol.bin";std::filesystem::create_directories(fixture.parent_path());
 std::vector<unsigned char> bytes(64,0x90);bytes[0]=0xb8;bytes[1]=42;bytes[2]=bytes[3]=bytes[4]=0;bytes[5]=0xc3;
 {std::ofstream out(fixture,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
 invoke(tools,"open_binary",{{"path",pathText(fixture)}});
 invoke(tools,"set_comment",{{"address","0x1000"},{"text","UTF-8 note: \xD8\xAA\xD8\xAD\xD9\x84\xD9\x8A\xD9\x84"}});
 invoke(tools,"set_bookmark",{{"address","0x1000"},{"name","Entry"}});
 const auto notes=invoke(tools,"list_annotations");
 check(notes.dump().find("UTF-8 note:")!=std::string::npos,"comments returned through MCP");
 const auto graph=invoke(tools,"get_control_flow",{{"address","0x1000"},{"instruction_budget",32}});
 check(!graph["nodes"].empty(),"control-flow tool returns blocks");
 invoke(tools,"set_function_signature",{{"address","0x1000"},{"declaration","int return42(void);"}});
 check(invoke(tools,"get_function_types",{{"address","0x1000"}})["signature"].is_string(),"types tool returns signature");
 for(const auto& arguments:{Json{{"address","0x1000"},{"outgoing",1}},Json{{"address","0x1000"},{"instruction_budget",-1}},Json{{"address","0x1000"},{"unexpected",true}}}) {
  auto invalid=tools.rpc(request("tools/call",{{"name","get_cross_references"},{"arguments",arguments}}));check(invalid["result"]["isError"]==true,"extra schema validated");
 }
 auto huge=tools.rpc(request("tools/call",{{"name","read_bytes"},{"arguments",{{"address","0x1000"},{"count",uint64_t(-1)}}}}));check(huge["result"]["isError"]==true,"large unsigned bound enforced");
 check(tools.rpc({{"jsonrpc","2.0"},{"method","notifications/cancelled"},{"params",{{"requestId",1}}}}).is_null(),"late cancellation remains silent");
 check(tools.rpc(request("ping",Json::object(),"after-cancel"))["id"]=="after-cancel","session remains usable after late cancellation");
 Engine controlSession;Tools controlled(controlSession);StubBackend backend;controlled.setBackend(&backend);
 auto controlInit=controlled.rpc(request("initialize",{{"protocolVersion","2025-06-18"}}));
 check(controlInit["result"]["protocolVersion"]=="2025-06-18","supported older version preserved");
 check(controlInit["result"]["capabilities"].contains("resources")&&controlInit["result"]["capabilities"].contains("prompts"),"resource and prompt capabilities advertised");
 controlled.rpc({{"jsonrpc","2.0"},{"method","notifications/initialized"}});
 check(controlled.list().size()==controlled.localList().size()+1,"backend definitions appended");
 check(controlled.rpc(request("resources/list"))["result"]["resources"][0]["annotations"]["priority"]==1.0,"resource annotations retained");
 check(controlled.rpc(request("resources/templates/list"))["result"]["resourceTemplates"].empty(),"unsupported resource templates empty");
 auto resource=controlled.rpc(request("resources/read",{{"uri","scratcher://session/state"}}));
 check(resource["result"]["contents"][0]["text"]=="{\"open\":false}","resource contents routed without tool wrapping");
 for(const char* uri:{"relative","scratcher://bad uri","scratcher://bad%GG","scratcher://bad\\path","scratcher://bad<path"})expectError(controlled.rpc(request("resources/read",{{"uri",uri}})),-32602,"malformed resource URI rejected");
 expectError(controlled.rpc(request("resources/read",{{"uri","scratcher://missing"}})),-32002,"missing resource error code");
 expectError(controlled.rpc(request("resources/read",{{"uri","scratcher://internal"}})),-32603,"internal resource failures distinguished");
 expectError(controlled.rpc(request("resources/list",{{"cursor","invalid"}})),-32602,"resource cursor rejected");
 check(controlled.rpc(request("prompts/list"))["result"]["prompts"][0]["name"]=="inspect","prompts discovered");
 auto prompt=controlled.rpc(request("prompts/get",{{"name","inspect"},{"arguments",{{"address","0x1000"}}}}));
 check(prompt["result"]["messages"][0]["content"]["text"]=="Inspect 0x1000","prompt arguments routed");
 check(prompt["result"]["messages"][0]["content"]["annotations"].contains("audience"),"prompt content annotations retained");
 for(const auto& arguments:{Json::object(),Json{{"address",42}},Json{{"address","0x1000"},{"extra","bad"}}})expectError(controlled.rpc(request("prompts/get",{{"name","inspect"},{"arguments",arguments}})),-32602,"prompt argument shape validated");
 expectError(controlled.rpc(request("prompts/get",{{"name","missing"}})),-32602,"unknown prompt rejected");
 const Json goodItem={{"amount",1.5},{"tag","ok"},{"location","0x1000"}};
 check(invoke(controlled,"control_probe",{{"items",Json::array({goodItem})}})["accepted"]==1,"backend control invoked");
 check(backend.calls==1,"backend invocation count");
 controlled.validate("control_probe",{{"items",Json::array({{{"amount",1},{"tag","\xD8\xAA\xD8\xAD\xD9\x84"},{"location","0x1000"}}})}});
 check(true,"schema string lengths count Unicode characters");
 for(const auto& args:{Json{{"items",Json::array()}},Json{{"items",Json::array({goodItem,goodItem})}},Json{{"items",Json::array({{{"amount",-1},{"tag","ok"},{"location","0x1000"}}})}},Json{{"items",Json::array({{{"amount",1},{"tag","long"},{"location","0x1000"}}})}},Json{{"items",Json::array({{{"amount",1},{"tag","ok"},{"location",std::string(64,'1')}}})}}}) {
  auto response=controlled.rpc(request("tools/call",{{"name","control_probe"},{"arguments",args}}));check(response["result"]["isError"]==true,"nested schemas enforced before invoking control");
 }
 bool infiniteRejected=false;try{controlled.validate("control_probe",{{"items",Json::array({{{"amount",std::numeric_limits<double>::infinity()},{"tag","ok"},{"location","0x1000"}}})}});}catch(const std::exception&){infiniteRejected=true;}check(infiniteRejected,"nonfinite direct arguments rejected");
 check(backend.calls==1,"invalid control arguments have no side effects");
 bool localRejected=false;try{controlled.callLocal("control_probe",{{"items",Json::array({goodItem})}});}catch(const std::exception&){localRejected=true;}check(localRejected,"local executor excludes control tools");
 check(backend.calls==1,"local executor never recurses through control backend");
 auto fallback=invoke(controlled,"open_binary",{{"path",pathText(fixture)}});check(fallback["entry"]=="0x1000","unhandled base tools fall back to local executor");
 std::cout<<"PASS: "<<checks<<" MCP protocol checks\n";return 0;
 }catch(const std::exception& exception){std::cerr<<"FAIL after "<<checks<<" checks: "<<exception.what()<<'\n';return 1;}}
