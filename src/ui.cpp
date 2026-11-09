#include <windows.h>
#include <d3d11.h>
#include <shellapi.h>
#include <commdlg.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "core.hpp"
#include "feature_automation_jobs.hpp"
#include "feature_desktop.hpp"
#include "feature_bridge.hpp"
#include "feature_navigation.hpp"
#include "ui_extra.hpp"
#include "ui_workspace.hpp"
#include <chrono>
#include <fstream>
#include <algorithm>
#include <set>
using namespace scratcher;
static ID3D11Device* device=nullptr;static ID3D11DeviceContext* context=nullptr;
static IDXGISwapChain* swapchain=nullptr;static ID3D11RenderTargetView* target=nullptr;
static std::filesystem::path dropped;
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);
static void makeTarget(){ID3D11Texture2D* back=nullptr;if(SUCCEEDED(swapchain->GetBuffer(0,IID_PPV_ARGS(&back)))){device->CreateRenderTargetView(back,nullptr,&target);back->Release();}}
static LRESULT CALLBACK windowProc(HWND w,UINT m,WPARAM p,LPARAM l){if(ImGui_ImplWin32_WndProcHandler(w,m,p,l))return true;switch(m){case WM_SIZE:if(device&&p!=SIZE_MINIMIZED){if(target){target->Release();target=nullptr;}swapchain->ResizeBuffers(0,LOWORD(l),HIWORD(l),DXGI_FORMAT_UNKNOWN,0);makeTarget();}return 0;case WM_DROPFILES:{wchar_t path[32768];DragQueryFileW((HDROP)p,0,path,32768);dropped=path;DragFinish((HDROP)p);return 0;}case WM_DESTROY:PostQuitMessage(0);return 0;case WM_SYSCOMMAND:if((p&0xfff0)==SC_KEYMENU)return 0;}return DefWindowProcW(w,m,p,l);}
static std::filesystem::path dialog(HWND window,bool save,const wchar_t* filter,const wchar_t* ext=nullptr){wchar_t path[32768]{};OPENFILENAMEW of{};of.lStructSize=sizeof(of);of.hwndOwner=window;of.lpstrFile=path;of.nMaxFile=32768;of.lpstrFilter=filter;of.lpstrDefExt=ext;of.Flags=OFN_NOCHANGEDIR|OFN_PATHMUSTEXIST|(save?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);return (save?GetSaveFileNameW(&of):GetOpenFileNameW(&of))?std::filesystem::path(path):std::filesystem::path();}
static ImVec4 accent={0.40f,0.89f,0.76f,1},muted={0.49f,0.56f,0.63f,1};
static void theme(){auto&s=ImGui::GetStyle();s.WindowPadding={18,14};s.FramePadding={12,7};s.ItemSpacing={10,8};s.WindowRounding=0;s.ChildRounding=8;s.FrameRounding=5;s.PopupRounding=7;s.TabRounding=5;s.ScrollbarRounding=5;s.WindowBorderSize=0;s.ChildBorderSize=1;s.FrameBorderSize=0;
 auto*c=s.Colors;c[ImGuiCol_Text]={0.85f,0.89f,0.92f,1};c[ImGuiCol_TextDisabled]=muted;c[ImGuiCol_WindowBg]={0.045f,0.059f,0.08f,1};c[ImGuiCol_ChildBg]={0.063f,0.078f,0.10f,1};c[ImGuiCol_PopupBg]={0.075f,0.09f,0.12f,1};c[ImGuiCol_Border]={0.13f,0.17f,0.21f,1};c[ImGuiCol_FrameBg]={0.10f,0.13f,0.16f,1};c[ImGuiCol_FrameBgHovered]={0.15f,0.20f,0.24f,1};c[ImGuiCol_FrameBgActive]={0.17f,0.24f,0.28f,1};c[ImGuiCol_Button]={0.10f,0.16f,0.19f,1};c[ImGuiCol_ButtonHovered]={0.15f,0.28f,0.29f,1};c[ImGuiCol_ButtonActive]={0.18f,0.35f,0.32f,1};c[ImGuiCol_Header]={0.12f,0.24f,0.25f,1};c[ImGuiCol_HeaderHovered]={0.14f,0.29f,0.29f,1};c[ImGuiCol_HeaderActive]={0.18f,0.34f,0.33f,1};c[ImGuiCol_Tab]={0.075f,0.10f,0.13f,1};c[ImGuiCol_TabHovered]={0.15f,0.25f,0.26f,1};c[ImGuiCol_TabSelected]={0.12f,0.20f,0.22f,1};c[ImGuiCol_TabSelectedOverline]=accent;c[ImGuiCol_CheckMark]=accent;c[ImGuiCol_SliderGrab]=accent;c[ImGuiCol_Separator]={0.13f,0.17f,0.21f,1};}
static void label(const char*s){ImGui::TextColored(muted,"%s",s);}
static std::vector<std::string> lines(const std::string&s){std::vector<std::string> out;std::istringstream in(s);std::string line;while(std::getline(in,line))out.push_back(line);return out;}
static void codeView(const std::vector<std::string>& rows,ImFont* mono){ImGui::PushFont(mono,17.0f);ImGui::BeginChild("code_scroll",{0,0},ImGuiChildFlags_None,ImGuiWindowFlags_HorizontalScrollbar);ImGuiListClipper clip;clip.Begin((int)rows.size());while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){ImGui::TextColored(muted,"%4d",i+1);ImGui::SameLine(65);auto&line=rows[i];if(line.find("/*")!=std::string::npos||line.find("//")!=std::string::npos)ImGui::TextColored({0.40f,0.55f,0.49f,1},"%s",line.c_str());else if(line.find("return")!=std::string::npos||line.find("if (")!=std::string::npos||line.find("void ")!=std::string::npos||line.find("int ")!=std::string::npos)ImGui::TextColored({0.61f,0.76f,0.96f,1},"%s",line.c_str());else ImGui::TextUnformatted(line.c_str());}ImGui::EndChild();ImGui::PopFont();}
static std::string operationName(const std::string& name) {
 static const std::map<std::string,std::string> names={{"navigate","Navigating"},{"open_binary","Opening binary"},{"load_project","Opening project"},{"save_project","Saving project"},{"analyze","Analyzing code"},{"get_control_flow","Building graph"},{"get_cross_references","Finding references"},{"get_call_graph","Building call graph"},{"set_comment","Saving comment"},{"set_bookmark","Saving bookmark"},{"set_function_signature","Applying signature"},{"stage_patch","Staging patch"},{"export_patched","Exporting copy"},{"search_bytes","Searching bytes"},{"discover_strings","Finding text"}};
 auto it=names.find(name);return it==names.end()?std::string("Updating workspace"):it->second;
}
struct Desktop {
 Engine engine; Tools tools{engine};
 bool busy=false; std::string status="Ready",lastError,bridgeError;
 Json info,functions=Json::array(),assembly=Json::array(),strings=Json::array(),imports=Json::array(),toolResult,location,workspace;
 std::string code="Select a function to view its pseudocode.",byteText;
 std::vector<std::string> codeLines=lines(code);
 std::map<size_t,std::vector<std::string>> pseudocodeAddresses;
 Address selected=0;bool pseudocodeReady=false;char search[512]{},gotoText[64]{},renameText[129]{},stringSearch[128]{};char args[16384]="{}";
 int toolIndex=0;std::vector<std::string> history;double lastMs=0,busySince=0;bool navigatePending=false;
 bool focusGoto=false,renameRequested=false,graphMode=false;std::string tabRequest,activeView="Overview",renderedView="Overview";NavigationHistory navigation;ExtraViews extras;WorkbenchView workbench;WorkspaceLayout layout;
 size_t functionOffset=0,functionTotal=0;std::string functionQuery;bool functionRefresh=false;
 uint64_t latestNavigation=0;DesktopMailbox mailbox;std::atomic_bool closing=false;AutomationJobs queue;
 std::unique_ptr<BridgeServer> bridge;
 Desktop():queue([this](const std::string&name,const Json&a,std::atomic_bool&cancelled)->Json {
  engine.setCancellation(&cancelled);
  struct Guard {Engine& engine;~Guard(){engine.setCancellation(nullptr);}} guard{engine};
  auto start=std::chrono::steady_clock::now();Json data;
  if(name=="navigate") {
   auto va=address(a.at("address"));if(!engine.binary())throw std::runtime_error("Open a binary first");
   auto where=describeAddress(*engine.binary(),va);if(!where["mapped"].get<bool>())throw std::runtime_error("Address is outside the memory map");
   data["location"]=where;
   if(engine.binary()->analysisCode(va)) {
    Address function=where["function"].is_object()?address(where["function"]["address"]):va;
    if(a.value("view",std::string("Disassembly"))=="Pseudocode"||a.value("preview_pseudocode",false)) {try{data["decompilation"]=tools.call("get_pseudocode_mapping",{{"address",hex(function)},{"limit",10000}});}catch(const std::exception&e){data["decompilation"]={{"code",std::string("Pseudocode unavailable: ")+e.what()}};}}
    else data["decompilation"]={{"code","Open Pseudocode to analyze this function."},{"deferred",true}};
    if(cancelled.load())throw std::runtime_error("Operation cancelled");
    data["disassembly"]=tools.call("disassemble",{{"address",hex(va)},{"count",512}});
    for(auto&row:data["disassembly"]["instructions"]){Instruction instruction{address(row["address"]),row["length"],row["mnemonic"],row["operands"],row["bytes"]};auto resolvedTarget=operandTarget(*engine.binary(),instruction);row["target"]=resolvedTarget?Json(hex(*resolvedTarget)):Json(nullptr);}
   }else {data["decompilation"]={{"code","Selected address contains data."}};data["disassembly"]={{"instructions",Json::array()}};}
   auto*section=engine.binary()->section(va);auto count=std::min<uint64_t>(256,section->memorySize-(va-section->va));data["bytes"]=engine.readBytes(va,(size_t)count);
   if(a.value("view",std::string())=="Graph"){data["view_tool"]="get_control_flow";data["view_data"]=tools.callLocal("get_control_flow",{{"address",hex(va)}});}
   if(a.value("view",std::string())=="References"){data["view_tool"]="get_cross_references";data["view_data"]=tools.callLocal("get_cross_references",{{"address",hex(va)}});}
   if(a.value("view",std::string())=="Types"){data["view_tool"]="get_function_types";data["view_data"]=tools.callLocal("get_function_types",{{"address",hex(va)}});}
  }else {try{data=tools.callLocal(name,a);}catch(...){if(!cancelled.load())throw;data={{"cancelled",true}};}}
  Json result={{"data",data},{"job_ms",std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count()}};
  if(engine.binary()){
   result["info"]=engine.binary()->info();result["workspace"]=engine.workspaceState();
   if(name=="open_binary"||name=="open_binary_architecture"||name=="load_project"||name=="load_analysis_database")result["function_page"]=engine.listFunctions(0,500);
   static const std::set<std::string> indexChanges={"run_auto_analysis","analyze_code_paths","analyze","analyze_reachable","analyze_advanced","discover_reachable_functions","rename_function","set_function_signature","batch_tools","create_function","delete_function","set_function_bounds","split_function","merge_functions","load_debug_symbols","undo","redo"};
   if(indexChanges.contains(name))result["refresh_functions"]=true;
   if(name=="batch_tools"&&!data.value("dry_run",false)&&data.contains("items"))for(auto&item:data["items"])if(item.value("success",false)){auto tool=item.value("tool",std::string());if(tool=="open_binary"||tool=="load_project")result["session_changed"]=true;if(tool=="rename_function"||tool=="set_function_signature"||tool=="set_variable_type")result["refresh_selection"]=true;}
  }return result;
 }) {
  extras.run=[this](const std::string&name,Json args){start(name,args);};
  extras.jump=[this](Address at){navigate(at);};
  workbench.run=extras.run;workbench.jump=extras.jump;
  layout.load(executableDir()/"config"/"workspace.json");extras.loadGraphViews(executableDir()/"config"/"graphs.json");
 }
 uint64_t start(const std::string&name,Json a,bool remote=false) {
  bool replaceable=name=="navigate"&&!remote;auto id=queue.submit(name,std::move(a),replaceable);
  if(replaceable)latestNavigation=id;busy=true;busySince=ImGui::GetTime();status=operationName(name)+"...";lastError.clear();
  return id;
 }
 void poll(){
  while(auto result=queue.poll()){
   auto&r=*result;
   if(r.cancelled&&(r.name=="navigate"||!r.result.is_object())){status="Cancelled";continue;}
   if(!r.error.empty()){lastError=r.error;status="Operation failed";history.push_back(operationName(r.name)+": "+r.error);continue;}
   auto&envelope=r.result;if(!envelope.is_object()||!envelope.contains("data")){toolResult=envelope;status="Result exceeds the retained output limit";continue;}auto data=envelope["data"];if(envelope.contains("info"))info=envelope["info"];if(envelope.contains("function_page")){functions=envelope["function_page"]["items"];functionTotal=envelope["function_page"].value("total",size_t(0));functionOffset=0;functionQuery.clear();search[0]=0;}if(envelope.value("refresh_functions",false))functionRefresh=true;if(envelope.contains("workspace"))workspace=envelope["workspace"];
   toolResult=data;lastMs=envelope.value("job_ms",0.0);status="Ready";history.push_back(operationName(r.name)+" / "+std::to_string((int)lastMs)+" ms");if(history.size()>100)history.erase(history.begin());
   if((r.name=="open_binary"||r.name=="open_binary_architecture"||r.name=="load_project"||r.name=="load_analysis_database"||envelope.value("session_changed",false))&&!data.value("cancelled",false)){
    selected=address(info["entry"]);navigation.clear();navigation.visit(selected);location=nullptr;code="Select a function to view its pseudocode.";pseudocodeReady=false;codeLines=lines(code);pseudocodeAddresses.clear();assembly=strings=imports=Json::array();byteText.clear();extras.clear();tabRequest=activeView="Overview";
   }
   if(info.is_object())extras.graphScope=info.value("path",std::string());extras.update(r.name,data,envelope.value("workspace",Json()));
   workbench.update(r.name,data);
   if(r.name=="list_functions"&&r.args.value("query",std::string())==std::string(search)){functions=data.value("items",Json::array());functionTotal=data.value("total",size_t(0));functionOffset=data.value("offset",size_t(0));functionQuery=r.args.value("query",std::string());}
   if(data.contains("view_tool"))extras.update(data["view_tool"],data["view_data"],workspace);
   if(r.name=="navigate"){selected=address(r.args["address"]);if(r.args.value("record",true))navigation.visit(selected);if(r.args.contains("view"))tabRequest=activeView=desktopView(r.args["view"]);location=data["location"];code=data["decompilation"]["code"];pseudocodeReady=!data["decompilation"].value("deferred",false);codeLines=lines(code);assembly=data["disassembly"]["instructions"];byteText=data["bytes"]["hex"];pseudocodeAddresses.clear();if(data["decompilation"].contains("lines"))for(auto& row:data["decompilation"]["lines"])pseudocodeAddresses[row["line"].get<size_t>()]=row["instruction_addresses"].get<std::vector<std::string>>();}
   if(r.name=="get_pseudocode_mapping"){pseudocodeReady=true;code=data["code"];codeLines=lines(code);pseudocodeAddresses.clear();for(auto& row:data.value("lines",Json::array()))pseudocodeAddresses[row["line"].get<size_t>()]=row["instruction_addresses"].get<std::vector<std::string>>();}
   if(r.name=="decompile"){pseudocodeAddresses.clear();pseudocodeReady=true;code=data["code"];codeLines=lines(code);tabRequest="Pseudocode";}
   if(r.name=="list_strings"||r.name=="discover_strings")strings=data["items"];
   if(r.name=="list_imports")imports=data["items"];
   if(r.name=="rename_function"||r.name=="set_function_signature"||r.name=="set_variable_type"||r.name=="undo"||r.name=="redo"||r.name=="set_operand_presentation"||r.name=="clear_operand_presentation"||r.name=="rename_variable"||r.name=="set_call_site_signature"||r.name=="set_indirect_call_target"||r.name=="force_pseudocode_goto"||r.name=="mark_multistage_jump"||r.name=="set_pseudocode_options"||r.name=="reset_pseudocode_controls"||r.name=="set_function_bounds"||r.name=="define_code"||r.name=="define_data"||envelope.value("refresh_selection",false))navigatePending=true;
   if(r.cancelled)status="Cancelled";
  }busy=queue.busy();
 }
 void navigate(Address va,bool record=true){auto view=tabRequest.empty()?activeView:tabRequest;if(view=="Overview")view="Disassembly";start("navigate",{{"address",hex(va)},{"record",record},{"view",view},{"preview_pseudocode",layout.splitPreview&&layout.preview=="Pseudocode"}});}
 void back(){if(auto va=navigation.back())navigate(*va,false);}
 void forward(){if(auto va=navigation.forward())navigate(*va,false);}
 Json state(bool views=false)const {
  Json result={{"binary",info},{"selected_address",info.is_null()?Json(nullptr):Json(hex(selected))},{"active_view",activeView},{"function_filter",search},{"function_count",functionTotal},{"function_page_offset",functionOffset},{"function_page_size",functions.size()},{"status",status},{"busy",queue.busy()},{"navigation",{{"can_back",navigation.canBack()},{"can_forward",navigation.canForward()},{"current",navigation.current()?Json(hex(*navigation.current())):Json(nullptr)}}},{"annotations",extras.notes},{"patches",extras.patches},{"selection",location}};
  if(views)result["views"]={{"pseudocode",code},{"disassembly",assembly},{"hex",byteText},{"strings",strings},{"imports",imports},{"graph",extras.graph},{"references",extras.references},{"calls",extras.calls},{"types",extras.types},{"search",extras.searchResults}};return result;
 }
 static uint64_t jobId(const Json&a){if(!a.contains("job_id")||!a["job_id"].is_string())throw std::runtime_error("job_id must be a decimal string");auto id=a["job_id"].get<std::string>();if(id.empty()||id.size()>20||!std::all_of(id.begin(),id.end(),[](char c){return c>='0'&&c<='9';}))throw std::runtime_error("Invalid job_id");auto number=std::stoull(id);if(!number)throw std::runtime_error("Invalid job_id");return number;}
 static Json jobRecord(Json record){if(record.contains("result")&&record["result"].is_object()&&record["result"].contains("data"))record["result"]=record["result"]["data"];return record;}
 Json handleRemote(const Json&request){
  if(!request.is_object()||!request.contains("name")||!request["name"].is_string())throw std::runtime_error("name must be a string");auto name=request["name"].get<std::string>();auto a=request.value("arguments",Json::object());validateDesktopArguments(name,a);
  if(closing.load())throw std::runtime_error("Desktop is closing");
  if(name=="get_job")return jobRecord(queue.get(jobId(a),a.value("include_result",true)));
  if(name=="list_jobs")return queue.list(a.value("offset",size_t(0)),a.value("limit",size_t(100)));
  if(name=="cancel_job")return jobRecord(queue.cancel(jobId(a)));
  if(name=="await_job"){
   auto timeout=a.value("timeout_ms",0u);if(timeout>30000)throw std::runtime_error("timeout_ms exceeds 30000");auto id=jobId(a);auto stop=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout);Json record;
   do{if(closing.load())throw std::runtime_error("Desktop is closing");auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(stop-std::chrono::steady_clock::now()).count();record=queue.await(id,(uint32_t)std::clamp<int64_t>(remaining,0,100),a.value("include_result",true));auto status=record.value("status","");if(status=="completed"||status=="failed"||status=="cancelled")break;}while(std::chrono::steady_clock::now()<stop);
   return jobRecord(record);
  }
  auto answer=mailbox.post(request).get();if(!answer.contains("__job_id"))return answer;auto id=answer["__job_id"].get<uint64_t>();Json record;
  for(;;){if(closing.load())throw std::runtime_error("Desktop is closing");record=queue.await(id,100,true);auto status=record.value("status","");if(status=="completed"||status=="failed"||status=="cancelled")break;}
  if(record.value("status","")=="failed")throw std::runtime_error(record.value("error","Operation failed"));if(record.value("status","")=="cancelled")throw std::runtime_error("Operation cancelled");
  // This barrier lets the desktop apply job snapshots before reporting success.
  auto snapshot=mailbox.post({{"name","get_workspace_state"},{"arguments",{{"include_views",answer.value("__workspace",false)}}}}).get();
  if(answer.value("__workspace",false))return snapshot;return jobRecord(record).at("result");
 }
 Json dispatch(const Json&request){
  auto name=request.at("name").get<std::string>();auto a=request.value("arguments",Json::object());validateDesktopArguments(name,a);
  if(name=="get_workspace_state")return state(a.value("include_views",false));
  if(name=="get_selection")return {{"address",info.is_null()?Json(nullptr):Json(hex(selected))},{"location",location},{"active_view",activeView}};
  if(name=="set_function_filter"){strncpy_s(search,a["query"].get<std::string>().c_str(),_TRUNCATE);functionOffset=0;functionRefresh=true;return state();}
  if(name=="get_activity_log"){auto offset=a.value("offset",size_t(0)),limit=std::min(a.value("limit",size_t(100)),size_t(100));Json items=Json::array();for(size_t i=offset;i<history.size()&&items.size()<limit;i++)items.push_back(history[i]);return {{"items",items},{"total",history.size()}};}
  if(name=="set_active_view"){
   auto view=desktopView(a.at("view"));activeView=tabRequest=view;if(view=="Pseudocode"&&!info.is_null()){Json args={{"address",hex(selected)},{"record",false},{"view",view}};return {{"__job_id",start("navigate",args,true)},{"__workspace",true}};}std::string tool;if(!info.is_null()){if(view=="Graph")tool="get_control_flow";if(view=="References")tool="get_cross_references";if(view=="Types")tool="get_function_types";if(view=="Calls")tool="get_call_graph";if(view=="Imports")tool="list_imports";if(view=="Strings")tool="discover_strings";}
   if(!tool.empty()){Json args=Json::object();if(tool=="get_control_flow"||tool=="get_cross_references"||tool=="get_function_types")args["address"]=hex(selected);return {{"__job_id",start(tool,args,true)},{"__workspace",true}};}return state();
  }
  if(name=="navigate_to"||name=="navigate_back"||name=="navigate_forward"){
   if(info.is_null())throw std::runtime_error("Open a binary first");Json args=a;bool record=true;
   if(name!="navigate_to"){auto va=name=="navigate_back"?navigation.back():navigation.forward();if(!va)return state();args["address"]=hex(*va);record=false;}
   if(!args.contains("view"))args["view"]=activeView=="Overview"?"Disassembly":activeView;args["record"]=record;args["preview_pseudocode"]=layout.splitPreview&&layout.preview=="Pseudocode";return {{"__job_id",start("navigate",args,true)},{"__workspace",true}};
  }
  std::string tool=name;auto args=a;if(name=="submit_job"){tool=a.at("tool").get<std::string>();args=a.value("arguments",Json::object());}
  tools.validateLocal(tool,args);auto id=start(tool,args,true);
  if(name=="submit_job")return jobRecord(queue.get(id,false));return {{"__job_id",id}};
 }
 void serviceRemote(){for(auto&command:mailbox.drain()){try{mailbox.resolve(command,dispatch(command->request));}catch(const std::exception&e){mailbox.reject(command,e.what());}}}
 void connect(){bridge=std::make_unique<BridgeServer>(executableDir()/"sessions",[this](const Json&request){return handleRemote(request);});}
 void close(){closing=true;mailbox.close();if(bridge)bridge->stop();queue.shutdown();layout.save();extras.saveGraphViews();}
 ~Desktop(){close();}
};
static bool requested(Desktop&s,const char*name){if(s.tabRequest==name){s.tabRequest.clear();return true;}return false;}
static void pseudocodeView(Desktop& s,ImFont* mono){
 ImGui::PushFont(mono,17.f);ImGui::BeginChild("mapped_code_scroll",{0,0},ImGuiChildFlags_None,ImGuiWindowFlags_HorizontalScrollbar);ImGuiListClipper clip;clip.Begin((int)s.codeLines.size());while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){ImGui::PushID(i);ImGui::TextColored(muted,"%4d",i+1);ImGui::SameLine(65);auto found=s.pseudocodeAddresses.find(size_t(i+1));bool mapped=found!=s.pseudocodeAddresses.end()&&!found->second.empty();const auto& line=s.codeLines[i];if(ImGui::Selectable((line+"##line").c_str(),false,ImGuiSelectableFlags_AllowDoubleClick)&&ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)&&mapped){s.tabRequest="Disassembly";s.navigate(address(Json(found->second.front())));}if(mapped&&ImGui::IsItemHovered()){ImGui::BeginTooltip();ImGui::TextUnformatted("Double-click to follow instruction");for(const auto& at:found->second)ImGui::TextUnformatted(at.c_str());ImGui::EndTooltip();}if(ImGui::BeginPopupContextItem("pseudocode_context")){if(mapped)for(const auto& at:found->second)if(ImGui::MenuItem(("Disassembly at "+at).c_str())){s.tabRequest="Disassembly";s.navigate(address(Json(at)));}if(ImGui::MenuItem("Function / variable types")){s.tabRequest="Types";s.start("get_function_types",{{"address",hex(s.selected)}});}if(ImGui::MenuItem("Edit pseudocode controls")){s.tabRequest="Workbench";s.workbench.category="Pseudocode";s.workbench.operation.clear();}if(ImGui::MenuItem("Copy line"))ImGui::SetClipboardText(line.c_str());ImGui::EndPopup();}ImGui::PopID();}ImGui::EndChild();ImGui::PopFont();
}
static void openBinary(Desktop&s,HWND window){auto path=dialog(window,false,L"Binary files\0*.exe;*.dll;*.sys;*.elf;*.bin\0All files\0*.*\0");if(!path.empty())s.start("open_binary",{{"path",pathText(path)}});}
static void copyMcpConfig(Desktop&s){auto path=pathText(executableDir()/"ScratcherMCP.exe");Json arguments=Json::array({"--mcp"});if(s.bridge){arguments.push_back("--desktop");arguments.push_back(s.bridge->endpoint().at("id"));}auto config=Json{{"mcpServers",{{"scratcher",{{"command",path},{"args",arguments}}}}}}.dump(2);ImGui::SetClipboardText(config.c_str());}
static void drawMenu(Desktop&s,HWND window){
 if(!ImGui::BeginMenuBar())return;
 if(ImGui::BeginMenu("File")){if(ImGui::MenuItem("Open binary","Ctrl+O",false,!s.busy))openBinary(s,window);if(ImGui::MenuItem("Open project",nullptr,false,!s.busy)){auto path=dialog(window,false,L"Scratcher projects\0*.scratcher\0");if(!path.empty())s.start("load_project",{{"path",pathText(path)}});}if(ImGui::MenuItem("Save project","Ctrl+S",false,!s.busy&&!s.info.is_null())){auto path=dialog(window,true,L"Scratcher project\0*.scratcher\0",L"scratcher");if(!path.empty())s.start("save_project",{{"path",pathText(path)}});}ImGui::EndMenu();}
 if(ImGui::BeginMenu("Edit")){if(ImGui::MenuItem("Undo","Ctrl+Z",false,!s.busy&&!s.info.is_null()))s.start("undo",Json::object());if(ImGui::MenuItem("Redo","Ctrl+Y",false,!s.busy&&!s.info.is_null()))s.start("redo",Json::object());ImGui::Separator();if(ImGui::MenuItem("Rename function","N",false,!s.info.is_null()))s.renameRequested=true;if(ImGui::MenuItem("Function signature",nullptr,false,!s.info.is_null())){s.tabRequest="Types";s.start("get_function_types",{{"address",hex(s.selected)}});}if(ImGui::MenuItem("Patch bytes",nullptr,false,!s.info.is_null()))s.tabRequest="Patches";ImGui::EndMenu();}
 if(ImGui::BeginMenu("Jump")){if(ImGui::MenuItem("Go to address","G"))s.focusGoto=true;if(ImGui::MenuItem("Back","Alt+Left",false,s.navigation.canBack()))s.back();if(ImGui::MenuItem("Forward","Alt+Right",false,s.navigation.canForward()))s.forward();if(ImGui::MenuItem("Mark position","Ctrl+B",false,!s.info.is_null()))s.start("set_bookmark",{{"address",hex(s.selected)}});ImGui::EndMenu();}
 if(ImGui::BeginMenu("View")){if(ImGui::MenuItem("Inspector",nullptr,&s.layout.showInspector))s.layout.save();if(ImGui::MenuItem("Synchronized preview",nullptr,&s.layout.splitPreview))s.layout.save();if(ImGui::BeginMenu("Preview content")){for(auto name:{"Pseudocode","Disassembly"})if(ImGui::MenuItem(name,nullptr,s.layout.preview==name)){s.layout.preview=name;s.layout.save();}ImGui::EndMenu();}ImGui::Separator();for(auto name:{"Overview","Disassembly","Pseudocode","Hex","Strings","Imports","Graph","References","Calls","Search","Bookmarks","Types","Patches","Workbench","Automation","Acceleration"})if(ImGui::MenuItem(name)){s.tabRequest=name;if(std::string(name)=="Graph"&&!s.info.is_null())s.start("get_control_flow",{{"address",hex(s.selected)}});}ImGui::EndMenu();}
 if(ImGui::BeginMenu("Search")){if(ImGui::MenuItem("Byte pattern")){s.tabRequest="Search";s.extras.textMode=false;}if(ImGui::MenuItem("Text")){s.tabRequest="Search";s.extras.textMode=true;}if(ImGui::MenuItem("Cross-references","X",false,!s.info.is_null())){s.tabRequest="References";s.start("get_cross_references",{{"address",hex(s.selected)}});}ImGui::EndMenu();}
 if(ImGui::BeginMenu("Tools")){if(ImGui::MenuItem("Automation"))s.tabRequest="Automation";if(ImGui::MenuItem("Copy MCP configuration"))copyMcpConfig(s);if(ImGui::MenuItem("Cancel operation","Esc",false,s.busy))s.queue.cancel();ImGui::EndMenu();}
 ImGui::EndMenuBar();
}
static void handleKeys(Desktop&s,HWND window){
 auto&io=ImGui::GetIO();if(io.WantTextInput)return;
 if(io.KeyCtrl&&ImGui::IsKeyPressed(ImGuiKey_O)&&!s.busy)openBinary(s,window);
 if(io.KeyAlt&&ImGui::IsKeyPressed(ImGuiKey_LeftArrow))s.back();if(io.KeyAlt&&ImGui::IsKeyPressed(ImGuiKey_RightArrow))s.forward();
 if(ImGui::IsKeyPressed(ImGuiKey_G))s.focusGoto=true;
 if(ImGui::IsKeyPressed(ImGuiKey_Escape)&&s.busy)s.queue.cancel();
 if(s.info.is_null())return;
 if(io.KeyCtrl&&ImGui::IsKeyPressed(ImGuiKey_Z)&&!s.busy)s.start("undo",Json::object());if(io.KeyCtrl&&ImGui::IsKeyPressed(ImGuiKey_Y)&&!s.busy)s.start("redo",Json::object());
 if(io.KeyCtrl&&ImGui::IsKeyPressed(ImGuiKey_S)&&!s.busy){auto path=dialog(window,true,L"Scratcher project\0*.scratcher\0",L"scratcher");if(!path.empty())s.start("save_project",{{"path",pathText(path)}});}
 if(ImGui::IsKeyPressed(ImGuiKey_N))s.renameRequested=true;
 if(io.KeyCtrl&&ImGui::IsKeyPressed(ImGuiKey_B))s.start("set_bookmark",{{"address",hex(s.selected)}});
 if(ImGui::IsKeyPressed(ImGuiKey_X)){s.tabRequest="References";s.start("get_cross_references",{{"address",hex(s.selected)}});}
 if(ImGui::IsKeyPressed(ImGuiKey_F5)){s.tabRequest="Pseudocode";s.navigate(s.selected);}
 if(ImGui::IsKeyPressed(ImGuiKey_Space)){s.graphMode=!s.graphMode;s.tabRequest=s.graphMode?"Graph":"Disassembly";if(s.graphMode)s.start("get_control_flow",{{"address",hex(s.selected)}});}
}
static void automation(Desktop&s,ImFont*mono){
 label("LIVE WORKSPACE MCP");if(s.bridge){ImGui::TextColored(accent,"Ready / commands control this workspace");ImGui::TextWrapped("Session: %s",s.bridge->endpoint()["id"].get<std::string>().c_str());}else ImGui::TextWrapped("Unavailable: %s",s.bridgeError.c_str());ImGui::Separator();
 auto definitions=s.tools.localList();if(s.toolIndex>=(int)definitions.size())s.toolIndex=0;auto name=definitions[s.toolIndex]["name"].get<std::string>();
 ImGui::SetNextItemWidth(250);if(ImGui::BeginCombo("Tool",name.c_str())){for(size_t i=0;i<definitions.size();i++)if(ImGui::Selectable(definitions[i]["name"].get<std::string>().c_str(),s.toolIndex==(int)i)){s.toolIndex=(int)i;Json defaults=Json::object();for(auto&required:definitions[i]["inputSchema"]["required"]){auto key=required.get<std::string>();defaults[key]=key=="address"?hex(s.selected):key=="path"?"D:/path/to/file":"";}strncpy_s(s.args,defaults.dump(2).c_str(),_TRUNCATE);}ImGui::EndCombo();}
 ImGui::SameLine();if(ImGui::Button("Copy MCP config"))copyMcpConfig(s);ImGui::TextWrapped("%s",definitions[s.toolIndex]["description"].get<std::string>().c_str());
 ImGui::InputTextMultiline("Arguments",s.args,sizeof(s.args),{-1,110});ImGui::BeginDisabled(s.busy);if(ImGui::Button("Run")){try{s.start(definitions[s.toolIndex]["name"],Json::parse(s.args));}catch(const std::exception&e){s.lastError=e.what();}}ImGui::EndDisabled();ImGui::Separator();codeView(lines(s.toolResult.dump(2)),mono);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int){
 ImGui_ImplWin32_EnableDpiAwareness();WNDCLASSEXW wc{sizeof(wc),CS_CLASSDC,windowProc,0,0,instance,nullptr,nullptr,nullptr,nullptr,L"ScratcherNative",nullptr};RegisterClassExW(&wc);
 HWND window=CreateWindowW(wc.lpszClassName,L"Scratcher | Binary workspace",WS_OVERLAPPEDWINDOW,100,80,1500,940,nullptr,nullptr,instance,nullptr);
 DXGI_SWAP_CHAIN_DESC sd{};sd.BufferCount=2;sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;sd.OutputWindow=window;sd.SampleDesc.Count=1;sd.Windowed=TRUE;sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;D3D_FEATURE_LEVEL level;
 HRESULT hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&sd,&swapchain,&device,&level,&context);
 if(FAILED(hr))hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&sd,&swapchain,&device,&level,&context);
 if(FAILED(hr)){MessageBoxW(window,L"Direct3D 11 initialization failed.",L"Scratcher",MB_ICONERROR);DestroyWindow(window);return 1;}makeTarget();
 IMGUI_CHECKVERSION();ImGui::CreateContext();auto&io=ImGui::GetIO();io.IniFilename=nullptr;io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;io.ConfigWindowsMoveFromTitleBarOnly=true;
 ImFont*font=io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf",18);if(!font)font=io.Fonts->AddFontDefault();ImFont*mono=io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/consola.ttf",17);if(!mono)mono=font;io.FontDefault=font;theme();
 ImGui_ImplWin32_Init(window);ImGui_ImplDX11_Init(device,context);ShowWindow(window,SW_SHOWDEFAULT);UpdateWindow(window);DragAcceptFiles(window,TRUE);
 Desktop s;try{s.connect();}catch(const std::exception&e){s.bridgeError=e.what();}int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc>1)dropped=argv[1];LocalFree(argv);
 bool done=false;while(!done){MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);if(msg.message==WM_QUIT)done=true;}if(done)break;
  s.poll();s.serviceRemote();if(!s.busy&&!dropped.empty()){auto p=dropped;dropped.clear();s.start(p.extension()==L".scratcher"?"load_project":"open_binary",{{"path",pathText(p)}});}if(!s.busy&&s.navigatePending){s.navigatePending=false;s.navigate(s.selected);}if(!s.busy&&s.functionRefresh&&!s.info.is_null()){s.functionRefresh=false;s.start("list_functions",{{"offset",s.functionOffset},{"limit",500},{"query",s.search}});}
  ImGui_ImplDX11_NewFrame();ImGui_ImplWin32_NewFrame();ImGui::NewFrame();auto*vp=ImGui::GetMainViewport();ImGui::SetNextWindowPos(vp->WorkPos);ImGui::SetNextWindowSize(vp->WorkSize);ImGui::Begin("Scratcher",nullptr,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_MenuBar);
  drawMenu(s,window);handleKeys(s,window);auto logo=ImGui::GetCursorScreenPos();ImGui::GetWindowDrawList()->AddRectFilled(logo,{logo.x+36,logo.y+36},ImGui::ColorConvertFloat4ToU32(accent),8);ImGui::SetCursorPosX(ImGui::GetCursorPosX()+10);ImGui::TextColored({0.03f,0.09f,0.09f,1},"S");ImGui::SameLine(68);ImGui::TextUnformatted("Scratcher");ImGui::SameLine();ImGui::TextColored(muted,"/  Binary workspace");
  ImGui::SameLine(std::max(420.0f,ImGui::GetWindowWidth()-520));ImGui::BeginDisabled(s.busy);
  if(ImGui::Button("Open binary")){auto p=dialog(window,false,L"Binary files\0*.exe;*.dll;*.sys;*.elf;*.bin\0All files\0*.*\0");if(!p.empty())s.start("open_binary",{{"path",pathText(p)}});}ImGui::SameLine();
  if(ImGui::Button("Open project")){auto p=dialog(window,false,L"Scratcher projects\0*.scratcher\0All files\0*.*\0");if(!p.empty())s.start("load_project",{{"path",pathText(p)}});}ImGui::SameLine();
  ImGui::BeginDisabled(s.info.is_null());if(ImGui::Button("Analyze"))s.start("run_auto_analysis",{{"time_budget_ms",60000}});ImGui::SameLine();if(ImGui::Button("Save")){auto p=dialog(window,true,L"Scratcher project\0*.scratcher\0",L"scratcher");if(!p.empty())s.start("save_project",{{"path",pathText(p)}});}ImGui::EndDisabled();ImGui::EndDisabled();ImGui::Dummy({0,5});ImGui::Separator();
  float contentHeight=ImGui::GetContentRegionAvail().y-40;float inspectorWidth=s.layout.showInspector?s.layout.inspector:0;float sidebarWidth=s.layout.navigator;float centerWidth=std::max(200.0f,ImGui::GetContentRegionAvail().x-sidebarWidth-inspectorWidth-(s.layout.showInspector?24.f:12.f));
  ImGui::BeginChild("navigator",{sidebarWidth,contentHeight},ImGuiChildFlags_Borders);label("WORKSPACE");if(!s.info.is_null()){auto file=std::filesystem::u8path(s.info["path"].get<std::string>()).filename().string();ImGui::TextWrapped("%s",file.c_str());ImGui::TextColored(accent,"%s  /  %d bit",s.info["format"].get<std::string>().c_str(),s.info["bits"].get<int>());}else ImGui::TextWrapped("Drop a binary here to begin.");ImGui::Separator();label("FUNCTIONS");ImGui::SetNextItemWidth(-1);if(ImGui::InputTextWithHint("##function_search","Search names or addresses",s.search,sizeof(s.search))){s.functionOffset=0;s.functionRefresh=true;}
  ImGui::BeginDisabled(s.busy||s.functionOffset==0);if(ImGui::SmallButton("Previous")){s.functionOffset=s.functionOffset>=500?s.functionOffset-500:0;s.functionRefresh=true;}ImGui::EndDisabled();ImGui::SameLine();ImGui::BeginDisabled(s.busy||s.functionOffset+s.functions.size()>=s.functionTotal);if(ImGui::SmallButton("Next")){s.functionOffset+=500;s.functionRefresh=true;}ImGui::EndDisabled();ImGui::TextDisabled("%zu-%zu of %zu",s.functions.empty()?0:s.functionOffset+1,s.functionOffset+s.functions.size(),s.functionTotal);
  ImGui::BeginChild("function_list",{0,0});ImGuiListClipper clip;clip.Begin((int)s.functions.size(),53);while(clip.Step())for(int row=clip.DisplayStart;row<clip.DisplayEnd;row++){auto&f=s.functions[row];auto va=address(f["address"]);ImGui::PushID(row);ImGui::BeginDisabled(s.info.is_null());if(ImGui::Selectable((f["name"].get<std::string>()+"##fn").c_str(),va==s.selected,0,{0,25})){s.tabRequest="Disassembly";s.navigate(va);}ImGui::EndDisabled();ImGui::TextColored(muted,"%s",f["address"].get<std::string>().c_str());ImGui::PopID();}ImGui::EndChild();ImGui::EndChild();s.layout.splitter("##navigator_split",contentHeight,s.layout.navigator);
  ImGui::BeginChild("workspace",{centerWidth,contentHeight},ImGuiChildFlags_Borders);ImGui::BeginDisabled(s.busy||s.info.is_null());if(s.focusGoto){ImGui::SetKeyboardFocusHere();s.focusGoto=false;}ImGui::SetNextItemWidth(190);ImGui::InputTextWithHint("##goto","Go to address (0x...)",s.gotoText,sizeof(s.gotoText));ImGui::SameLine();if(ImGui::Button("Go")){try{s.navigate(address(Json(s.gotoText)));}catch(const std::exception&e){s.lastError=e.what();}}ImGui::SameLine();if(ImGui::Button("Rename")){s.renameText[0]=0;ImGui::OpenPopup("Rename function");}ImGui::EndDisabled();
  if(s.renameRequested){s.renameRequested=false;s.renameText[0]=0;ImGui::OpenPopup("Rename function");}if(ImGui::BeginPopup("Rename function")){ImGui::InputText("Name",s.renameText,sizeof(s.renameText));if(ImGui::Button("Apply")){s.start("rename_function",{{"address",hex(s.selected)},{"name",s.renameText}});ImGui::CloseCurrentPopup();}ImGui::EndPopup();}
  if(!s.lastError.empty())ImGui::TextWrapped("%s",s.lastError.c_str());
  float viewHeight=ImGui::GetContentRegionAvail().y;if(s.layout.splitPreview)viewHeight=std::max(100.f,viewHeight*(1.f-s.layout.previewFraction)-12.f);ImGui::BeginChild("primary_views",{0,viewHeight});
  if(ImGui::BeginTabBar("views",ImGuiTabBarFlags_FittingPolicyScroll)){const auto requestedView=s.tabRequest;
   if(ImGui::BeginTabItem("Overview",nullptr,requested(s,"Overview")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Overview";
    ImGui::Spacing();ImGui::TextColored(accent,"Binary intelligence, on demand.");ImGui::Spacing();if(s.info.is_null()){ImGui::TextWrapped("Open an executable to inspect its structure, browse functions, and recover readable pseudocode.");ImGui::Spacing();label("Browse code, trace references, and annotate your findings.");ImGui::Spacing();ImGui::TextWrapped("Open PE, ELF, Mach-O, raw binaries or captured process memory. Select a function to inspect it; use Workbench for analysis and corrections.");}else{label("FILE");ImGui::TextWrapped("%s",s.info["path"].get<std::string>().c_str());ImGui::Spacing();ImGui::Text("Size: %llu bytes",s.info["size"].get<unsigned long long>());ImGui::Text("Entry: %s",s.info["entry"].get<std::string>().c_str());ImGui::Text("Indexed functions: %llu",s.info["function_count"].get<unsigned long long>());ImGui::Spacing();ImGui::BeginDisabled(s.busy);if(ImGui::Button("Decompile entry point")){s.tabRequest="Pseudocode";s.navigate(address(s.info["entry"]));}ImGui::EndDisabled();ImGui::Spacing();label("MEMORY MAP");if(ImGui::BeginTable("sections",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_ScrollY,{0,300})){ImGui::TableSetupColumn("Section");ImGui::TableSetupColumn("Address");ImGui::TableSetupColumn("Bytes");ImGui::TableSetupColumn("Access");ImGui::TableHeadersRow();for(auto&sec:s.info["sections"]){ImGui::TableNextRow();ImGui::TableNextColumn();ImGui::TextUnformatted(sec["name"].get<std::string>().c_str());ImGui::TableNextColumn();ImGui::TextUnformatted(sec["address"].get<std::string>().c_str());ImGui::TableNextColumn();ImGui::Text("%llu",sec["memory_size"].get<unsigned long long>());ImGui::TableNextColumn();ImGui::Text("R%s%s",sec["writable"].get<bool>()?"W":"",sec["executable"].get<bool>()?"X":"");}ImGui::EndTable();}}
    ImGui::Spacing();label("RECENT OPERATIONS");for(auto it=s.history.rbegin();it!=s.history.rend()&&it-s.history.rbegin()<7;it++)ImGui::TextUnformatted(it->c_str());ImGui::EndTabItem();}
   if(ImGui::BeginTabItem("Pseudocode",nullptr,requested(s,"Pseudocode")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Pseudocode";if(!s.pseudocodeReady&&!s.busy&&!s.info.is_null()){s.pseudocodeReady=true;auto at=s.location.is_object()&&s.location["function"].is_object()?s.location["function"]["address"]:Json(hex(s.selected));s.start("get_pseudocode_mapping",{{"address",at},{"limit",10000}});}label("PSEUDOCODE");ImGui::SameLine();ImGui::BeginDisabled(s.busy||s.info.is_null());if(ImGui::SmallButton("Refresh"))s.start("get_pseudocode_mapping",{{"address",hex(s.selected)},{"limit",10000}});ImGui::EndDisabled();ImGui::SameLine();if(ImGui::SmallButton("Copy"))ImGui::SetClipboardText(s.code.c_str());ImGui::SameLine();if(ImGui::SmallButton("Export")){auto p=dialog(window,true,L"C source\0*.c\0",L"c");if(!p.empty()){std::ofstream out(p);out<<s.code;if(!out)s.lastError="Cannot export code";}}pseudocodeView(s,mono);ImGui::EndTabItem();}
   if(ImGui::BeginTabItem("Disassembly",nullptr,requested(s,"Disassembly")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Disassembly";ImGui::PushFont(mono,17.0f);if(ImGui::BeginTable("asm",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,{0,0})){ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,150);ImGui::TableSetupColumn("Bytes",ImGuiTableColumnFlags_WidthFixed,180);ImGui::TableSetupColumn("Instruction",ImGuiTableColumnFlags_WidthFixed,90);ImGui::TableSetupColumn("Operands");ImGui::TableHeadersRow();ImGuiListClipper c;c.Begin((int)s.assembly.size());while(c.Step())for(int i=c.DisplayStart;i<c.DisplayEnd;i++){auto&r=s.assembly[i];ImGui::TableNextRow();ImGui::TableNextColumn();ImGui::TextColored(muted,"%s",r["address"].get<std::string>().c_str());ImGui::TableNextColumn();ImGui::TextColored(muted,"%s",r["bytes"].get<std::string>().c_str());ImGui::TableNextColumn();auto instructionText=r.value("prefixes",std::string());if(!instructionText.empty())instructionText+=" ";instructionText+=r["mnemonic"].get<std::string>();ImGui::TextColored(accent,"%s",instructionText.c_str());ImGui::TableNextColumn();ImGui::PushID(i);if(ImGui::Selectable(r.value("display_operands",r["operands"].get<std::string>()).c_str(),address(r["address"])==s.selected,ImGuiSelectableFlags_AllowDoubleClick)&&ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)&&r.contains("target")&&r["target"].is_string()){s.navigate(address(r["target"]));}if(ImGui::BeginPopupContextItem("instruction_menu")){if(ImGui::MenuItem("Go to instruction"))s.navigate(address(r["address"]));if(ImGui::MenuItem("References")){s.tabRequest="References";s.navigate(address(r["address"]));}if(ImGui::MenuItem("Pseudocode")){s.tabRequest="Pseudocode";s.navigate(address(r["address"]));}if(ImGui::MenuItem("Define code"))s.start("define_code",{{"address",r["address"]},{"end",hex(address(r["address"])+r["length"].get<uint64_t>())}});if(ImGui::MenuItem("Define data"))s.start("define_data",{{"address",r["address"]},{"end",hex(address(r["address"])+r["length"].get<uint64_t>())},{"data_type","byte"}});if(ImGui::MenuItem("Edit function / operands")){s.tabRequest="Workbench";s.workbench.category="Corrections";s.workbench.operation.clear();s.navigate(address(r["address"]));}if(ImGui::MenuItem("Bookmark"))s.start("set_bookmark",{{"address",r["address"]}});ImGui::EndPopup();}ImGui::PopID();}ImGui::EndTable();}ImGui::PopFont();ImGui::EndTabItem();}
   if(ImGui::BeginTabItem("Hex",nullptr,requested(s,"Hex")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Hex";label("SELECTED ADDRESS / READ-ONLY BYTES");ImGui::PushFont(mono,17.0f);for(size_t i=0;i<s.byteText.size()/2;i+=16){std::string text,ascii;for(size_t j=i;j<std::min(i+16,s.byteText.size()/2);j++){auto pair=s.byteText.substr(j*2,2);text+=pair+" ";int n=std::stoi(pair,nullptr,16);ascii+=n>=32&&n<127?(char)n:'.';}ImGui::TextColored(muted,"%s",hex(s.selected+i).c_str());ImGui::SameLine(165);ImGui::TextUnformatted(text.c_str());ImGui::SameLine(650);ImGui::TextColored(accent,"%s",ascii.c_str());}ImGui::PopFont();ImGui::EndTabItem();}
   if(ImGui::BeginTabItem("Strings",nullptr,requested(s,"Strings")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Strings";ImGui::BeginDisabled(s.busy||s.info.is_null());ImGui::SetNextItemWidth(230);ImGui::InputTextWithHint("##string_filter","Find printable text",s.stringSearch,sizeof(s.stringSearch));ImGui::SameLine();if(ImGui::Button("Scan strings"))s.start("discover_strings",{{"query",s.stringSearch},{"limit",500}});ImGui::EndDisabled();if(ImGui::BeginTable("strings",2,ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,{0,0})){ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,170);ImGui::TableSetupColumn("Text");ImGui::TableHeadersRow();ImGuiListClipper c;c.Begin((int)s.strings.size());while(c.Step())for(int i=c.DisplayStart;i<c.DisplayEnd;i++){auto&r=s.strings[i];ImGui::TableNextRow();ImGui::TableNextColumn();if(r["address"].is_string())ImGui::TextColored(muted,"%s",r["address"].get<std::string>().c_str());else ImGui::TextColored(muted,"Unmapped");ImGui::TableNextColumn();ImGui::TextUnformatted(r["text"].get<std::string>().c_str());}ImGui::EndTable();}ImGui::EndTabItem();}
   if(ImGui::BeginTabItem("Imports",nullptr,requested(s,"Imports")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Imports";ImGui::BeginDisabled(s.busy||s.info.is_null());if(ImGui::Button("Read imports"))s.start("list_imports",Json::object());ImGui::EndDisabled();if(ImGui::BeginTable("imports",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,{0,0})){ImGui::TableSetupColumn("IAT address");ImGui::TableSetupColumn("Module");ImGui::TableSetupColumn("Symbol");ImGui::TableHeadersRow();ImGuiListClipper c;c.Begin((int)s.imports.size());while(c.Step())for(int i=c.DisplayStart;i<c.DisplayEnd;i++){auto&r=s.imports[i];ImGui::TableNextRow();for(auto key:{"address","module","name"}){ImGui::TableNextColumn();ImGui::TextUnformatted(r[key].get<std::string>().c_str());}}ImGui::EndTable();}ImGui::EndTabItem();}
   s.extras.drawTabs(s.selected,s.busy,mono,s.tabRequest,s.renderedView);if(ImGui::BeginTabItem("Workbench",nullptr,requested(s,"Workbench")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Workbench";s.workbench.draw(s.tools.localList(),s.selected,s.busy,mono);ImGui::EndTabItem();}if(ImGui::BeginTabItem("Automation",nullptr,requested(s,"Automation")?ImGuiTabItemFlags_SetSelected:0)){s.renderedView="Automation";automation(s,mono);ImGui::EndTabItem();}ImGui::EndTabBar();s.activeView=requestedView.empty()?s.renderedView:requestedView;}
  ImGui::EndChild();
  if(s.layout.splitPreview){
   ImGui::InvisibleButton("##preview_split",{ImGui::GetContentRegionAvail().x,6});if(ImGui::IsItemHovered()||ImGui::IsItemActive())ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);if(ImGui::IsItemActive())s.layout.previewFraction=std::clamp(s.layout.previewFraction-ImGui::GetIO().MouseDelta.y/std::max(contentHeight,1.f),.2f,.7f);if(ImGui::IsItemDeactivated())s.layout.save();
   ImGui::BeginChild("synchronized_preview",{0,0},ImGuiChildFlags_Borders);ImGui::TextColored(muted,"%s / %s",s.layout.preview.c_str(),hex(s.selected).c_str());ImGui::SameLine();ImGui::BeginDisabled(s.busy||s.info.is_null());if(ImGui::SmallButton("Refresh pseudocode"))s.start("get_pseudocode_mapping",{{"address",hex(s.selected)},{"limit",10000}});ImGui::EndDisabled();if(s.layout.preview=="Pseudocode")pseudocodeView(s,mono);else {ImGui::PushFont(mono,15.f);ImGui::BeginChild("preview_listing",{0,0},ImGuiChildFlags_None,ImGuiWindowFlags_HorizontalScrollbar);ImGuiListClipper clip;clip.Begin((int)s.assembly.size());while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){auto& row=s.assembly[i];auto line=row["address"].get<std::string>()+"  "+row["mnemonic"].get<std::string>()+"  "+row.value("display_operands",row["operands"].get<std::string>());if(ImGui::Selectable(line.c_str(),false,ImGuiSelectableFlags_AllowDoubleClick)&&ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)&&row.contains("target")&&row["target"].is_string())s.navigate(address(row["target"]));}ImGui::EndChild();ImGui::PopFont();}ImGui::EndChild();
  }
  ImGui::EndChild();if(s.layout.showInspector){s.layout.splitter("##inspector_split",contentHeight,s.layout.inspector,true);
   ImGui::BeginChild("inspector",{inspectorWidth,contentHeight},ImGuiChildFlags_Borders);label("INSPECTOR");ImGui::TextColored(accent,"%s",hex(s.selected).c_str());if(!s.info.is_null()){ImGui::Text("%s / %d bit",s.info["format"].get<std::string>().c_str(),s.info["bits"].get<int>());for(auto&f:s.functions)if(address(f["address"])==s.selected){ImGui::TextWrapped("%s",f["name"].get<std::string>().c_str());break;}}s.extras.drawInspector(s.selected,s.busy);ImGui::EndChild();}
  ImGui::Separator();ImGui::TextColored(s.busy?accent:muted,"%s",s.status.c_str());ImGui::SameLine();if(s.busy)ImGui::Text("%.1fs",ImGui::GetTime()-s.busySince);else ImGui::TextColored(muted,"/ last operation %.2f ms",s.lastMs);ImGui::SameLine(std::max(600.0f,ImGui::GetWindowWidth()-350));ImGui::TextColored(muted,"Scratcher 0.8");ImGui::End();
  ImGui::Render();float clear[]={0.045f,0.059f,0.08f,1};if(target){context->OMSetRenderTargets(1,&target,nullptr);context->ClearRenderTargetView(target,clear);ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());swapchain->Present(1,0);}if(IsIconic(window))Sleep(20);
 }
 s.close();ImGui_ImplDX11_Shutdown();ImGui_ImplWin32_Shutdown();ImGui::DestroyContext();if(target)target->Release();swapchain->Release();context->Release();device->Release();DestroyWindow(window);UnregisterClassW(wc.lpszClassName,instance);return 0;
}
