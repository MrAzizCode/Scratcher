#include "ui_extra.hpp"
#include <algorithm>
#include <deque>
#include <cmath>
#include <fstream>
namespace scratcher {
namespace {
ImVec4 accent{.4f,.89f,.76f,1},dim{.49f,.56f,.63f,1};
std::string text(const Json&j,const char*key,const char*fallback=""){return j.contains(key)&&j[key].is_string()?j[key].get<std::string>():(fallback?fallback:"");}
void copy(char*dst,size_t cap,const std::string&value){strncpy_s(dst,cap,value.c_str(),_TRUNCATE);}
void heading(const char*s){ImGui::TextColored(dim,"%s",s);}
bool addressLink(const std::string&s){ImGui::PushID(s.c_str());bool clicked=ImGui::Selectable(s.c_str(),false,ImGuiSelectableFlags_AllowDoubleClick);bool follow=clicked&&ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);ImGui::PopID();return follow;}
void smallJson(const Json&value){auto s=value.dump(2);ImGui::TextWrapped("%s",s.c_str());}
}
void ExtraViews::clear(){rememberGraphView();graph=references=calls=types=searchResults=nullptr;accelerationInfo=similarityIndex=similarityResults=nullptr;notes=patches=Json::array();editing=UINT64_MAX;pan={20,20};zoom=1;graphKey.clear();graphPositions.clear();graphHeights.clear();graphLayoutDirty=true;}
void ExtraViews::loadGraphViews(const std::filesystem::path& path){graphSettings=path;try{std::ifstream file(path);if(file){Json data;file>>data;if(data.is_object()&&data.size()<=128)graphViews=std::move(data);}}catch(...){}}
void ExtraViews::rememberGraphView(){if(graphKey.empty())return;graphViews[graphKey]={{"pan_x",pan.x},{"pan_y",pan.y},{"zoom",zoom}};while(graphViews.size()>128)graphViews.erase(graphViews.begin());}
void ExtraViews::saveGraphViews(){rememberGraphView();if(graphSettings.empty())return;try{std::filesystem::create_directories(graphSettings.parent_path());auto temporary=graphSettings;temporary+=L".tmp";{std::ofstream out(temporary);out<<graphViews.dump(2);if(!out)return;}std::error_code error;std::filesystem::remove(graphSettings,error);std::filesystem::rename(temporary,graphSettings,error);}catch(...){}}
void ExtraViews::buildGraphLayout(){
 graphPositions.clear();graphHeights.clear();graphExtent={1,1};if(!graph.is_object()||!graph.contains("nodes"))return;
 std::map<std::string,std::vector<std::string>> adjacency;for(auto& edge:graph["edges"])if(!edge.value("external",false))adjacency[text(edge,"source")].push_back(text(edge,"target"));
 std::map<std::string,size_t> levels;std::deque<std::string> pending;auto entry=text(graph,"entry");levels[entry]=0;pending.push_back(entry);while(!pending.empty()){auto from=pending.front();pending.pop_front();for(const auto& target:adjacency[from])if(!target.empty()&&!levels.contains(target)){levels[target]=levels[from]+1;pending.push_back(target);}}
 std::map<size_t,size_t> rows;for(auto& node:graph["nodes"]){auto id=text(node,"id");auto depth=levels.contains(id)?levels[id]:0;auto row=rows[depth]++;ImVec2 position{float(depth)*380.f,float(row)*270.f};auto height=float(std::min<size_t>(node["instructions"].size(),9)*21+67);graphPositions[id]=position;graphHeights[id]=height;graphExtent.x=std::max(graphExtent.x,position.x+320);graphExtent.y=std::max(graphExtent.y,position.y+height);}graphLayoutDirty=false;
}
void ExtraViews::update(const std::string&name,const Json&data,const Json&workspace){
 if(name=="get_acceleration_info")accelerationInfo=data;
 if(name=="build_function_similarity_index"){similarityIndex=data;similarityResults=nullptr;}
 if(name=="find_similar_functions")similarityResults=data;
 if(workspace.is_object()){if(workspace.contains("annotations"))notes=workspace["annotations"].value("annotations",Json::array());if(workspace.contains("patches"))patches=workspace["patches"];}
 if(name=="get_control_flow"){rememberGraphView();graph=data;graphKey=graphScope+":"+text(data,"entry");pan={20,20};zoom=1;try{if(graphViews.contains(graphKey)){auto& view=graphViews[graphKey];pan={view.value("pan_x",20.f),view.value("pan_y",20.f)};zoom=std::clamp(view.value("zoom",1.f),.1f,2.f);if(!std::isfinite(pan.x)||!std::isfinite(pan.y)){pan={20,20};zoom=1;}}}catch(...){pan={20,20};zoom=1;}graphLayoutDirty=true;}
 if(name=="get_cross_references")references=data;
 if(name=="get_call_graph")calls=data;
 if(name=="get_function_types"||name=="set_function_signature"||name=="set_variable_type"){types=data;if(data.contains("signature"))copy(signature,sizeof(signature),text(data,"signature"));}
 if(name=="search_bytes"||name=="discover_strings")searchResults=data;
 if(name=="list_annotations")notes=data.value("annotations",Json::array());
 if(name=="list_patches")patches=data.value("items",Json::array());
}
void ExtraViews::drawInspector(Address selected,bool busy){
 if(editing!=selected){editing=selected;comment[0]=bookmark[0]=label[0]=0;for(auto&n:notes)if(text(n,"address")==hex(selected)){copy(comment,sizeof(comment),text(n,"comment"));copy(bookmark,sizeof(bookmark),text(n,"bookmark"));copy(label,sizeof(label),text(n,"label"));break;}}
 ImGui::Spacing();ImGui::Separator();heading("COMMENT");ImGui::InputTextMultiline("##address_comment",comment,sizeof(comment),{-1,100});ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Save comment",{-1,0}))run("set_comment",{{"address",hex(selected)},{"text",comment}});ImGui::EndDisabled();
 ImGui::Spacing();heading("BOOKMARK");ImGui::SetNextItemWidth(-1);ImGui::InputTextWithHint("##bookmark_name","Optional name",bookmark,sizeof(bookmark));ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Mark position",{-1,0}))run("set_bookmark",{{"address",hex(selected)},{"name",bookmark}});ImGui::EndDisabled();
 ImGui::Spacing();heading("LABEL");ImGui::SetNextItemWidth(-1);ImGui::InputTextWithHint("##address_label","Address label",label,sizeof(label));ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Save label",{-1,0}))run("set_label",{{"address",hex(selected)},{"name",label}});ImGui::EndDisabled();
 ImGui::Spacing();heading("SHORTCUTS");ImGui::TextWrapped("G   Go to address\nN   Rename function\nX   Cross-references\nSpace   Graph / listing\nAlt + Left / Right   History\nCtrl + B   Bookmark\nF5   Pseudocode\nEsc   Cancel operation");
}
void ExtraViews::drawGraph(ImFont* mono){
 if(!graph.is_object()||!graph.contains("nodes")){ImGui::TextWrapped("Select a function and load its graph.");return;}
 auto& nodes=graph["nodes"];if(nodes.empty()){ImGui::TextWrapped("No reachable blocks were recovered.");return;}if(graphLayoutDirty)buildGraphLayout();
 ImGui::TextColored(dim,"%zu blocks / %zu branches / %llu instructions",nodes.size(),graph["edges"].size(),graph.value("instruction_count",0ULL));if(graph.value("truncated",false)){ImGui::SameLine();ImGui::TextColored({1,.70f,.36f,1},"Partial graph");}ImGui::SameLine();if(ImGui::SmallButton("Reset view")){pan={20,20};zoom=1;}
 ImGui::BeginChild("flow_canvas",{0,0},ImGuiChildFlags_Borders,ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse);auto origin=ImGui::GetCursorScreenPos(),size=ImGui::GetContentRegionAvail();if(size.x<1||size.y<1){ImGui::EndChild();return;}
 ImGui::InvisibleButton("##graph_canvas",size,ImGuiButtonFlags_MouseButtonLeft|ImGuiButtonFlags_MouseButtonMiddle);bool hover=ImGui::IsItemHovered();auto& io=ImGui::GetIO();
 ImVec2 mapStart{origin.x+std::max(0.f,size.x-190),origin.y+12},mapEnd{origin.x+size.x-12,origin.y+142};bool overMap=size.x>230&&size.y>180&&hover&&io.MousePos.x>=mapStart.x&&io.MousePos.x<=mapEnd.x&&io.MousePos.y>=mapStart.y&&io.MousePos.y<=mapEnd.y;
 if(hover&&ImGui::IsMouseDragging(ImGuiMouseButton_Middle)){pan.x+=io.MouseDelta.x;pan.y+=io.MouseDelta.y;}
 if(hover&&!overMap&&io.MouseWheel){float old=zoom;zoom=std::clamp(zoom+io.MouseWheel*.08f,.1f,2.f);auto mx=io.MousePos.x-origin.x,my=io.MousePos.y-origin.y;pan.x=mx-(mx-pan.x)*zoom/old;pan.y=my-(my-pan.y)*zoom/old;}
 auto* draw=ImGui::GetWindowDrawList();draw->PushClipRect(origin,{origin.x+size.x,origin.y+size.y},true);float grid=32*zoom;for(float x=std::fmod(pan.x,grid);x<size.x;x+=grid)draw->AddLine({origin.x+x,origin.y},{origin.x+x,origin.y+size.y},IM_COL32(31,39,49,100));for(float y=std::fmod(pan.y,grid);y<size.y;y+=grid)draw->AddLine({origin.x,origin.y+y},{origin.x+size.x,origin.y+y},IM_COL32(31,39,49,100));
 auto screen=[&](ImVec2 p){return ImVec2{origin.x+pan.x+p.x*zoom,origin.y+pan.y+p.y*zoom};};
 auto visible=[&](ImVec2 a,ImVec2 b){return b.x>=origin.x&&a.x<=origin.x+size.x&&b.y>=origin.y&&a.y<=origin.y+size.y;};
 for(auto& edge:graph["edges"]){auto from=text(edge,"source"),to=text(edge,"target");if(!graphPositions.contains(from)||!graphPositions.contains(to))continue;auto p=screen(graphPositions[from]),q=screen(graphPositions[to]);p={p.x+320*zoom,p.y+graphHeights[from]*zoom*.5f};q={q.x,q.y+graphHeights[to]*zoom*.5f};auto label=text(edge,"label");ImU32 color=label=="true"?IM_COL32(103,221,169,210):label=="false"?IM_COL32(237,133,130,210):IM_COL32(148,180,229,200);float bend=std::max(45.f*zoom,std::abs(q.x-p.x)*.45f);if(!visible({std::min(p.x,q.x)-bend,std::min(p.y,q.y)},{std::max(p.x,q.x)+bend,std::max(p.y,q.y)}))continue;draw->AddBezierCubic(p,{p.x+bend,p.y},{q.x-bend,q.y},q,color,1.8f*zoom);draw->AddTriangleFilled(q,{q.x-8*zoom,q.y-4*zoom},{q.x-8*zoom,q.y+4*zoom},color);}
 for(auto& node:nodes){auto id=text(node,"id");auto p=screen(graphPositions[id]);auto end=ImVec2{p.x+320*zoom,p.y+graphHeights[id]*zoom};if(!visible(p,end))continue;bool over=hover&&!overMap&&io.MousePos.x>=p.x&&io.MousePos.x<=end.x&&io.MousePos.y>=p.y&&io.MousePos.y<=end.y;draw->AddRectFilled(p,end,IM_COL32(20,29,37,255),7*zoom);draw->AddRect(p,end,over?IM_COL32(106,235,198,255):IM_COL32(65,93,104,255),7*zoom,ImDrawFlags_None,over?2.f:1.f);draw->AddRectFilled(p,{end.x,p.y+30*zoom},IM_COL32(30,53,59,255),7*zoom);if(zoom>=.3f){draw->AddText(mono,16*zoom,{p.x+10*zoom,p.y+6*zoom},IM_COL32(116,228,198,255),id.c_str());float y=p.y+40*zoom;size_t shown=0;for(auto& instruction:node["instructions"]){if(shown++>=9)break;auto line=text(instruction,"mnemonic")+"  "+text(instruction,"operands");if(line.size()>37)line=line.substr(0,34)+"...";draw->AddText(mono,15*zoom,{p.x+12*zoom,y},IM_COL32(214,225,234,255),line.c_str());y+=21*zoom;}auto exit=text(node,"exit");if(node["instructions"].size()>9)exit="...  "+exit;draw->AddText(mono,13*zoom,{p.x+12*zoom,end.y-21*zoom},IM_COL32(123,149,167,255),exit.c_str());}if(over&&ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))jump(address(Json(id)));}
 if(size.x>230&&size.y>180){float factor=std::min((mapEnd.x-mapStart.x-12)/graphExtent.x,(mapEnd.y-mapStart.y-12)/graphExtent.y);ImVec2 inner{mapStart.x+6,mapStart.y+6};draw->AddRectFilled(mapStart,mapEnd,IM_COL32(10,18,25,238),5);draw->PushClipRect(mapStart,mapEnd,true);for(auto& [id,p]:graphPositions){ImVec2 a{inner.x+p.x*factor,inner.y+p.y*factor},b{inner.x+(p.x+320)*factor,inner.y+(p.y+graphHeights[id])*factor};draw->AddRectFilled(a,b,IM_COL32(88,159,145,210));}ImVec2 a{inner.x-pan.x/zoom*factor,inner.y-pan.y/zoom*factor},b{a.x+size.x/zoom*factor,a.y+size.y/zoom*factor};draw->AddRect(a,b,IM_COL32(166,218,255,255),0,ImDrawFlags_None,1.5f);draw->PopClipRect();draw->AddRect(mapStart,mapEnd,IM_COL32(61,92,106,255),5);if(overMap&&ImGui::IsMouseDown(ImGuiMouseButton_Left)){pan.x=size.x*.5f-(io.MousePos.x-inner.x)/factor*zoom;pan.y=size.y*.5f-(io.MousePos.y-inner.y)/factor*zoom;}}
 draw->PopClipRect();ImGui::EndChild();
}
void ExtraViews::drawAcceleration(Address selected,bool busy){
 heading("FUNCTION SIMILARITY");
 ImGui::TextWrapped("Compare normalized instruction prefixes with CPU, GPU or measured automatic selection. Similarity is a search aid; it does not prove equivalent behavior.");
 ImGui::SetNextItemWidth(200);ImGui::Combo("Execution mode",&accelerationMode,"Automatic\0CPU\0GPU (CUDA)\0");
 ImGui::TextColored(dim,"Loading, instruction decoding and pseudocode currently use the CPU.");
 ImGui::BeginDisabled(busy);
 if(ImGui::Button("Refresh hardware"))run("get_acceleration_info",Json::object());
 ImGui::SameLine();
 if(ImGui::Button("Build similarity index"))run("build_function_similarity_index",{{"max_functions",10000},{"per_function_instruction_budget",64},{"workers",8}});
 ImGui::EndDisabled();
 if(busy)ImGui::TextColored(accent,"Analysis is running in the background. Esc cancels supported work.");
 if(accelerationInfo.is_object()&&accelerationInfo.contains("gpu")){
  auto& gpu=accelerationInfo["gpu"];
  ImGui::Spacing();heading("COMPUTE DEVICE");
  if(gpu.value("available",false)){
   ImGui::TextUnformatted(text(gpu,"name").c_str());
   ImGui::Text("VRAM: %.1f MiB free / %.1f MiB total",gpu.value("free_bytes",0ULL)/1048576.0,gpu.value("total_bytes",0ULL)/1048576.0);
  }else ImGui::TextWrapped("GPU unavailable: %s",text(gpu,"reason","CPU execution remains available").c_str());
 }
 if(similarityIndex.is_object()){
  ImGui::Spacing();heading("SESSION INDEX");
  ImGui::Text("%llu indexed prefixes / %llu candidate starts",similarityIndex.value("index_size",0ULL),similarityIndex.value("candidate_functions",0ULL));
  ImGui::Text("Extraction %.2f ms",similarityIndex.value("elapsed_ms",0.0));
  if(similarityIndex.value("truncated",false))ImGui::TextWrapped("Prefix or index limits were reached; these are bounded candidate descriptions.");
 }
 ImGui::BeginDisabled(busy||!selected||!similarityIndex.is_object());
 if(ImGui::Button("Find similar to selected function")){
  const char* modes[]={"auto","cpu","cuda"};
  run("find_similar_functions",{{"addresses",Json::array({hex(selected)})},{"top_k",8},{"mode",modes[std::clamp(accelerationMode,0,2)]},{"exclude_self",true}});
 }
 ImGui::EndDisabled();
 if(!similarityResults.is_object())return;
 ImGui::Spacing();heading("LAST COMPARISON");
 ImGui::Text("Requested %s / used %s",text(similarityResults,"backend_requested").c_str(),text(similarityResults,"backend_used").c_str());
 auto reason=text(similarityResults,"fallback_reason");if(!reason.empty())ImGui::TextWrapped("%s",reason.c_str());
 if(similarityResults.contains("timings")){
  const auto& timing=similarityResults["timings"];
  ImGui::Text("Total %.3f ms | CPU %.3f ms | GPU kernels %.3f ms",timing.value("end_to_end_ms",0.0),timing.value("cpu_ms",0.0),timing.value("kernel_ms",0.0));
  ImGui::Text("GPU setup %.3f ms | transfers %.3f ms | calibration %.3f ms",timing.value("setup_ms",0.0),timing.value("corpus_upload_ms",0.0)+timing.value("query_upload_ms",0.0)+timing.value("download_ms",0.0),timing.value("calibration_ms",0.0));
  if(similarityResults.value("backend_requested",std::string())=="auto")ImGui::TextWrapped("Auto compares resident data: CPU %.3f ms, warm CUDA %.3f ms; required gain %.0f%%. Calibration costs are included above.",similarityResults.value("auto_cpu_baseline_ms",0.0),similarityResults.value("auto_cuda_warm_baseline_ms",0.0),similarityResults.value("auto_minimum_gain_percent",10.0));
 }
 ImGui::Text("Device buffers %.2f MiB | corpus %s",similarityResults.value("device_bytes",0ULL)/1048576.0,similarityResults.value("cache_hit",false)?"reused":"new or unused");
 if(similarityResults.contains("queries")&&ImGui::BeginTable("similar_functions",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,{0,240})){
  for(const char* column:{"Address","Function","Distance / 256","Similarity"})ImGui::TableSetupColumn(column);ImGui::TableHeadersRow();
  for(const auto& query:similarityResults["queries"])for(const auto& match:query["matches"]){
   ImGui::TableNextRow();ImGui::TableNextColumn();auto at=text(match,"address");if(addressLink(at))jump(address(Json(at)));
   ImGui::TableNextColumn();ImGui::TextUnformatted(text(match,"name").c_str());
   ImGui::TableNextColumn();ImGui::Text("%d",match.value("distance",0));
   ImGui::TableNextColumn();ImGui::Text("%.2f%%",match.value("similarity_percent",0.0));
  }ImGui::EndTable();
 }
}
void ExtraViews::drawTabs(Address selected,bool busy,ImFont*mono,std::string&requestedView,std::string&activeView){
 auto begin=[&](const char*name){bool choose=requestedView==name;if(choose)requestedView.clear();bool visible=ImGui::BeginTabItem(name,nullptr,choose?ImGuiTabItemFlags_SetSelected:0);if(visible)activeView=name;return visible;};
 if(begin("Acceleration")){drawAcceleration(selected,busy);ImGui::EndTabItem();}
 if(begin("Graph")){ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Load function graph"))run("get_control_flow",{{"address",hex(selected)},{"instruction_budget",4096}});ImGui::EndDisabled();ImGui::SameLine();heading("Middle-drag to pan / wheel to zoom / double-click to follow");drawGraph(mono);ImGui::EndTabItem();}
 if(begin("References")){ImGui::Checkbox("Outgoing",&outgoing);ImGui::SameLine();ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Find references"))run("get_cross_references",{{"address",hex(selected)},{"outgoing",outgoing},{"instruction_budget",100000}});ImGui::EndDisabled();if(references.is_object()){if(references.value("truncated",false))ImGui::TextColored({1,.7f,.36f,1},"Partial scan. Increase the scan budget through Automation to cover more code.");if(ImGui::BeginTable("references",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,{0,0})){for(auto*col:{"From","To","Kind","Function"})ImGui::TableSetupColumn(col);ImGui::TableHeadersRow();for(auto&r:references["items"]){ImGui::TableNextRow();ImGui::TableNextColumn();auto from=text(r,"from");if(addressLink(from))jump(address(Json(from)));ImGui::TableNextColumn();auto to=text(r,"to");if(addressLink(to))jump(address(Json(to)));ImGui::TableNextColumn();ImGui::TextUnformatted(text(r,"kind").c_str());ImGui::TableNextColumn();ImGui::TextUnformatted(text(r,"function_name").c_str());}ImGui::EndTable();}}ImGui::EndTabItem();}
 if(begin("Calls")){ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Build call graph"))run("get_call_graph",{{"instruction_budget",100000}});ImGui::EndDisabled();if(calls.is_object()){ImGui::SameLine();ImGui::TextColored(dim,"%zu functions / %zu connections",calls["nodes"].size(),calls["edges"].size());std::map<std::string,std::string> names;for(auto&n:calls["nodes"])names[text(n,"address")]=text(n,"name");if(ImGui::BeginTable("calls",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,{0,0})){ImGui::TableSetupColumn("Caller");ImGui::TableSetupColumn("Callee");ImGui::TableSetupColumn("Call sites");ImGui::TableHeadersRow();for(auto&e:calls["edges"]){ImGui::TableNextRow();ImGui::TableNextColumn();auto from=text(e,"from"),to=text(e,"to");if(addressLink((names[from].empty()?from:names[from])+"##"+from))jump(address(Json(from)));ImGui::TableNextColumn();if(addressLink((names[to].empty()?to:names[to])+"##"+to))jump(address(Json(to)));ImGui::TableNextColumn();ImGui::Text("%zu",e["sites"].size());}ImGui::EndTable();}}ImGui::EndTabItem();}
 if(begin("Search")){ImGui::Checkbox("Text search",&textMode);ImGui::SameLine();ImGui::SetNextItemWidth(330);if(textMode)ImGui::InputTextWithHint("##text_search","ASCII / UTF-16 text",textQuery,sizeof(textQuery));else ImGui::InputTextWithHint("##pattern","48 8B ?? ??",pattern,sizeof(pattern));ImGui::SameLine();ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Find")){if(textMode)run("discover_strings",{{"query",textQuery},{"limit",500}});else run("search_bytes",{{"pattern",pattern},{"limit",500}});}if(searchResults.is_object()&&!searchResults.value("next_offset",Json()).is_null()){ImGui::SameLine();if(ImGui::Button("Next page")){auto cursor=searchResults["next_offset"];if(textMode)run("discover_strings",{{"query",textQuery},{"offset",cursor},{"limit",500}});else run("search_bytes",{{"pattern",pattern},{"offset",cursor},{"limit",500}});}}ImGui::EndDisabled();if(searchResults.is_object()){if(ImGui::BeginTable("search_results",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,{0,0})){ImGui::TableSetupColumn("Address");ImGui::TableSetupColumn("File offset");ImGui::TableSetupColumn("Result");ImGui::TableHeadersRow();for(auto&r:searchResults["items"]){ImGui::TableNextRow();ImGui::TableNextColumn();auto va=text(r,"address");if(!va.empty()){if(addressLink(va))jump(address(Json(va)));}else heading("Unmapped");ImGui::TableNextColumn();ImGui::Text("%s",hex(r.value("file_offset",0ULL)).c_str());ImGui::TableNextColumn();auto value=text(r,"text",nullptr);if(value.empty())value=text(r,"bytes");ImGui::TextUnformatted(value.c_str());if(r.contains("encoding")){ImGui::SameLine();heading(text(r,"encoding").c_str());}}ImGui::EndTable();}}ImGui::EndTabItem();}
 if(begin("Bookmarks")){if(notes.empty())ImGui::TextWrapped("Mark a position with Ctrl+B or the inspector.");if(ImGui::BeginTable("notes",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,{0,0})){for(auto*col:{"Address","Bookmark","Label","Comment"})ImGui::TableSetupColumn(col);ImGui::TableHeadersRow();for(auto&n:notes){ImGui::TableNextRow();ImGui::TableNextColumn();auto va=text(n,"address");if(addressLink(va))jump(address(Json(va)));for(auto*key:{"bookmark","label","comment"}){ImGui::TableNextColumn();ImGui::TextUnformatted(text(n,key).c_str());}}ImGui::EndTable();}ImGui::EndTabItem();}
 if(begin("Types")){ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Inspect function types"))run("get_function_types",{{"address",hex(selected)}});ImGui::Spacing();heading("FUNCTION SIGNATURE");ImGui::SetNextItemWidth(-1);ImGui::InputTextWithHint("##signature","int function_name(int count, char *buffer);",signature,sizeof(signature));if(ImGui::Button("Apply signature"))run("set_function_signature",{{"address",hex(selected)},{"declaration",signature}});ImGui::EndDisabled();if(types.is_object()){ImGui::Spacing();ImGui::TextWrapped("%s",text(types,"signature").c_str());if(ImGui::BeginTable("variables",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable,{0,230})){ImGui::TableSetupColumn("Name");ImGui::TableSetupColumn("Type");ImGui::TableSetupColumn("Role");ImGui::TableHeadersRow();for(auto*group:{"parameters","locals"})if(types.contains(group))for(auto&v:types[group]){ImGui::TableNextRow();ImGui::TableNextColumn();auto name=text(v,"name");if(ImGui::Selectable(name.c_str()))copy(variable,sizeof(variable),name);ImGui::TableNextColumn();ImGui::TextUnformatted(text(v,"type").c_str());ImGui::TableNextColumn();heading(group);}ImGui::EndTable();}}ImGui::Spacing();heading("VARIABLE DECLARATION");ImGui::InputText("Variable",variable,sizeof(variable));ImGui::InputText("Declaration",variableDeclaration,sizeof(variableDeclaration));ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Apply variable type"))run("set_variable_type",{{"address",hex(selected)},{"name",variable},{"declaration",variableDeclaration}});ImGui::EndDisabled();ImGui::EndTabItem();}
 if(begin("Patches")){heading("STAGED BYTE EDITS");ImGui::TextWrapped("Stage edits here, then export a separate copy. The open file is preserved.");ImGui::SetNextItemWidth(-1);ImGui::InputTextWithHint("##patch_bytes","Replacement bytes, for example 90 90",patchBytes,sizeof(patchBytes));ImGui::BeginDisabled(busy||!selected);if(ImGui::Button("Stage at selected address"))run("stage_patch",{{"address",hex(selected)},{"bytes",patchBytes}});ImGui::EndDisabled();if(ImGui::BeginTable("patches",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable,{0,220})){for(auto*col:{"Address","Original","Replacement",""})ImGui::TableSetupColumn(col);ImGui::TableHeadersRow();for(auto&p:patches){ImGui::TableNextRow();auto va=text(p,"address");ImGui::TableNextColumn();ImGui::TextUnformatted(va.c_str());ImGui::TableNextColumn();ImGui::TextUnformatted(text(p,"original").c_str());ImGui::TableNextColumn();ImGui::TextUnformatted(text(p,"bytes").c_str());ImGui::TableNextColumn();ImGui::PushID(va.c_str());ImGui::BeginDisabled(busy);if(ImGui::SmallButton("Remove"))run("remove_patch",{{"address",va}});ImGui::EndDisabled();ImGui::PopID();}ImGui::EndTable();}heading("NEW OUTPUT FILE");ImGui::SetNextItemWidth(-1);ImGui::InputText("##patch_output",patchPath,sizeof(patchPath));ImGui::BeginDisabled(busy||patches.empty());if(ImGui::Button("Export patched copy"))run("export_patched",{{"path",patchPath}});ImGui::EndDisabled();ImGui::EndTabItem();}
}
}
