#pragma once
#include "core.hpp"
#include "imgui.h"
#include <functional>
namespace scratcher {
struct ExtraViews {
 Json graph,references,calls,types,notes=Json::array(),patches=Json::array(),searchResults;
 Json accelerationInfo,similarityIndex,similarityResults;
 int accelerationMode=0;
 std::function<void(const std::string&,Json)> run;
 std::function<void(Address)> jump;
 char comment[16385]{},bookmark[257]{},label[257]{},signature[4097]{},variable[129]{},variableDeclaration[4097]{};
 char pattern[4097]="48 8B ??",textQuery[257]{},patchBytes[4097]{},patchPath[1024]="D:/Scratcher/patched.bin";
 bool outgoing=false,textMode=false;Address editing=UINT64_MAX;ImVec2 pan{20,20};float zoom=1;
 Json graphViews=Json::object();std::filesystem::path graphSettings;std::string graphScope,graphKey;
 std::map<std::string,ImVec2> graphPositions;std::map<std::string,float> graphHeights;ImVec2 graphExtent{1,1};bool graphLayoutDirty=true;
 void loadGraphViews(const std::filesystem::path&);
 void saveGraphViews();
 void rememberGraphView();
 void buildGraphLayout();
 void update(const std::string&name,const Json&data,const Json&workspace);
 void clear();
 void drawTabs(Address selected,bool busy,ImFont* mono,std::string& requestedView,std::string& activeView);
 void drawInspector(Address selected,bool busy);
 void drawGraph(ImFont* mono);
 void drawAcceleration(Address selected,bool busy);
};
}
