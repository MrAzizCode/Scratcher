#pragma once
#include "core.hpp"
#include "imgui.h"
#include <functional>
#include <map>
namespace scratcher {
struct WorkspaceLayout {
 float navigator=270,inspector=285,previewFraction=.38f;
 bool showInspector=true,splitPreview=false;
 std::string preview="Pseudocode";
 std::filesystem::path settings;
 void load(const std::filesystem::path&);
 void save()const;
 void splitter(const char* id,float height,float& width,bool reverse=false);
};
struct WorkbenchView {
 struct Field {std::vector<char> input=std::vector<char>(32769);bool included=false,boolean=false;};
 std::string category="Analysis",operation,error,resultText;
 std::string renderedCategory;
 std::map<std::string,Field> fields;
 Json result;
 std::function<void(const std::string&,Json)> run;
 std::function<void(Address)> jump;
 void choose(const Json&,Address);
 void update(const std::string&,const Json&);
 void draw(const Json& definitions,Address selected,bool busy,ImFont* mono);
};
}
