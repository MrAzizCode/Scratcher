#include "tools_extra.hpp"
namespace scratcher {
Json extraTools(){
 Json tools=Json::array();auto str=[](const char*d){return Json{{"type","string"},{"description",d}};};auto num=[](size_t max){return Json{{"type","integer"},{"minimum",0},{"maximum",max}};};auto addr=str("Virtual address, for example 0x140001000");
 auto add=[&](const char*n,const char*d,Json p,Json required,bool read){tools.push_back({{"name",n},{"description",d},{"inputSchema",{{"type","object"},{"properties",p},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",read},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("get_control_flow","Recover reachable basic blocks and branch connections for a function.",{{"address",addr},{"instruction_budget",num(100000)}},{"address"},true);
 add("get_cross_references","Find indexed references to or from an address. Scans are bounded and may be partial.",{{"address",addr},{"outgoing",{{"type","boolean"}}},{"instruction_budget",num(1000000)}},{"address"},true);
 add("get_call_graph","Build a function call graph from a bounded reference scan.",{{"instruction_budget",num(1000000)}},Json::array(),true);
 add("set_comment","Set an address comment; empty text removes it.",{{"address",addr},{"text",str("UTF-8 comment text")}},{"address","text"},false);
 add("set_bookmark","Bookmark an address with an optional display name.",{{"address",addr},{"name",str("Bookmark name")}},{"address"},false);
 add("remove_bookmark","Remove a bookmark.",{{"address",addr}},{"address"},false);
 add("set_label","Set a display label at an address; empty name removes it.",{{"address",addr},{"name",str("Display label")}},{"address","name"},false);
 add("list_annotations","List address comments, bookmarks, and labels.",Json::object(),Json::array(),true);
 add("set_function_signature","Apply a C function declaration, return type, named parameters, and calling convention.",{{"address",addr},{"declaration",str("C signature, for example int add(int left, int right);")}},{"address","declaration"},false);
 add("get_function_types","Read a function signature, parameters, and recovered local variables.",{{"address",addr}},{"address"},true);
 add("set_variable_type","Apply a declaration to a recovered variable, retaining its storage size.",{{"address",addr},{"name",str("Existing variable name")},{"declaration",str("Declaration, for example char *buffer")}},{"address","name","declaration"},false);
 add("search_bytes","Search hex bytes with ?? wildcards. Offset is a file-byte cursor; use next_offset to continue.",{{"pattern",str("Hex pattern, for example 48 8B ?? ??")},{"offset",num(SIZE_MAX)},{"limit",num(500)}},{"pattern"},true);
 add("discover_strings","Find ASCII and UTF-16 text. Offset is a file-byte cursor; use next_offset to continue.",{{"minimum",num(4096)},{"offset",num(SIZE_MAX)},{"limit",num(500)},{"query",str("Text filter")}},Json::array(),true);
 add("stage_patch","Stage replacement hex bytes. The input file is preserved.",{{"address",addr},{"bytes",str("Replacement hex bytes")}},{"address","bytes"},false);
 add("list_patches","List staged byte patches and their original bytes.",Json::object(),Json::array(),true);
 add("remove_patch","Remove a staged patch.",{{"address",addr}},{"address"},false);
 add("export_patched","Export a separate patched copy to a new destination file.",{{"path",str("New output path")}},{"path"},false);
 return tools;
}
std::optional<Json> callExtraTool(Engine&e,const std::string&n,const Json&a){
 if(n=="get_control_flow")return e.controlFlow(address(a.at("address")),a.value("instruction_budget",size_t(4096)));
 if(n=="get_cross_references")return e.crossReferences(address(a.at("address")),a.value("outgoing",false),a.value("instruction_budget",size_t(100000)));
 if(n=="get_call_graph")return e.callGraph(a.value("instruction_budget",size_t(100000)));
 if(n=="set_comment")return e.setComment(address(a.at("address")),a.at("text"));
 if(n=="set_bookmark")return e.setBookmark(address(a.at("address")),a.value("name",std::string()));
 if(n=="remove_bookmark")return e.removeBookmark(address(a.at("address")));
 if(n=="set_label")return e.setLabel(address(a.at("address")),a.at("name"));
 if(n=="list_annotations")return e.annotations();
 if(n=="set_function_signature")return e.setSignature(address(a.at("address")),a.at("declaration"));
 if(n=="get_function_types")return e.functionTypes(address(a.at("address")));
 if(n=="set_variable_type")return e.setVariableType(address(a.at("address")),a.at("name"),a.at("declaration"));
 if(n=="search_bytes")return e.searchPattern(a.at("pattern"),a.value("offset",size_t(0)),a.value("limit",size_t(500)));
 if(n=="discover_strings")return e.discoverText(a.value("minimum",size_t(5)),a.value("offset",size_t(0)),a.value("limit",size_t(500)),a.value("query",std::string()));
 if(n=="stage_patch")return e.stagePatch(address(a.at("address")),a.at("bytes"));
 if(n=="list_patches")return Json{{"items",e.listPatches()}};
 if(n=="remove_patch")return e.removePatch(address(a.at("address")));
 if(n=="export_patched")return e.exportPatched(std::filesystem::u8path(a.at("path").get<std::string>()));
 return std::nullopt;
}
}
