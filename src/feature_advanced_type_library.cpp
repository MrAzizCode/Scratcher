#include "feature_advanced_type_library.hpp"
#include "architecture.hh"
#include "grammar.hh"
#include "type.hh"
#include <algorithm>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

namespace scratcher {
namespace {
constexpr size_t maxHeader=262144, maxTypes=2048;
bool identifier(const std::string& s) {return std::regex_match(s,std::regex("[A-Za-z_][A-Za-z_0-9]{0,127}"));}
void checkCancelled(Engine& e){if(e.cancelled())throw std::runtime_error("Type operation cancelled");}
Json library(Engine& e){return e.advancedState().value("type_library",Json::array());}
std::string normalized(std::string text){
 const std::vector<std::pair<std::string,std::string>> aliases={
 {"unsigned\\s+long\\s+long(?:\\s+int)?","uint64_t"},{"signed\\s+long\\s+long(?:\\s+int)?","int64_t"},{"long\\s+long(?:\\s+int)?","int64_t"},
 {"unsigned\\s+long(?:\\s+int)?","ulong"},{"unsigned\\s+short(?:\\s+int)?","ushort"},{"unsigned\\s+char","uchar"},{"unsigned(?:\\s+int)?","uint"},
 {"signed\\s+char","schar"},{"signed\\s+short(?:\\s+int)?","short"},{"signed\\s+long(?:\\s+int)?","long"},{"signed(?:\\s+int)?","int"},{"short\\s+int","short"},{"long\\s+int","long"}};
 for(auto& [p,r]:aliases)text=std::regex_replace(text,std::regex("\\b"+p+"\\b"),r);
 return text;
}
std::string trim(std::string s){auto p=s.find_first_not_of(" \t\r\n");if(p==std::string::npos)return {};return s.substr(p,s.find_last_not_of(" \t\r\n")-p+1);}
// Intentionally bounded C declarations: no preprocessing, function declarations,
// expressions, bitfields, packing pragmas, anonymous nested aggregates or C++.
Json parseHeader(const std::string& input){
 if(input.empty()||input.size()>maxHeader)throw std::runtime_error("Header must contain 1 to 262144 bytes");
 std::string text; bool line=false,block=false;
 for(size_t i=0;i<input.size();++i){char c=input[i],n=i+1<input.size()?input[i+1]:0;
  if(line){if(c=='\n'){line=false;text+=' ';}continue;}
  if(block){if(c=='*'&&n=='/'){block=false;++i;text+=' ';}continue;}
  if(c=='/'&&n=='/'){line=true;++i;continue;}if(c=='/'&&n=='*'){block=true;++i;continue;}
  if(c==0||c=='#'||c=='"'||c=='\''||c=='('||c==')'||c==':'||c=='<'||c=='>')throw std::runtime_error("Unsupported C syntax: only named aggregates and typedefs are accepted");
  text+=c;
 }
 if(block)throw std::runtime_error("Unclosed C comment");
 Json result=Json::array();size_t start=0;int depth=0;
 for(size_t i=0;i<text.size();++i){if(text[i]=='{'){if(++depth>1)throw std::runtime_error("Nested aggregate definitions are unsupported");}
  if(text[i]=='}'&&--depth<0)throw std::runtime_error("Unbalanced aggregate braces");
  if(text[i]!=';'||depth)continue;
  auto declaration=trim(text.substr(start,i-start+1));start=i+1;if(declaration.empty())continue;
  std::smatch m;std::string name,kind;
  if(std::regex_match(declaration,m,std::regex("(struct|union|enum)\\s+([A-Za-z_][A-Za-z_0-9]*)\\s*\\{[\\s\\S]*\\}\\s*;"))){kind=m[1];name=m[2];}
  else if(std::regex_match(declaration,m,std::regex("typedef\\s+[\\s\\S]*\\b([A-Za-z_][A-Za-z_0-9]*)\\s*(?:\\[\\s*([0-9]+)\\s*\\])?\\s*;"))){name=m[1];kind=m[2].matched?"array":"typedef";
   if(declaration.find('{')!=std::string::npos)throw std::runtime_error("Declare named aggregates separately before typedef aliases");}
  else throw std::runtime_error("Expected named struct, union, enum or typedef declaration");
  if(!identifier(name)||result.size()>=maxTypes)throw std::runtime_error("Invalid name or too many types");
  // Array counts are bounded before invoking the native C parser.
  std::regex arrays("\\[\\s*([0-9]+)\\s*\\]");
  uint64_t product=1;for(std::sregex_iterator it(declaration.begin(),declaration.end(),arrays),end;it!=end;++it){auto count=std::stoull((*it)[1]);if(!count||count>1048576||product>1048576/count)throw std::runtime_error("Array dimensions exceed the supported bound");product*=count;}
  result.push_back({{"name",name},{"kind",kind},{"declaration",declaration}});
 }
 if(depth||!trim(text.substr(start)).empty()||result.empty())throw std::runtime_error("Incomplete C declaration; a semicolon is required");
 return result;
}
Json describe(Engine& e,const Json& item){
 auto* t=e.nativeArchitecture()->types->findByName(item.at("name").get<std::string>());if(!t)throw std::runtime_error("Type registration failed");
 Json row=item;row["size"]=t->getSize();row["alignment"]=t->getAlignment();row["registered"]=true;
 auto field=[](const ghidra::TypeField& f){return Json{{"name",f.name},{"offset",f.offset},{"size",f.type->getSize()},{"type",f.type->getName()}};};
 if(t->getMetatype()==ghidra::TYPE_STRUCT){row["fields"]=Json::array();auto* s=static_cast<ghidra::TypeStruct*>(t);for(auto it=s->beginField();it!=s->endField();++it)row["fields"].push_back(field(*it));}
 if(t->getMetatype()==ghidra::TYPE_UNION){row["fields"]=Json::array();auto* u=static_cast<ghidra::TypeUnion*>(t);for(int i=0;i<u->numDepend();++i)row["fields"].push_back(field(*u->getField(i)));}
 if(t->isEnumType()){row["values"]=Json::array();auto* v=static_cast<ghidra::TypeEnum*>(t);for(auto it=v->beginEnum();it!=v->endEnum();++it)row["values"].push_back({{"name",it->second},{"value",it->first}});}
 return row;
}
Json list(Engine& e){if(!e.binary())throw std::runtime_error("Open a binary first");Json rows=Json::array();for(auto& t:library(e)){checkCancelled(e);rows.push_back(describe(e,t));}
 return {{"types",rows},{"count",rows.size()},{"abi",{{"pointer_bytes",e.binary()->bits/8},{"long_bytes",e.binary()->format=="ELF"&&e.binary()->bits==64?8:4},{"enum_bytes",4},{"layout","Natural alignment; explicit packing and bitfields unsupported"}}},{"supported_c","Named struct/union/enum definitions, primitive or existing-type typedefs, pointers and fixed-size arrays; comments accepted; no preprocessor, C++, function declarations or bitfields"}};
}
Json install(Engine& e,const Json& next){
 if(!e.binary())throw std::runtime_error("Open a binary first");if(next.size()>maxTypes)throw std::runtime_error("At most 2048 types are supported");
 if(next.dump().size()>1048576)throw std::runtime_error("Combined type declarations exceed 1 MiB");
 checkCancelled(e);auto old=library(e);auto workspace=e.workspaceState();
 // Parse everything against an isolated architecture before touching live types.
 Engine candidate;candidate.open(e.binary()->path,e.binary()->base,e.binary()->bits);candidate.advancedState()["type_library"]=next;restoreTypeLibrary(candidate);
 auto validationWorkspace=workspace;validationWorkspace.erase("advanced");validationWorkspace.erase("advanced_state");candidate.restoreWorkspaceState(validationWorkspace);
 checkCancelled(e);e.advancedState()["type_library"]=next;
 try{e.rebuildArchitecture();restoreTypeLibrary(e);auto replay=workspace;replay.erase("advanced");replay.erase("advanced_state");e.restoreWorkspaceState(replay);}
 catch(...){e.advancedState()["type_library"]=old;e.rebuildArchitecture();restoreTypeLibrary(e);auto replay=workspace;replay.erase("advanced");replay.erase("advanced_state");e.restoreWorkspaceState(replay);throw;}
 return list(e);
}
Json merge(Engine& e,const Json& additions,bool replace){auto next=library(e);for(auto& t:additions){auto it=std::find_if(next.begin(),next.end(),[&](auto& row){return row.at("name")==t.at("name");});if(it==next.end())next.push_back(t);else if(replace)*it=t;else throw std::runtime_error("Type already exists: "+t.at("name").get<std::string>());}return install(e,next);}
}
void restoreTypeLibrary(Engine& e){
 auto rows=library(e);if(!rows.is_array()||rows.size()>maxTypes||rows.dump().size()>1048576)throw std::runtime_error("Invalid or oversized type library");if(rows.empty())return;
 auto* arch=e.nativeArchitecture();std::set<std::string> names;
 try{for(auto& row:rows){auto name=row.at("name").get<std::string>();if(!identifier(name)||!names.insert(name).second)throw std::runtime_error("Invalid or duplicate type name");
  auto declarations=parseHeader(row.at("declaration").get<std::string>());if(declarations.size()!=1||declarations[0]["name"]!=name)throw std::runtime_error("Type declaration name does not match");
  if(auto* existing=arch->types->findByName(name)){if(existing->isCoreType())throw std::runtime_error("Custom type name conflicts with a built-in type");continue;}
  auto declaration=normalized(row.at("declaration").get<std::string>());
  for(auto& declared:rows){auto tag=declared.at("name").get<std::string>();if(identifier(tag)&&arch->types->findByName(tag))declaration=std::regex_replace(declaration,std::regex("\\b(?:struct|union|enum)\\s+("+tag+")\\b(?!\\s*\\{)"),"$1");}
  // Check fixed array sizes before native multiplication; custom elements can
  // themselves be very large. Every field is validated independently.
  auto parts=declaration;auto open=parts.find('{');if(open!=std::string::npos)parts=parts.substr(open+1,parts.find_last_of('}')-open-1);
  std::istringstream fields(parts);std::string part;std::regex arrays("\\[\\s*([0-9]+)\\s*\\]");
  while(std::getline(fields,part,';')){if(part.find('[')==std::string::npos)continue;uint64_t count=1;for(std::sregex_iterator it(part.begin(),part.end(),arrays),end;it!=end;++it)count*=std::stoull((*it)[1]);
   auto base=std::regex_replace(part,arrays,"");base=std::regex_replace(base,std::regex("^\\s*typedef\\s+"),"");std::istringstream input(base);std::string variable;auto* element=ghidra::parse_type(input,variable,arch);
   if(!element||element->getSize()<=0||count>16777216/static_cast<uint64_t>(element->getSize()))throw std::runtime_error("Array type exceeds 16 MiB");}
  if(declaration.starts_with("typedef ")){auto text=declaration.substr(8);text.pop_back();std::istringstream input(text);std::string alias;auto* target=ghidra::parse_type(input,alias,arch);if(alias!=name)throw std::runtime_error("Invalid typedef name");arch->types->getTypedef(target,name,0,0);}
  else {std::istringstream stream(declaration);ghidra::parse_C(arch,stream);}
  auto* type=arch->types->findByName(name);if(!type||type->getSize()<=0||type->getSize()>16777216)throw std::runtime_error("Type must be complete and at most 16 MiB");
 }}catch(const ghidra::ParseError&error){throw std::runtime_error("Invalid C type declaration: "+error.explain);}catch(const ghidra::LowlevelError&error){throw std::runtime_error("Type layout cannot be represented: "+error.explain);}
}
Json typeLibraryTools(){
 Json tools=Json::array();auto str=[](const char* d){return Json{{"type","string"},{"description",d}};};auto add=[&](const char* n,const char* d,Json p,Json r,bool read){tools.push_back({{"name",n},{"description",d},{"inputSchema",{{"type","object"},{"properties",p},{"required",r},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",read},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("list_types","List registered native types with actual ABI sizes, fields and enum values.",Json::object(),Json::array(),true);
 add("define_type","Create or replace a named struct, union, enum, typedef or array from a C declaration.",{{"declaration",str("One named aggregate or typedef declaration")},{"replace",{{"type","boolean"}}}},{"declaration"},false);
 add("delete_type","Remove a custom type. Referenced types cannot be removed unless dependent types and edits are removed first.",{{"name",str("Custom type name")}},{"name"},false);
 add("import_c_header","Atomically import up to 256 KiB of the documented C declaration subset; binary and function edits are preserved.",{{"text",str("C declarations, no preprocessing")},{"replace",{{"type","boolean"}}}},{"text"},false);
 add("save_type_library","Save custom C type declarations and ABI information as JSON.",{{"path",str("Output JSON file")}},{"path"},false);
 add("load_type_library","Atomically load a bounded JSON type library; reject mismatched pointer and long ABI widths.",{{"path",str("Type library JSON path")},{"replace",{{"type","boolean"}}}},{"path"},false);
 return tools;
}
std::optional<Json> callTypeLibraryTool(Engine& e,const std::string& n,const Json& a){
 if(n=="list_types")return list(e);
 if(n=="define_type"){auto parsed=parseHeader(a.at("declaration"));if(parsed.size()!=1)throw std::runtime_error("define_type accepts one declaration");return merge(e,parsed,a.value("replace",false));}
 if(n=="import_c_header")return merge(e,parseHeader(a.at("text")),a.value("replace",false));
 if(n=="delete_type"){auto name=a.at("name").get<std::string>();auto next=library(e);auto it=std::find_if(next.begin(),next.end(),[&](auto& t){return t["name"]==name;});if(it==next.end())throw std::runtime_error("Custom type not found");next.erase(it);return install(e,next);}
 if(n=="save_type_library"){auto result=list(e);auto path=std::filesystem::u8path(a.at("path").get<std::string>());std::error_code ec;if(e.binary()&&std::filesystem::equivalent(path,e.binary()->path,ec))throw std::runtime_error("Choose a path other than the input binary");std::ofstream out(path,std::ios::binary|std::ios::trunc);if(!out)throw std::runtime_error("Unable to save type library");Json value={{"scratcher_type_library",1},{"abi",result["abi"]},{"types",library(e)}};out<<value.dump(2);out.close();if(!out)throw std::runtime_error("Unable to complete type library write");return Json{{"path",pathText(path)},{"count",value["types"].size()}};}
 if(n=="load_type_library"){if(!e.binary())throw std::runtime_error("Open a binary first");auto path=std::filesystem::u8path(a.at("path").get<std::string>());if(std::filesystem::file_size(path)>1048576)throw std::runtime_error("Type library exceeds 1 MiB");std::ifstream in(path,std::ios::binary);Json doc=Json::parse(in);auto abi=list(e)["abi"];if(doc.at("scratcher_type_library")!=1||doc.at("abi").at("pointer_bytes")!=abi["pointer_bytes"]||doc["abi"].at("long_bytes")!=abi["long_bytes"])throw std::runtime_error("Type library ABI does not match the binary");auto rows=doc.at("types");if(!rows.is_array()||rows.size()>maxTypes)throw std::runtime_error("Invalid type library");Json parsed=Json::array();for(auto& row:rows){auto one=parseHeader(row.at("declaration"));if(one.size()!=1||one[0]["name"]!=row.at("name"))throw std::runtime_error("Invalid type library declaration");parsed.push_back(one[0]);}return merge(e,parsed,a.value("replace",false));}
 return std::nullopt;
}
}
