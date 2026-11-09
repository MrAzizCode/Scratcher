#include "feature_advanced_pseudocode.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "printlanguage.hh"
#include "type.hh"
#include "xml.hh"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <functional>
#include <regex>
#include <sstream>

namespace scratcher {
namespace {
bool identifier(const std::string&s){return !s.empty()&&s.size()<=128&&(std::isalpha((unsigned char)s[0])||s[0]=='_')&&std::all_of(s.begin(),s.end(),[](unsigned char c){return std::isalnum(c)||c=='_';});}
ghidra::Funcdata* function(Engine&e,Address va){
 if(!e.binary()||!e.binary()->analysisCode(va))throw std::runtime_error("Choose an executable function address");
 auto*a=e.nativeArchitecture();auto*s=a->symboltab->getGlobalScope();ghidra::Address at(a->getDefaultCodeSpace(),va);auto*f=s->queryFunction(at);
 if(!f)f=s->addFunction(at,"sub_"+hex(va).substr(2))->getFunction();return f;
}
ghidra::Funcdata* analyzed(Engine&e,Address va){
 e.decompile(va);auto*f=function(e,va);if(!f->isProcStarted()){e.invalidateDecompilation();e.decompile(va);f=function(e,va);}return f;
}
Json state(const Engine&e,Address va){
 const auto&s=e.advancedState();if(s.contains("pseudocode")&&s["pseudocode"].is_object()&&s["pseudocode"].contains(hex(va)))return s["pseudocode"][hex(va)];return Json::object();
}
void store(Engine&e,Address va,const Json&v){if(!e.advancedState().contains("pseudocode"))e.advancedState()["pseudocode"]=Json::object();e.advancedState()["pseudocode"][hex(va)]=v;e.nativeArchitecture()->clearAnalysis(function(e,va));e.invalidateDecompilation();}
ghidra::PrototypePieces prototype(Engine&e,const std::string&text){
 if(text.empty()||text.size()>4096||text.find_first_of("{}#\"'")!=std::string::npos||text.find('\0')!=std::string::npos)throw std::runtime_error("Enter a single C function declaration up to 4096 characters");
 auto t=text;while(!t.empty()&&std::isspace((unsigned char)t.back()))t.pop_back();if(t.back()!=';')t+=';';if(t.find(';')!=t.size()-1)throw std::runtime_error("Enter one C function declaration");
 t=std::regex_replace(t,std::regex("\\bunsigned\\s+int\\b"),"uint");
 ghidra::PrototypePieces p{};std::istringstream in(t);ghidra::parse_protopieces(p,in,e.nativeArchitecture());
 if(!identifier(p.name)||p.intypes.size()>64||!p.model)throw std::runtime_error("Invalid call-site signature");
 std::vector<ghidra::ParameterPieces> assigned;p.model->assignParameterStorage(p,assigned,false);return p;
}
void checkInstruction(Engine&e,Address fn,Address va,const std::string&kind){
 auto*f=analyzed(e,fn);bool found=false;
 for(auto it=f->beginOpAlive();it!=f->endOpAlive();++it){auto*op=*it;if(op->getAddr().getOffset()!=va)continue;
  auto c=op->code();if(kind=="call"&&(c==ghidra::CPUI_CALL||c==ghidra::CPUI_CALLIND))found=true;
  if(kind=="indirect"&&c==ghidra::CPUI_CALLIND)found=true;
  if(kind=="jump"&&c==ghidra::CPUI_BRANCHIND)found=true;
  if(kind=="branch"&&(c==ghidra::CPUI_BRANCH||c==ghidra::CPUI_CBRANCH))found=true;
 }
 if(!found)throw std::runtime_error("The selected instruction is not a recovered "+kind+" in this function");
}
std::string attr(const ghidra::Element*el,const std::string&name){for(int i=0;i<el->getNumAttributes();++i)if(el->getAttributeName(i)==name)return el->getAttributeValue(i);return {};}
Json mapping(Engine&e,Address va,size_t offset,size_t limit){
 if(limit==0||limit>10000)throw std::runtime_error("Token limit must be between 1 and 10000");auto*f=analyzed(e,va);auto*a=e.nativeArchitecture();
 a->print->setFlat(state(e,va).value("options",Json::object()).value("flat",false));
 std::map<uint64_t,Address> operations;for(auto it=f->beginOpAlive();it!=f->endOpAlive();++it)operations[(*it)->getTime()]=(*it)->getAddr().getOffset();
 std::ostringstream markup,discard;bool previous=a->print->emitsMarkup();auto*previousStream=a->print->getOutputStream();
 // Changing the stream recreates the encoder in packed mode. Select XML afterwards.
 try{a->print->setMarkup(true);a->print->setOutputStream(&markup);a->print->setPackedOutput(false);a->print->docFunction(f);a->print->setOutputStream(&discard);a->print->setMarkup(previous);a->print->setOutputStream(previousStream);}
 catch(...){a->print->setOutputStream(&discard);a->print->setMarkup(previous);a->print->setOutputStream(previousStream);throw;}
 if(markup.str().size()>16*1024*1024)throw std::runtime_error("Pseudocode mapping exceeds 16 MiB; reduce the function analysis limit");
 std::istringstream input(markup.str());std::unique_ptr<ghidra::Document> doc(ghidra::xml_tree(input));
 Json tokens=Json::array(),lines=Json::array();size_t row=1,column=0,total=0;std::string code;std::map<size_t,std::set<Address>> lineAddresses;
 std::function<void(const ghidra::Element*,std::string)> walk=[&](const ghidra::Element*el,std::string inherited){
  auto reference=attr(el,"opref");if(reference.empty())reference=inherited;
  if(el->getName()=="break"){code+='\n';++row;column=0;auto indent=attr(el,"indent");size_t n=indent.empty()?0:std::stoull(indent);if(n>4096)throw std::runtime_error("Invalid pseudocode indentation");code.append(n,' ');column=n;return;}
  if(!el->getContent().empty()){
   auto text=el->getContent();Json token={{"index",total},{"line",row},{"column",column},{"text",text},{"kind",el->getName()},{"instruction_address",nullptr}};
   if(!reference.empty()){auto found=operations.find(std::stoull(reference,nullptr,0));if(found!=operations.end()){token["instruction_address"]=hex(found->second);lineAddresses[row].insert(found->second);}}
   auto varref=attr(el,"varref");if(!varref.empty())token["variable_id"]=varref;auto color=attr(el,"color");if(!color.empty())token["color"]=std::stoul(color,nullptr,0);
   if(total>=offset&&tokens.size()<limit)tokens.push_back(token);++total;column+=text.size();code+=text;
  }
  for(auto*child:el->getChildren())walk(child,reference);
 };
 walk(doc->getRoot(),{});for(auto&[line,addresses]:lineAddresses){Json values=Json::array();for(auto x:addresses)values.push_back(hex(x));lines.push_back({{"line",line},{"instruction_addresses",values}});}
 return {{"address",hex(va)},{"code",code},{"tokens",tokens},{"lines",lines},{"total",total},{"offset",offset},{"next_offset",offset+tokens.size()<total?Json(offset+tokens.size()):Json(nullptr)},{"mapping","native_operation_metadata"},{"column_unit","UTF-8 bytes"},{"unmapped_tokens","Declarations and syntax may have no instruction address"}};
}
}
void applyPseudocodeOptions(Engine&e,Address va){
 auto*a=e.nativeArchitecture();auto settings=state(e,va);a->max_instructions=50000;a->max_jumptable_size=1024;a->print->setFlat(false);
 if(settings.is_null()||settings.empty())return;if(!settings.is_object())throw std::runtime_error("Invalid saved pseudocode settings");
 if(settings.contains("options")){const auto&o=settings["options"];auto n=o.value("max_instructions",uint64_t(50000)),j=o.value("max_jump_table_entries",uint64_t(1024));if(n<1||n>1000000||j<1||j>65536)throw std::runtime_error("Invalid saved pseudocode limits");a->max_instructions=(ghidra::uint4)n;a->max_jumptable_size=(ghidra::uint4)j;a->print->setFlat(o.value("flat",false));}
 auto*f=function(e,va);auto space=a->getDefaultCodeSpace();
 for(auto&item:settings.value("call_prototypes",Json::array())){auto p=prototype(e,item.at("declaration"));auto fp=std::make_unique<ghidra::FuncProto>();fp->setInternal(p.model,a->types->getTypeVoid());fp->setPieces(p);f->getOverride().insertProtoOverride(ghidra::Address(space,address(item.at("call_address"))),fp.release());}
 for(auto&item:settings.value("indirect_targets",Json::array())){auto target=address(item.at("target"));function(e,target);f->getOverride().insertIndirectOverride(ghidra::Address(space,address(item.at("call_address"))),ghidra::Address(space,target));}
 for(auto&item:settings.value("forced_gotos",Json::array()))f->getOverride().insertForceGoto(ghidra::Address(space,address(item.at("branch_address"))),ghidra::Address(space,address(item.at("target"))));
 for(auto&item:settings.value("multistage_jumps",Json::array())){ghidra::Address at(space,address(item));if(!f->getOverride().queryMultistageJumptable(at))f->getOverride().insertMultistageJump(at);}
}
Json pseudocodeTools(){
 Json out=Json::array();Json addr={{"type","string"}},str={{"type","string"}};
 auto add=[&](const char*n,const char*d,Json p,Json req,bool read){out.push_back({{"name",n},{"description",d},{"inputSchema",{{"type","object"},{"properties",p},{"required",req},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",read},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("get_pseudocode_mapping","Get structured pseudocode tokens with real instruction metadata; syntax and declarations may be unmapped.",{{"address",addr},{"offset",{{"type","integer"},{"minimum",0}}},{"limit",{{"type","integer"},{"minimum",1},{"maximum",10000}}}},Json::array({"address"}),true);
 add("rename_variable","Rename a recovered variable while preserving its native type and storage size.",{{"address",addr},{"name",str},{"new_name",str}},Json::array({"address","name","new_name"}),false);
 add("set_call_site_signature","Apply a C prototype to one recovered direct or indirect call instruction.",{{"address",addr},{"call_address",addr},{"declaration",str}},Json::array({"address","call_address","declaration"}),false);
 add("set_indirect_call_target","Resolve one recovered indirect call to an executable target address.",{{"address",addr},{"call_address",addr},{"target",addr}},Json::array({"address","call_address","target"}),false);
 add("force_pseudocode_goto","Force an existing branch to render as a goto to an existing recovered instruction.",{{"address",addr},{"branch_address",addr},{"target",addr}},Json::array({"address","branch_address","target"}),false);
 add("mark_multistage_jump","Request multistage recovery for a recovered indirect jump.",{{"address",addr},{"jump_address",addr}},Json::array({"address","jump_address"}),false);
 add("set_pseudocode_options","Persist per-function instruction/jump-table analysis limits and structured/flat output.",{{"address",addr},{"max_instructions",{{"type","integer"},{"minimum",1},{"maximum",1000000}}},{"max_jump_table_entries",{{"type","integer"},{"minimum",1},{"maximum",65536}}},{"flat",{{"type","boolean"}}}},Json::array({"address"}),false);
 add("get_pseudocode_controls","Get saved controls and explicit support status for contextual pseudocode actions.",{{"address",addr}},Json::array({"address"}),true);
 add("reset_pseudocode_controls","Remove all call/flow overrides and options for one function, retaining signatures and variable edits.",{{"address",addr}},Json::array({"address"}),false);return out;
}
std::optional<Json> callPseudocodeTool(Engine&e,const std::string&name,const Json&args){
 if(name!="get_pseudocode_mapping"&&name!="rename_variable"&&name!="set_call_site_signature"&&name!="set_indirect_call_target"&&name!="force_pseudocode_goto"&&name!="mark_multistage_jump"&&name!="set_pseudocode_options"&&name!="get_pseudocode_controls"&&name!="reset_pseudocode_controls")return std::nullopt;
 auto va=address(args.at("address"));function(e,va);
 try{
 if(name=="get_pseudocode_mapping")return mapping(e,va,args.value("offset",size_t(0)),args.value("limit",size_t(2000)));
 if(name=="reset_pseudocode_controls"){
  auto workspace=e.workspaceState();if(workspace.contains("advanced")&&workspace["advanced"].contains("pseudocode"))workspace["advanced"]["pseudocode"].erase(hex(va));
  // Native overrides survive clearAnalysis; rebuild is necessary to actually remove them.
  e.rebuildArchitecture();e.restoreWorkspaceState(workspace);return Json{{"address",hex(va)},{"applied",true},{"settings",Json::object()},{"requires_reanalysis",true}};
 }
 if(name=="get_pseudocode_controls")return Json{{"address",hex(va)},{"settings",state(e,va)},{"actions",{{"rename_variable",true},{"retype_variable",true},{"call_site_signature",true},{"indirect_call_target",true},{"token_instruction_mapping",true},{"force_goto",true},{"multistage_jump",true},{"split_variable",false},{"merge_variables",false}}},{"variable_split_merge_limitation","Stable lifetime-specific variable selection and undo support are required before exposing split or merge operations"}};
 if(name=="rename_variable"){
  const std::string old=args.at("name"),next=args.at("new_name");if(!identifier(next))throw std::runtime_error("Use a C identifier up to 128 characters");auto types=e.functionTypes(va);Json matched;size_t count=0;
  for(auto key:{"parameters","locals"})for(auto&v:types[key]){if(v["name"]==next&&next!=old)throw std::runtime_error("The new variable name already exists");if(v["name"]==old){matched=v;++count;}}
  if(count!=1)throw std::runtime_error("Choose an unambiguous recovered variable");auto result=e.setVariableType(va,old,matched.at("type").get<std::string>()+" "+next+";");result["storage_preserved"]=true;return result;
 }
 auto settings=state(e,va);
 if(name=="set_pseudocode_options"){
  auto opts=settings.value("options",Json::object());for(auto key:{"max_instructions","max_jump_table_entries","flat"})if(args.contains(key))opts[key]=args[key];auto n=opts.value("max_instructions",uint64_t(50000)),j=opts.value("max_jump_table_entries",uint64_t(1024));if(n<1||n>1000000||j<1||j>65536)throw std::runtime_error("Pseudocode limits are out of range");settings["options"]=opts;
 }else{
  const char*key=nullptr,*identity=nullptr;Json item;
  if(name=="set_call_site_signature"){auto at=address(args.at("call_address"));checkInstruction(e,va,at,"call");prototype(e,args.at("declaration"));key="call_prototypes";identity="call_address";item={{identity,hex(at)},{"declaration",args.at("declaration")}};}
  if(name=="set_indirect_call_target"){auto at=address(args.at("call_address")),target=address(args.at("target"));checkInstruction(e,va,at,"indirect");if(!e.binary()->analysisCode(target))throw std::runtime_error("Indirect call target is not executable");key="indirect_targets";identity="call_address";item={{identity,hex(at)},{"target",hex(target)}};}
  if(name=="force_pseudocode_goto"){auto at=address(args.at("branch_address")),target=address(args.at("target"));checkInstruction(e,va,at,"branch");auto*f=analyzed(e,va);bool present=false;for(auto it=f->beginOpAlive();it!=f->endOpAlive();++it)if((*it)->getAddr().getOffset()==target)present=true;if(!present)throw std::runtime_error("Goto target must be an instruction in this recovered function");key="forced_gotos";identity="branch_address";item={{identity,hex(at)},{"target",hex(target)}};}
  if(name=="mark_multistage_jump"){auto at=address(args.at("jump_address"));checkInstruction(e,va,at,"jump");auto&list=settings["multistage_jumps"];if(list.is_null())list=Json::array();if(std::find(list.begin(),list.end(),Json(hex(at)))==list.end())list.push_back(hex(at));}
  if(key){auto&list=settings[key];if(list.is_null())list=Json::array();list.erase(std::remove_if(list.begin(),list.end(),[&](const Json&v){return v.at(identity)==item.at(identity);}),list.end());if(list.size()>=1024)throw std::runtime_error("Too many per-function overrides");list.push_back(item);}
 }
 store(e,va,settings);return Json{{"address",hex(va)},{"applied",true},{"settings",settings},{"requires_reanalysis",true}};
 }catch(const ghidra::ParseError&){throw std::runtime_error("Invalid C call-site declaration");}catch(const ghidra::LowlevelError&){throw std::runtime_error("The selected pseudocode operation could not be applied");}
}
}
