#include "core.hpp"
#include "session.hpp"
#include "feature_graph.hpp"
#include "feature_xrefs.hpp"
#include "feature_types.hpp"
#include "feature_search.hpp"
#include "feature_advanced_manual.hpp"
#include <algorithm>
namespace scratcher {
void Engine::resetFeatures(){features_=std::make_unique<SessionFeatures>();}
Json Engine::controlFlow(Address va,size_t budget){require();auto key=hex(va)+":"+std::to_string(budget);if(features_->graphs.contains(key)){auto value=features_->graphs[key];value["cached"]=true;return value;}auto value=buildControlFlowGraph(*this,va,budget);auto bytes=value.dump().size();if(bytes<=8*1024*1024){if(features_->graphBytes+bytes>8*1024*1024){features_->graphs=Json::object();features_->graphBytes=0;}features_->graphBytes+=bytes;features_->graphs[key]=value;}value["cached"]=false;return value;}
Json Engine::crossReferences(Address va,bool outgoing,size_t budget){require();if(features_->references.is_null()||features_->referenceBudget<budget){features_->references=collectCrossReferences(*this,budget);features_->referenceBudget=budget;}return referencesAt(features_->references,va,outgoing);}
Json Engine::callGraph(size_t budget){require();if(features_->references.is_null()||features_->referenceBudget<budget){features_->references=collectCrossReferences(*this,budget);features_->referenceBudget=budget;}return buildCallGraph(features_->references,*binary_);}
Json Engine::setComment(Address va,const std::string&text){require();return features_->notes.setComment(va,text);}
Json Engine::setBookmark(Address va,const std::string&name){require();return features_->notes.setBookmark(va,name);}
Json Engine::removeBookmark(Address va){require();return features_->notes.removeBookmark(va);}
Json Engine::setLabel(Address va,const std::string&name){require();return features_->notes.setLabel(va,name);}
Json Engine::annotations()const{require();return features_->notes.list();}
Json Engine::setSignature(Address va,const std::string&decl){require();auto result=setFunctionSignature(*this,va,decl);features_->signatures[va]=decl;auto&edits=features_->variableEdits;edits.erase(std::remove_if(edits.begin(),edits.end(),[va](const Json&edit){return address(edit["address"])==va;}),edits.end());return result;}
Json Engine::functionTypes(Address va){require();return describeFunctionTypes(*this,va);}
Json Engine::setVariableType(Address va,const std::string&name,const std::string&decl){require();auto result=scratcher::setVariableType(*this,va,name,decl);features_->variableEdits.push_back({{"address",hex(va)},{"name",name},{"declaration",decl}});auto types=describeFunctionTypes(*this,va);for(auto key:{"signature","parameters","locals"})result[key]=types[key];return result;}
Json Engine::searchPattern(const std::string&pattern,size_t offset,size_t limit){require();return searchBytePattern(*binary_,pattern,offset,limit);}
Json Engine::discoverText(size_t minimum,size_t offset,size_t limit,const std::string&q){require();return discoverStrings(*binary_,minimum,offset,limit,q);}
Json Engine::stagePatch(Address va,const std::string&bytes){require();return features_->patches.stage(*binary_,va,bytes);}
Json Engine::listPatches()const{require();return features_->patches.list();}
Json Engine::removePatch(Address va){require();return features_->patches.remove(va);}
Json Engine::exportPatched(const std::filesystem::path&path){require();return features_->patches.exportPatched(*binary_,path);}
Json Engine::workspaceState()const{Json types=Json::array();for(auto&[va,decl]:features_->signatures)types.push_back({{"address",hex(va)},{"declaration",decl}});return {{"annotations",features_->notes.exportState()},{"patches",features_->patches.exportState()},{"signatures",types},{"variable_edits",features_->variableEdits},{"advanced",advancedState_}};}
void Engine::restoreWorkspaceState(const Json&state){require();if(!state.is_object())throw std::runtime_error("Invalid workspace metadata");if(state.contains("advanced")){if(!state["advanced"].is_object())throw std::runtime_error("Invalid advanced metadata");if(state["advanced"].contains("manual"))validateManualState(*binary_,state["advanced"]["manual"]);advancedState_=state["advanced"];}if(state.contains("annotations"))features_->notes.importState(state["annotations"]);if(state.contains("patches"))features_->patches.importState(*binary_,state["patches"]);features_->signatures.clear();features_->variableEdits=Json::array();if(state.contains("signatures")){if(!state["signatures"].is_array())throw std::runtime_error("Invalid signatures");for(auto&entry:state["signatures"])if(!manuallyDeletedFunction(*this,address(entry.at("address"))))setSignature(address(entry.at("address")),entry.at("declaration"));}if(state.contains("variable_edits")){auto edits=state["variable_edits"];if(!edits.is_array()||edits.size()>100000)throw std::runtime_error("Invalid variable edits");for(auto&edit:edits)if(!manuallyDeletedFunction(*this,address(edit.at("address"))))setVariableType(address(edit.at("address")),edit.at("name"),edit.at("declaration"));}}
}
