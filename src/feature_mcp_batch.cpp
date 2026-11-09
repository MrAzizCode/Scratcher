#include "feature_mcp_batch.hpp"
namespace scratcher {
Json batchToolDefinition(){
 Json operation={{"type","object"},{"properties",{{"tool",{{"type","string"},{"minLength",1},{"maxLength",128}}},{"arguments",{{"type","object"}}}}},{"required",{"tool"}},{"additionalProperties",false}};
 return {{"name","batch_tools"},{"description","Run up to 256 analysis or editing operations in order on the same workspace. Results identify every attempted operation. dry_run validates schemas only; it does not validate file contents or execute edits. The batch is not transactional; earlier successful edits remain if a later operation fails or is cancelled."},{"inputSchema",{{"type","object"},{"properties",{{"operations",{{"type","array"},{"items",operation},{"minItems",1},{"maxItems",256}}},{"stop_on_error",{{"type","boolean"}}},{"dry_run",{{"type","boolean"}}},{"max_output_bytes",{{"type","integer"},{"minimum",1024},{"maximum",4*1024*1024}}}}},{"required",{"operations"}},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",false},{"destructiveHint",false},{"openWorldHint",false}}}};
}
Json executeToolBatch(Engine& engine,Tools& tools,const Json&a){
 const auto&operations=a.at("operations");if(!operations.is_array()||operations.empty()||operations.size()>256)throw std::runtime_error("A batch needs 1 to 256 operations");
 const bool dry=a.value("dry_run",false),stop=a.value("stop_on_error",true);size_t budget=a.value("max_output_bytes",size_t(4*1024*1024));if(budget<1024||budget>4*1024*1024)throw std::runtime_error("Batch output limit must be 1024 to 4194304 bytes");
 Json items=Json::array();size_t used=512,attempted=0;bool failed=false,cancelled=false,truncated=false;
 // Validate the entire plan before the first edit. Every operation remains a
 // normal local tool; control/job tools and recursive batches are disallowed.
 for(auto&op:operations){if(!op.is_object()||!op.contains("tool")||!op["tool"].is_string())throw std::runtime_error("Each operation needs a tool name");const auto name=op["tool"].get<std::string>();if(name=="batch_tools")throw std::runtime_error("Nested batches are not supported");tools.validateLocal(name,op.value("arguments",Json::object()));}
 for(auto&op:operations){if(engine.cancelled()){cancelled=true;break;}if(used+512>budget){truncated=true;break;}auto name=op["tool"].get<std::string>();Json row={{"index",attempted},{"tool",name}};++attempted;
  try{if(dry){row["success"]=true;row["validation"]="schema_only";row["executed"]=false;}else {row["result"]=tools.callLocal(name,op.value("arguments",Json::object()));row["success"]=true;row["executed"]=true;}}
  catch(const std::exception&e){row["success"]=false;row["error"]=e.what();failed=true;}
  size_t bytes=row.dump().size()+1;if(used+bytes>budget){row.erase("result");row["result_omitted"]=true;row["reason"]="output_budget";bytes=row.dump().size()+1;truncated=true;}items.push_back(std::move(row));used+=bytes;if(truncated||(failed&&stop))break;
 }
 return {{"items",items},{"attempted",attempted},{"remaining",operations.size()-attempted},{"next_index",attempted<operations.size()?Json(attempted):Json(nullptr)},{"dry_run",dry},{"failed",failed},{"cancelled",cancelled},{"truncated",truncated},{"transactional",false}};
}
}
