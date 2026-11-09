#include "feature_auto_pipeline.hpp"
#include "feature_auto_code.hpp"
#include "feature_auto_rtti.hpp"
#include "feature_auto_exceptions.hpp"
#include "feature_auto_references.hpp"
#include "feature_advanced_sdk.hpp"
#include <chrono>
#include <algorithm>
#include <set>
namespace scratcher {
namespace {
using Clock=std::chrono::steady_clock;
double elapsed(Clock::time_point start){return std::chrono::duration<double,std::milli>(Clock::now()-start).count();}
Json optionsFor(Engine& e,const Json& args,const char* phase,const char* tool,const Json& schema,uint64_t remaining){
 Json opts=args.value("phase_options",Json::object()).value(phase,Json::object());
 const auto& properties=schema.at("inputSchema").at("properties");
 if(std::string(phase)=="code"){
  if(!opts.contains("boundary_policy"))opts["boundary_policy"]="control_flow";
  if(!opts.contains("discovery_rounds"))opts["discovery_rounds"]=32;
  if(!opts.contains("instruction_budget")&&!args.contains("instruction_budget"))opts["instruction_budget"]=100000000;
  if(!opts.contains("byte_budget")&&!args.contains("byte_budget"))opts["byte_budget"]=536870912;
  if(!opts.contains("coverage_span_budget"))opts["coverage_span_budget"]=4000000;
 }
 for(const char* key:{"instruction_budget","byte_budget","data_byte_budget","workers"})if(args.contains(key)&&properties.contains(key)&&!opts.contains(key))opts[key]=args[key];
 if(properties.contains("time_budget_ms")){auto hi=properties["time_budget_ms"].value("maximum",uint64_t(600000));auto requested=opts.value("time_budget_ms",remaining);opts["time_budget_ms"]=std::max<uint64_t>(1,std::min({remaining,requested,hi}));}
 Tools tools(e);tools.validateLocal(tool,opts);return opts;
}
Json schemaFor(const Json& schemas,const char* name){for(const auto& row:schemas)if(row.at("name")==name)return row;throw std::runtime_error("Missing analysis schema");}
}
Json autoPipelineTools(){
 Json phases={{"type","array"},{"minItems",1},{"maxItems",4},{"uniqueItems",true},{"items",{{"type","string"},{"enum",{"code","exceptions","rtti","references"}}}}};
 auto integer=[](uint64_t lo,uint64_t hi){return Json{{"type","integer"},{"minimum",lo},{"maximum",hi}};};
 Json phaseOptions=Json::object();for(const char* phase:{"code","exceptions","rtti","references"})phaseOptions[phase]={{"type","object"},{"maxProperties",24}};
 Json props={{"phases",phases},{"time_budget_ms",integer(1,600000)},{"instruction_budget",integer(1,100000000)},{"byte_budget",integer(8,536870912)},{"data_byte_budget",integer(0,1073741824)},{"workers",integer(1,32)},{"phase_options",{{"type","object"},{"properties",phaseOptions},{"additionalProperties",false}}}};
 Json rows=Json::array();auto add=[&](const char* name,const char* desc,Json p,bool readonly){rows.push_back({{"name",name},{"description",desc},{"inputSchema",{{"type","object"},{"properties",p},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readonly},{"destructiveHint",false},{"openWorldHint",false}}}});};
 add("run_auto_analysis","Run bounded native reachable code, exception metadata, RTTI, and code/data references. Reports per-phase scope, partial recovery and cooperative deadline. Function seeds are not validated bodies; completion does not establish full semantic analysis.",props,false);
 add("get_auto_analysis_report","Read the last configured analysis run and its scope, warnings and per-phase counters.",Json::object(),true);return rows;
}
std::optional<Json> callAutoPipelineTool(Engine& e,const std::string& name,const Json& args){
 if(name=="get_auto_analysis_report")return e.advancedState().value("auto_pipeline",Json{{"status","not_run"},{"semantic_analysis_complete",false}});
 if(name!="run_auto_analysis")return {};
 if(!e.binary())throw std::runtime_error("Open a binary first");
 Tools validator(e);validator.validateLocal(name,args);
 const auto phases=args.value("phases",Json::array({"code","exceptions","rtti","references"}));std::set<std::string> selected;for(const auto& p:phases)selected.insert(p.get<std::string>());
 struct Phase {const char* id;const char* tool;Json schemas;std::optional<Json>(*call)(Engine&,const std::string&,const Json&);};
 const std::vector<Phase> ordered={{"code","analyze_code_paths",autoCodeTools(),callAutoCodeTool},{"exceptions","analyze_exceptions",autoExceptionTools(),callAutoExceptionTool},{"rtti","analyze_rtti",autoRttiTools(),callAutoRttiTool},{"references","analyze_references",autoReferenceTools(),callAutoReferenceTool}};
 // Validate every selected phase before starting any work.
 auto total=args.value("time_budget_ms",uint64_t(60000));for(const auto& phase:ordered)if(selected.contains(phase.id))optionsFor(e,args,phase.id,phase.tool,schemaFor(phase.schemas,phase.tool),total);
 auto start=Clock::now();Json rows=Json::array(),warnings=Json::array();size_t finished=0;bool cancelled=false,deadline=false,failed=false;
 for(const auto& phase:ordered){if(!selected.contains(phase.id))continue;
  if(e.cancelled()){cancelled=true;break;}auto spent=elapsed(start);if(spent>=total){deadline=true;break;}
  auto options=optionsFor(e,args,phase.id,phase.tool,schemaFor(phase.schemas,phase.tool),uint64_t(total-spent));auto began=Clock::now();
  try {auto result=phase.call(e,phase.tool,options);if(!result)throw std::runtime_error("Analysis phase unavailable");
   rows.push_back({{"phase",phase.id},{"tool",phase.tool},{"wall_ms",elapsed(began)},{"options",options},{"result",*result}});++finished;
   bool partial=result->value("truncated",false)||result->value("budget_exhausted",false)||result->value("time_budget_exhausted",false)||result->value("deadline_exceeded",false);
   for(const char* key:{"complete","traversal_complete","code_scan_complete","coverage_complete"})if(result->contains(key)&&!result->at(key).get<bool>())partial=true;
   if(partial)warnings.push_back(std::string(phase.id)+" has incomplete coverage; inspect its limits and stop counters");
  }catch(const std::exception& ex){rows.push_back({{"phase",phase.id},{"tool",phase.tool},{"wall_ms",elapsed(began)},{"error",ex.what()}});warnings.push_back(std::string(phase.id)+" failed");failed=true;if(e.cancelled()){cancelled=true;break;}}
 }
 auto ms=elapsed(start);deadline|=ms>total;
 Json report={{"status",cancelled?"cancelled":deadline?"deadline_reached":failed?"partial_failure":"configured_passes_finished"},{"configured_phases_finished",finished==selected.size()&&!failed},{"semantic_analysis_complete",false},{"full_analysis_parity_established",false},{"function_starts_are_body_evidence",false},{"function_count",e.binary()->functions.size()},{"import_count",e.binary()->imports.size()},{"metadata",e.binary()->peMetadata},{"time_budget_ms",total},{"elapsed_ms",ms},{"cancelled",cancelled},{"deadline_reached",deadline},{"phases",rows},{"warnings",warnings},{"deadline_policy","cooperative; checked in bounded loops; final merge/index and serialization may overrun"},{"detail_cache_persistence","session only; summaries and indexed function starts persist in projects"}};
 e.advancedState()["auto_pipeline"]=report;notifySdkEvent(e,"auto_analysis_completed",{{"status",report["status"]},{"elapsed_ms",ms}});return report;
}
}
