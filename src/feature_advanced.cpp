#include "feature_advanced.hpp"
#include "feature_advanced_analysis.hpp"
#include "feature_advanced_manual.hpp"
#include "feature_advanced_type_library.hpp"
#include "feature_advanced_symbols.hpp"
#include "feature_advanced_recognition.hpp"
#include "feature_advanced_database.hpp"
#include "feature_advanced_pseudocode.hpp"
#include "feature_advanced_debugger.hpp"
#include "feature_advanced_architectures.hpp"
#include "feature_advanced_sdk.hpp"
#include "feature_auto_code.hpp"
#include "feature_auto_exceptions.hpp"
#include "feature_auto_rtti.hpp"
#include "feature_auto_references.hpp"
#include "feature_auto_pipeline.hpp"
#include "feature_auto_imports.hpp"
#include "feature_acceleration.hpp"
namespace scratcher {
Json advancedTools(){Json result=Json::array();for(auto source:{analysisTools(),manualTools(),typeLibraryTools(),symbolsTools(),recognitionTools(),databaseTools(),pseudocodeTools(),debuggerTools(),architecturesTools(),sdkTools(),autoCodeTools(),autoExceptionTools(),autoRttiTools(),autoReferenceTools(),autoPipelineTools(),autoImportTools(),accelerationTools()})for(auto&tool:source)result.push_back(std::move(tool));return result;}
std::optional<Json> callAdvancedTool(Engine&e,const std::string&n,const Json&a){
 if(auto r=callAccelerationTool(e,n,a))return r;
 if(auto r=callAutoPipelineTool(e,n,a))return r;
 if(auto r=callAutoImportTool(e,n,a))return r;
 if(auto r=callAutoCodeTool(e,n,a))return r;
 if(auto r=callAutoExceptionTool(e,n,a))return r;
 if(auto r=callAutoRttiTool(e,n,a))return r;
 if(auto r=callAutoReferenceTool(e,n,a))return r;
 if(auto r=callDatabaseTool(e,n,a))return r;
 if(auto r=callSdkTool(e,n,a))return r;
 if(auto r=callDebuggerTool(e,n,a))return r;
 if(auto r=callArchitecturesTool(e,n,a))return r;
 if(auto r=callPseudocodeTool(e,n,a))return r;
 if(auto r=callAnalysisTool(e,n,a))return r;
 if(auto r=callManualTool(e,n,a))return r;
 if(auto r=callTypeLibraryTool(e,n,a))return r;
 if(auto r=callSymbolsTool(e,n,a))return r;
 if(auto r=callRecognitionTool(e,n,a))return r;
 return std::nullopt;
}
}
