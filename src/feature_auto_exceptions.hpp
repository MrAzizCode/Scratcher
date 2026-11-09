#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json autoExceptionTools();
Json analyzeExceptionMetadata(Engine&,const Json& options=Json::object());
std::vector<Function> exceptionCallableRanges(Engine&);
std::optional<Json> callAutoExceptionTool(Engine&,const std::string&,const Json&);
}
