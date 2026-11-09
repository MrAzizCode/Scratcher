#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json debuggerTools();
std::optional<Json> callDebuggerTool(Engine&,const std::string&,const Json&);
}
