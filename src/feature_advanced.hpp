#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json advancedTools();
std::optional<Json> callAdvancedTool(Engine&,const std::string&,const Json&);
}
