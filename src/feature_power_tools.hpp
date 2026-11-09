#pragma once
#include "core.hpp"
#include <optional>

namespace scratcher {
Json powerTools();
std::optional<Json> callPowerTool(Engine& engine,const std::string& name,const Json& arguments);
}
