#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json autoRttiTools();
std::optional<Json> callAutoRttiTool(Engine& engine,const std::string& name,const Json& arguments);
}
