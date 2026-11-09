#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json accelerationTools();
std::optional<Json> callAccelerationTool(Engine&,const std::string&,const Json&);
}
