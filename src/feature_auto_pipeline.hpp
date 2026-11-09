#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json autoPipelineTools();
std::optional<Json> callAutoPipelineTool(Engine&,const std::string&,const Json&);
}
