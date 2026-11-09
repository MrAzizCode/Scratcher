#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json recognitionTools();
std::optional<Json> callRecognitionTool(Engine& engine,const std::string& name,const Json& arguments);
}
