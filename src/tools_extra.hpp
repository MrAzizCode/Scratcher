#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json extraTools();
std::optional<Json> callExtraTool(Engine& session,const std::string& name,const Json& args);
}
