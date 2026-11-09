#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json autoReferenceTools();
std::optional<Json> callAutoReferenceTool(Engine&,const std::string&,const Json&);
}
