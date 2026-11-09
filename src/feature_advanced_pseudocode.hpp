#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json pseudocodeTools();
std::optional<Json> callPseudocodeTool(Engine&,const std::string&,const Json&);
// Invoke after clearing previous native analysis and before running actions.
void applyPseudocodeOptions(Engine&,Address);
}
