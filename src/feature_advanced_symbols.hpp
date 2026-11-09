#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json symbolsTools();
std::optional<Json> callSymbolsTool(Engine&,const std::string&,const Json&);
}
