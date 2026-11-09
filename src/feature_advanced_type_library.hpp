#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json typeLibraryTools();
std::optional<Json> callTypeLibraryTool(Engine&, const std::string&, const Json&);
void restoreTypeLibrary(Engine&);
}
