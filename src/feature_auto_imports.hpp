#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
// Called after architecture initialization. Does not call Engine::nativeArchitecture().
void installImportSemantics(Engine&, ghidra::Architecture*);
Json autoImportTools();
std::optional<Json> callAutoImportTool(Engine&, const std::string&, const Json&);
}
