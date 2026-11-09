#pragma once
#include "core.hpp"
#include "tool_backend.hpp"
namespace scratcher {
std::unique_ptr<ToolBackend> createAutomationBackend(Engine& engine,Tools& tools,const std::string& desktopId="");
}
