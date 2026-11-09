#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json sdkTools();
Json sdkPluginTools(Engine&);
std::optional<Json> callSdkTool(Engine&,const std::string&,const Json&);
void notifySdkEvent(Engine&,const std::string& event,const Json& payload);
}
