#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
Json databaseTools();
std::optional<Json> callDatabaseTool(Engine&,const std::string&,const Json&);
class EditHistoryGuard {
 Engine& engine_;std::string operation_;Json before_;std::vector<Function> functions_;std::vector<Section> sections_;int exceptions_=0;bool active_=false;
public:
 EditHistoryGuard(Engine&,const std::string&);
 ~EditHistoryGuard();
};
}
