#pragma once
#include "core.hpp"
#include <optional>

namespace scratcher {
// Persistent manual metadata lives exclusively under advancedState()["manual"].
// Ranges are nonoverlapping half-open {start,end,kind,data_type} address strings.
// Operands use {address,index,presentation,text}; switches include a verified
// targets array. Deleted function starts are kept in deleted_functions.
Json manualTools();
std::optional<Json> callManualTool(Engine&,const std::string&,const Json&);
std::optional<std::string> manualClassification(const Engine&,Address);
std::vector<Address> manualSwitchTargets(const Engine&,Address);
bool manuallyDeletedFunction(const Engine&,Address);
std::string manualDisplayedOperands(const Engine&,const Instruction&);
void validateManualState(const Binary&,const Json&);
}
