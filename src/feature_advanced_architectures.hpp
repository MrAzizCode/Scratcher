#pragma once
#include "core.hpp"
#include <functional>
#include <optional>
namespace scratcher {
std::string binaryArchitecture(const Binary&);
bool parseMachOImage(Binary&);
std::vector<Instruction> decodeArchitectureListing(const Binary&,Address,size_t,const std::function<bool()>&);
Json scanArchitectureCalls(const Binary&,size_t,std::vector<Function>&,const std::function<bool()>&,bool);
Json architecturesTools();
std::optional<Json> callArchitecturesTool(Engine&,const std::string&,const Json&);
}
