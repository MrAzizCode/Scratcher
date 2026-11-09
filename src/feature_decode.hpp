#pragma once
#include "core.hpp"
#include <functional>
namespace scratcher {
std::vector<Instruction> decodeListing(const Binary&, Address, size_t, const std::function<bool()>&);
Json scanDirectCalls(const Binary&, size_t, std::vector<Function>&, const std::function<bool()>&, bool fullScan=false);
}
