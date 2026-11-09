#pragma once
#include "core.hpp"

namespace scratcher {
// Recover reachable basic blocks from a function address. Calls are recorded,
// while only intra-function branch destinations are traversed. Indirect jumps
// reuse validated native recovered switch tables; unresolved tables trigger
// bounded analysis of this function alone, capped at 4096 native instructions
// and table entries even when the graph traversal budget is larger.
// Recovered tables never become manual overrides or imply semantic equivalence.
Json buildControlFlowGraph(Engine& session, Address entry, size_t instructionBudget=4096);
}
