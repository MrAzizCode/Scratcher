#pragma once
#include "core.hpp"

namespace scratcher {
// Indexes only file-backed executable bytes. The scan is bounded; register
// indirect transfers and unresolved memory expressions are never guessed.
Json collectCrossReferences(Engine& engine, size_t instructionBudget = 100000);
Json referencesAt(const Json& index, Address target, bool outgoing = false);
Json buildCallGraph(const Json& index, const Binary& binary);
}
