#pragma once
#include "core.hpp"
namespace scratcher {
// Declarations use C syntax, for example: int add(int left, int right).
Json setFunctionSignature(Engine& engine, Address va, const std::string& declaration);
Json describeFunctionTypes(Engine& engine, Address va);
// The declaration may include a new variable name, for example: char *buffer.
Json setVariableType(Engine& engine, Address va, const std::string& name,
                     const std::string& declaration);
}
