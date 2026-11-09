#pragma once
#include "core.hpp"
namespace scratcher {
Json batchToolDefinition();
Json executeToolBatch(Engine& engine,Tools& tools,const Json& arguments);
}
