#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
struct BoundedSwitchTransfer {
 Address source=0,target=0;
 std::string provenance="bounded_read_only_table";
};
struct BoundedSwitchSnapshot {
 std::vector<BoundedSwitchTransfer> transfers;
 size_t requestedFunctions=0,processedFunctions=0,instructionsExamined=0,skippedFunctions=0;
 bool selectedFunctionsComplete=true,storageComplete=true,dataflowComplete=true,residualUnknown=false,limitReached=false;
 Json metadata=Json::object();
};
// Owner-thread preparation only: reachable analysis mutates Engine caches.
// The returned sorted, deduplicated value snapshot can then be read by workers.
// Explicit selected starts only (<=256); no automatic metadata-seed sweep.
// Unsupported for capture/scan_ranges-restricted bulk analysis: the caller must
// skip or reject preparation there until full read-dependency allowlists exist.
// Only converged bounded read-only dispatch tables are exported, independent of
// the paginated JSON edge limit. Incomplete selection/storage remains a lower
// bound and never establishes whole-function or semantic completion.
BoundedSwitchSnapshot prepareBoundedSwitchSnapshot(Engine&,const std::vector<Address>& entries,
 size_t perFunctionInstructionBudget=4096,size_t perFunctionTimeBudgetMs=100,size_t transferLimit=4096);
Json analysisTools();
std::optional<Json> callAnalysisTool(Engine&, const std::string&, const Json&);
}
