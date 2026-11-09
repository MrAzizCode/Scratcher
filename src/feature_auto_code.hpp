#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
struct CodeAnalysisTransfer {
 Address source=0,target=0;
 bool call=false;
 std::string provenance;
 std::optional<Address> readonlySlot;
 // Straight-line register facts prove a candidate path, not dominance across
 // unknown or later-discovered incoming routes. Such transfers remain unknown
 // globally and never close the whole function traversal.
 bool pathLocal=false,residualUnknown=false;
};
Json autoCodeTools();
std::optional<Json> callAutoCodeTool(Engine&,const std::string&,const Json&);
// Fresh union of decoded reachable instruction candidates, not proof that all
// code was recovered. Missing and stale caches both return nullopt.
// analyze_code_paths optionally accepts scan_ranges (exclusive hexadecimal
// start/end pairs). Their normalized intersection with original candidate scope
// limits readable evidence; an empty list decodes nothing. Original candidate
// bytes remain the coverage denominator, and ranges never create entry seeds.
// Discovery supports 1..32 rounds (direct-tool default 3). A round cap with
// pending decoded call targets reports discovery_round_budget_exhausted;
// completing the last allowed round without pending targets is not exhaustion.
std::optional<std::vector<std::pair<Address,Address>>> codeAnalysisRanges(Engine&);
// Fresh bounded retained indirect-transfer evidence. A missing/stale cache
// returns nullptr; inspect transfer_evidence_complete in the analysis summary
// before treating an empty vector as absence of candidates.
std::shared_ptr<const std::vector<CodeAnalysisTransfer>> codeAnalysisTransfers(Engine&);
std::optional<uint64_t> codeAnalysisTransferFingerprint(Engine&);
}
