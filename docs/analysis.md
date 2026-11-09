# Scratcher native analysis controls

Open a file, then call `run_auto_analysis`. The desktop Analyze button uses the same pipeline. Default configured work includes reachable x86/x64 code paths, AMD64 PE unwind metadata, MSVC x64 RTTI and code/data references. Other formats retain existing manual, decode and pseudocode tools; unsupported automatic phases report their limits.

```json
{"time_budget_ms":60000,"workers":8,"phases":["code","exceptions","rtti","references"]}
```

The global deadline is cooperative. Inner loops check time and cancellation; merges, native graph actions and serialization may overrun. Per-phase options belong in `phase_options`, under `code`, `exceptions`, `rtti`, or `references`. Every selected phase's options are validated before work starts. Inspect `tools/list` for current numeric bounds.

| Evidence | Run | Inspect |
| --- | --- | --- |
| Reachable instruction candidates | `analyze_code_paths` | `get_code_analysis`, functions or coverage pages |
| Validated class metadata and hierarchy | `analyze_rtti` | `get_rtti`, with name filtering and output size cap |
| Runtime function bounds, unwind operations and handlers | `analyze_exceptions` | `get_exception_info`, optionally containing an address |
| Indexed operand, pointer and relocation references | `analyze_references` | `get_analysis_references`, incoming/outgoing address pages |
| Imported names and known API prototypes | Installed when pseudocode is first requested | `get_import_semantics` |
| Configured run scope and counters | `run_auto_analysis` | `get_auto_analysis_report` |

PE metadata import validates file-backed addresses and Guard CF entry strides, suppression flags, delay imports and guard helper pointers. Original memory permissions are preserved. Valid metadata can establish candidate code regions even when the section lacks an execute flag. Function starts remain separate from recovered ends.

Reachable paths stop at invalid bytes, unresolved indirect branches, proven exclusive ends or explicit limits. The automatic pipeline uses `boundary_policy: "control_flow"`, following actual direct branches and sequential flow across heuristic metadata starts. It also follows concrete read-only pointer transfers and validated manual switch targets. Mutable/import pointer slots remain unresolved. The direct `analyze_code_paths` tool retains the conservative `next_seed` default; either policy can be supplied under the pipeline's `phase_options.code`.

Automatic analysis allows up to 32 discovery rounds while retaining its time, instruction, byte and storage limits. The direct code tool defaults to three rounds and accepts `discovery_rounds` from 1 through 32. A round can discover new direct-call entries for the next round. If the round limit leaves pending entries, `discovery_round_budget_exhausted` and `budget_exhausted` are true; this is incomplete recovery even when other budgets were sufficient. `pending_discovered_seeds` gives the outstanding entry count.

`candidate_code_bytes` is the unchanged union of original executable and metadata candidate regions clipped to file-backed bytes. `coverage_percent` divides the unique decoded span union by that scope; it does not estimate the percentage of all true program code. Function ownership and full semantics remain unproven. A closed traversal also does not prove behavioral correctness. Explicit manual data boundaries take precedence.

Enable exact diagnostics with `stop_limit` (default `0`, maximum `1000000`), then read `get_code_analysis` with `view: "stops"`. Each retained event identifies its seed, exact address, path start, instruction count before the event, reason, and bytes supplied to the decoder when applicable. Duplicate sites across seeds are retained. Reaching the storage limit creates a schedule-dependent subset and does not stop decoding. Use `stop_evidence_complete` to distinguish a complete record of observed events from truncated retention.

For selected guarded switch analysis, pass `switch_functions` with up to 256 indexed entry addresses and `boundary_policy: "control_flow"`. Each entry is analyzed within `switch_instruction_budget` and `switch_time_budget_ms`; `switch_transfer_limit` caps prepared targets and withholds incomplete case lists. The bulk pass uses a guarded table only for its corresponding entry. Targets retain `bounded_read_only_table` provenance and unresolved incoming paths, including when indexed as references. This option is unavailable with `scan_ranges` because the current preparation pass cannot enforce capture allowlists on all table dependencies. See [0.8 validation](analysis-0.8.md).

For partially captured code images, `scan_ranges` accepts up to 4096 `{ "start": "0x...", "end": "0x..." }` intervals with exclusive ends. The analyzer clips and merges them, restricts seeds, branches, decoding and concrete pointer reads to those bytes, and keeps the original `candidate_code_bytes` denominator. Missing capture gaps cannot contribute coverage. An explicit empty array supplies no readable evidence. `scan_scope_bytes`, `unexamined_candidate_scope_bytes` and `scan_scope_uncovered_bytes` distinguish captured availability from decoded coverage. This option restricts analysis; it does not import a snapshot or prove its identity.

The command-line snapshot workflow uses `scripts/capture-module-code.py` with an explicit existing process ID, matching original PE and a new output directory. It reads accessible code pages from that loaded module, verifies the original file and loaded build metadata, and records inaccessible pages as missing. It does not start or suspend the process, attach a debugger, inject code or change memory protection.

```powershell
python scripts/capture-module-code.py --pid 12345 --original-pe D:/Scratcher/benchmark-inputs/RobloxPlayerBeta-0.742.exe --module RobloxPlayerBeta.exe --output D:/Scratcher/captures/roblox-742-new
python scripts/replay-module-capture.py --manifest D:/Scratcher/captures/roblox-742-new/manifest.json --original-pe D:/Scratcher/benchmark-inputs/RobloxPlayerBeta-0.742.exe --output D:/Scratcher/reports/coverage-70/roblox-742-new.analysis.bin
```

Replace the example process ID with the existing matching process. Output paths must be new and under `D:/Scratcher`. The offline importer checks payload hashes, original/build identity, range bounds, nonoverlap and exact captured/missing accounting before creating an analysis copy. Only documented, physically captured DIR64 pointers into the same module are normalized to the original image base. The original file is preserved. Its candidate scope is independently checked through the original PE and MCP loader; only captured code can contribute decoded bytes.

Capture availability and decoded coverage are reported separately. The snapshot is unsuspended and non-atomic. An unsigned manifest and payload hashes provide integrity checks and recorded acquisition evidence; they cannot authenticate the acquisition or establish semantic correctness. Code-only acquisition excludes private heap and stack bytes.

Reference `code_policy` can be `auto`, `reachable` or `linear`. Auto uses fresh reachable coverage when present; otherwise it scans candidate code regions linearly. Reachable requires fresh coverage. Scope completion leaves other candidate bytes unexamined. Aligned data pointers are lower-confidence candidates; relocation storage and decoded operands retain distinct provenance. Native indices and scan buffers have a configurable memory allowance separate from process memory and other caches.

RTTI groups use TypeDescriptor identity, with separate counts for names, complete object locators, vftables and base descriptors. Names can repeat. Object fields, sizes and complete virtual method bodies are unknown. Unwind parsing retains handler locations; language-specific C++ exception tables remain unsupported. Import signatures are a small exact module/name library; unknown prototypes remain unknown.

Graph requests can use validated switch targets recovered for the selected function. Recovery is bounded and lazy; it does not decompile every indexed function. Manual switches take precedence. Incomplete target tables remain unresolved.

Detailed native code/RTTI/reference/unwind indices are session-local. Project version 3 retains compact summaries, indexed functions and the existing bounded instruction/graph/pseudocode caches. Reopening verifies the original input hash. Rerun a phase to inspect detailed evidence after reopening.

`configured_phases_finished` means the requested calls finished. Inspect each phase's coverage, budget and error fields. `semantic_analysis_complete` and `full_analysis_parity_established` remain false. Recovered pseudocode reports obvious text warning signals; it is not a behavioral or type-accuracy test.
