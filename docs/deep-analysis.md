# Scratcher 0.7: deeper static analysis

This increment improves reachable x86/x64 code recovery, selected-function CFGs and cross-references. It also repairs unsafe width assumptions in bounded switch-table analysis. The GPU fingerprint matcher is unchanged; these new analysis passes run on the CPU.

## Register-derived control transfers

The shared straight-line tracker recognizes width-correct register constants from MOV, LEA, copies, ADD/SUB and XOR-self. It reads immutable file pointers only through a caller that checks full file backing, read-only storage, import-slot overlap and any applicable captured-range restriction. Unsupported explicit, implicit, conditional or partial register writes invalidate facts. Calls discard them.

Examples now recovered as candidate paths include `lea rax,[rip+target]; jmp rax`, `mov rax,target; call rax`, and a validated read-only pointer load followed by a register jump. No invalid-byte skipping or arbitrary offset scanning is used.

Facts reset at trace entries, conditional splits, known branch destinations and indexed starts. A later-discovered incoming edge may bypass a definition. Register-derived transfers therefore always retain `path_local: true` and `residual_unknown: true`; following their candidate destinations does not prove that all incoming paths resolve to those destinations. They continue to contribute to unresolved-edge accounting. Fixed RIP/absolute read-only pointer transfers have separate provenance.

Decoded coverage remains the unique instruction-candidate byte union over the original file-backed candidate scope. New paths never shrink that denominator or establish function ownership. Explicit function ends, manual data, deleted function seeds and capture holes remain enforced by bulk recovery.

## Bounded evidence and references

```json
{"name":"analyze_code_paths","arguments":{"boundary_policy":"control_flow","workers":8,"discovery_rounds":32,"transfer_limit":262144}}
{"name":"get_code_analysis","arguments":{"view":"transfers","offset":0,"limit":500}}
{"name":"analyze_references","arguments":{"code_policy":"reachable","include_recovered_transfers":true}}
```

The evidence limit accepts 1–1,000,000 rows and defaults to 262,144. Reaching it makes transfer pages a lower bound while decoding continues. `transfer_evidence_complete` describes storage completeness, not semantic resolution. Detailed rows and coverage are session-local. Projects retain supported summaries and function starts; rerun analysis after reopening for detailed evidence.

Reference analysis imports retained targets only at source instructions it successfully decodes within its own byte/instruction/time limits. Rows use `recovered_indirect_call` or `recovered_indirect_jump`, preserving path-local uncertainty and optional read-only source slots. Set `include_recovered_transfers: false` for operands alone. Linear policy never imports these path-dependent results. An incomplete retained evidence dependency prevents the combined reference report from claiming scope completion.

Shared evidence snapshots avoid copying the transfer corpus into each query. A canonical evidence fingerprint invalidates reference caches when transfer evidence changes, even if covered bytes remain identical. Reference index and scan buffers retain their separate memory budget; other retained analysis caches are outside that budget.

Selected-function graphs use the same tracker on original instruction bytes. Manual switches take precedence. Inferred targets have explicit provenance and residual-unknown flags; bounded native switch recovery remains available for other unresolved jumps. Graph pointer reads have their own bounded allowance.

## Correctness repairs

A comparison of EAX does not generally bound a 64-bit RAX table index. For example, after `mov rax,0x100000001`, `cmp eax,1` succeeds for the low word while `[table+rax*8]` addresses far beyond a two-entry table. Analysis now tracks bound widths and requires a sufficiently wide bound or a proven upper-zero fact on every incoming path. Partial/implicit writes, conditional writes, calls and incompatible joins invalidate those proofs. Register constant reads use the actual operand width.

Switch validation requires the whole nonwrapping table inside one read-only, file-backed section and excludes runtime import slots. A table that begins in read-only storage and continues into writable storage is rejected. x86 analysis rejects other instruction sets before decoding, and validated metadata code candidates retain their original memory flags and contiguous readable bounds. Cache identity includes relevant architecture, candidate regions and import-slot provenance.

## Validation and limits

Regression tests cover register copies, RIP-relative materialization, clobbers, implicit writes, calls, diamond bypasses, backward joins, mutable/import pointers, manual boundaries, capture holes, evidence caps and cache freshness. The redistributable `examples/deep_analysis_fixture.cpp` is built with `/Od` and `/O2`; it contains compiler-generated control flow and clearly labeled hand-authored byte arrays. The arrays are decoded as data-driven tests and never executed.

`scripts/benchmark-deep-analysis.py` compares the preserved 0.6 application with the new build, records actual settings and file hashes, independently audits byte unions, checks embedded encodings with a second decoder when available, and reports repeated timings, variance, p95 and memory. Optional heavy passes disclose exhausted budgets and missing scope.

The 0.7 validation ran 24 fresh MCP processes: three trials for each version on two fixture builds and two large local binaries. The embedded register-call/jump arrays recovered 55 unique bytes versus 43 previously. The whole fixture gain was exactly those 12 bytes; no additional compiler-generated recovery was demonstrated. Original Roblox coverage stayed at 3,321,405 / 102,242,816 candidate bytes (3.248546%) and its median code time increased from 204.14 to 234.62 ms. Chrome exhausted the shared five-million-instruction budget and showed no demonstrated recovery improvement. See [the comparison](../reports/deep-analysis/comparison.md) and [delivery evidence](../reports/deep-analysis/delivery.md).

### Reproduce from the source checkout

Keep the preserved `dist-v0.6` installation. Configure/build the current application using [the build guide](hyperdecomp/usage.md); the default build also creates the two redistributable fixture executables. Python 3.11+ is required for the harness.

```powershell
# Run from D:/Scratcher. Use the local bundled Python if python is not on PATH.
python -m pip install --target .tmp/independent-decode iced-x86==1.21.0
python scripts/benchmark-deep-analysis.py --runs 3
# Optional: repeat --heavy for legally available local PE inputs.
python scripts/benchmark-deep-analysis.py --runs 3 --heavy 'C:/path/to/large.dll' --heavy 'D:/path/to/application.exe'
```

The harness writes `reports/deep-analysis/comparison.json` and `.md`; preserve an earlier report before rerunning. For the published 24-process matrix both heavy inputs were supplied. The raw report identifies exact input/build/source hashes, every accepted setting, budget exhaustion, median/p95/variance, sampled process memory and interval audits. Startup is excluded from code-call latency; no OS file-cache flush is performed. The 93 MB raw report contains retained evidence, not executable target data. The two external binaries are not redistributed.

```powershell
./vendor/tools/cmake-4.4.4-windows-x86_64/bin/ctest.exe --test-dir build -C Release --output-on-failure
./vendor/tools/cmake-4.4.4-windows-x86_64/bin/ctest.exe --test-dir build-cpu -C Release --output-on-failure
python scripts/verify-hyperdecomp.py --require-cuda --output reports/deep-analysis/integration-cuda.json
python scripts/verify-hyperdecomp.py --directory build-cpu/Release --expect-cpu-fallback --output reports/deep-analysis/integration-cpu.json
```

The distinct CPU-only build must first be configured with `SCRATCHER_ENABLE_CUDA=OFF` as documented in the build guide. CPU/GPU verification checks functional pseudocode and exact fingerprint-neighbor parity; it does not establish whole-program pseudocode equivalence.

This work does not supply missing readable bytes for the earlier Roblox target, prove complete decompilation or establish broad semantic equivalence. A fully converged interprocedural data-flow solver and GPU CFG/data-flow implementation remain further work.
