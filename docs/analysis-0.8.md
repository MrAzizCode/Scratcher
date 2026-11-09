# Scratcher 0.8 analysis validation

The 0.8 development snapshot adds exact stop diagnostics, reduces unnecessary decoding of operands, and lets callers use selected guarded switch tables during bulk reachable-code traversal. All new analysis runs on the CPU. CUDA still serves fingerprint matching only.

## Validation

The CUDA-enabled Release build passed 42 CTest suites and 33 command-line and MCP checks, including actual GPU matching and pseudocode generation. Tests exercised exact stop addresses and retained bytes, branch-path attribution, caps, guarded read-only tables, wrong-width indices, path joins, manual bounds, and uncertainty in recovered references. A controlled two-case table increased unique decoded bytes from 15 to 27 out of a fixed 128-byte scope. The selected analysis retains residual uncertainty and does not claim the entire traversal is closed.

## Original-file results

| Input | Candidate scope | Unique reached bytes | Coverage | Invalid events rejected by the independent decoder |
| --- | ---: | ---: | ---: | ---: |
| Roblox Player 0.742 | 102,242,816 | 3,321,405 | 3.248546% | 206,370 of 206,395 |
| Roblox Player 0.743 | 103,782,912 | 3,383,710 | 3.260373% | 208,499 of 208,532 |

For 0.742, 22,006 invalid events were at seed entries and 184,389 occurred downstream. The exact stop corpus includes repeated addresses reached from different seeds. The small set of decoder disagreements remains diagnostic evidence and was not treated as additional code. Decode failures alone do not establish how the file bytes were produced. Preparing 128 selected candidate functions per input produced no guarded switch targets on either Roblox build and did not change coverage. Neither Roblox run exhausted its analysis budgets.

An attempt to acquire read-only code from an already-running 0.743 process was refused because a page required for identity verification was unavailable. No capture from that process was used. Its build is separate from the 0.742 baseline.

## Timing

Three fresh processes per build and input, with the same five-million-instruction budget and optional stop retention off. Timings measure the code analysis call, exclude process startup, and do not flush the OS file cache. No analyzed binary was executed.

| Workload | 0.7 median / p95 | 0.8 median / p95 | Scope |
| --- | ---: | ---: | --- |
| Original Roblox Player 0.742 | 229.12 / 241.29 ms | 228.90 / 236.63 ms | Same coverage; no budget exhausted |
| Chrome 156 x64 DLL, 306,491,544 bytes | 874.86 / 980.17 ms | 880.07 / 884.16 ms | Both hit instruction cap; small byte differences under the parallel cap |

The medians are essentially unchanged. Three samples do not establish a tail-latency improvement. These are bounded static code measurements, not whole-application or decompilation speed comparisons.

## Reproduce

Run from the source checkout after building. Use an explicitly supplied, local copy of each analyzed binary. Place the exact Roblox 0.742 input under `benchmark-inputs/` to reproduce the original benchmark; the harness verifies the hash.

```powershell
python -m pip install --target .tmp/independent-decode iced-x86==1.21.0
python scripts/diagnose-code-stops.py diagnose --label original-742
python scripts/diagnose-code-stops.py benchmark --baseline D:/path/to/0.7/ScratcherMCP.exe --chrome D:/path/to/chrome.dll --runs 3
```

Raw JSON, JSONL, and timing reports are generated locally in `reports/deep-next/`. The diagnostic decodes once at each exact reported stop address using independently read file-backed bytes; it never resynchronizes past an invalid instruction. The benchmark audits the byte union and keeps the original candidate scope fixed. Local test inputs and raw reports are excluded from this repository.
