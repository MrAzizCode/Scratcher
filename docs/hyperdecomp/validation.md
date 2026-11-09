# Validation scope

All new automated verification uses native test programs, CLI, or stdio MCP. The analyzed fixture, system binaries, installed application binaries and earlier game images are read without being launched. Existing debugger tests explicitly exercise their own compiled test process; debugger execution is separate from this analysis pipeline.

## Ground truth and exact checks

| Dataset/check | Evidence available | Limits |
|---|---|---|
| `examples/analysis_fixture.cpp` / `ScratcherAnalysisFixture.exe` | Redistributable source and self-compiled PE with named branch/switch/RTTI/EH exports; controlled switch test checks all 26 instructions, ten blocks, six destinations and the guard/default machine edges | One `/Od` MSVC configuration; does not establish broad compiler/optimization coverage or whole-program semantic equivalence |
| Backend scalar oracle and synthetic corpora | Exact 256-bit distances, deterministic tie order, empty inputs, caps, partial tiles, extreme distances and k=1/8/17/32 | Agreement is over fingerprints, not recovered function semantics |
| Feature-generated instruction fixtures | Normalization across rebased immediates, distinct instruction shapes, thread-count determinism, bounds/data edits, invalid stops, stale indices, self exclusion and current names | Prefix descriptors intentionally lose information |
| Runtime CUDA tests | Real device execution when available, exact CPU/GPU agreement, Auto measured-choice/caching invariants | GPU-less runs explicitly report unavailable/fallback; they do not count as CUDA tests |
| CPU-only configuration | Backend compiled with `SCRATCHER_ENABLE_CUDA=OFF`, exact CPU results and explicit forced-CUDA fallback | Separate from simulating runtime DLL absence; both paths need retained evidence |
| CLI/MCP integration | 150 unique schemas; input inspection, real instructions and pseudocode; four acceleration controls; modes; paginated export; input/output bounds and no-overwrite behavior | Native process tests do not verify desktop pixels or all interaction behavior |
| Existing regression suites | Parsers, architecture handling, native pseudocode, analysis paths, graph switches, annotations, projects, references, debugger fixture and UI state | Passing tests do not prove absence of parser/IR defects or complete feature parity |

The benchmark compares every neighbor and distance from every forced CUDA trial against the same optimized CPU implementation. Backend unit tests additionally use a simple independent bit-counting oracle. Auto validates both its initial and warm GPU result during calibration and requires a measured warm gain of at least 10%; it accounts for all calibration work in the first request.

## Reproduce

```powershell
./vendor/tools/cmake-4.4.4-windows-x86_64/bin/ctest.exe --test-dir build -C Release --output-on-failure
./build/Release/accelerator_tests.exe
python ./scripts/verify-hyperdecomp.py --require-cuda
```

For another runtime directory, pass `--directory`; `--input` selects the self-compiled fixture. Use `--expect-cpu-fallback` when testing a package without a usable CUDA backend. The script writes raw evidence and executable/input hashes to a selectable `--output` JSON file. Required CUDA verification fails if a fallback occurs.

## Performance definitions

Fingerprint matching timing begins at the library search call and ends after final top-k results are available on the host. Cold CUDA includes initial context, NVRTC/module setup and corpus upload. Warm retains device corpus/buffers and includes query transfer, kernels, final download and synchronization. Fingerprint extraction and process creation are separate. Repeated fresh-process and warm results report median, nearest-rank p95 and population variance.

Algorithm buffer sizes are measured from owned allocation sizes. Pre/post NVIDIA SMI snapshots are contextual telemetry, not continuous GPU utilization or peak VRAM profiling. MCP working-set peaks are Windows process counters when included. No application-wide speedup is inferred from these searches.

## Required further validation

Remaining work includes a larger labeled C/C++ corpus spanning optimization levels and stripping; PDB/DWARF-grounded function precision/recall; independent CFG/xref checks; compilable pseudocode behavioral tests; sustained parser/decoder/IR fuzzing; crash/timeout recovery under isolated workers; actual GPU fault/OOM stress; continuous RAM/VRAM/utilization profiling; and comparable full-pipeline baselines.

IDA Pro and Binary Ninja results require a verified licensed installation. No such current baseline is asserted. RetDec is researched, not integrated or benchmarked here. Earlier headless comparisons remain historical and scope-limited. The earlier Roblox source has missing/unverified code evidence; fingerprint acceleration does not satisfy its 70% recovery goal or turn partial recovery into full analysis.
