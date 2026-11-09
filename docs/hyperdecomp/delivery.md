# Scratcher 0.6 — HyperDecomp working milestone

Built and verified on 2026-10-14T11:00:17.335396+03:00.

## Delivered code

- Real optional CUDA C++ fingerprint top-k search, persistent buffers and CPU fallback.
- Optimized multithreaded CPU matcher and a complete separately built CUDA-disabled application.
- Automatic retained-corpus selection with exact calibration checks and a 10% measured warm-gain requirement.
- Four working MCP acceleration tools, 150 total tools, JSON analysis/export CLI, and desktop Acceleration panel.
- Existing native instruction/IR/pseudocode integration retained; new headless panel and integration checks.
- Pinned optional compiler components, license inventory, source dependency locks/patch, build guide, research and benchmark scripts.

## Measured results

Host: Windows 11 x64, Intel i5-13400F (10 cores/16 threads), RTX 3060 12 GiB, 32 GiB system RAM. Exact top-k=8 over 256-bit fingerprints, 16 CPU workers. Three fresh processes per case, five warm repeats each. All CPU/GPU neighbors and ties agree in every successful CUDA trial. No target execution or Computer Use.

| Corpus | Candidates × queries | CPU warm median ms | CUDA warm median ms | Ratio |
|---|---:|---:|---:|---:|
| Synthetic | 32,768 × 64 | 0.829 | 0.270 | 3.07× |
| Synthetic | 131,072 × 128 | 5.149 | 1.522 | 3.38× |
| Synthetic | 1,000,000 × 128 | 43.514 | 12.976 | 3.35× |
| Self-compiled fixture | 548 × 128 | 0.220 | 0.116 | 1.89× |
| Installed 305 MB DLL | 651,417 × 128 | 24.539 | 8.601 | 2.85× |

These are complete matching-call measurements with final results returned to the CPU, not full binary analysis/decompilation speedups. Cold CUDA setup remains slower than CPU on these workloads. The 1-candidate control is also slower on CUDA even when warm. Auto reports all initialization/calibration costs and selects for subsequent retained-corpus searches.

The 304,965,272-byte DLL was read locally and is not redistributed. Its metadata supplied 694,392 candidate starts; 651,417 prefixes met the extraction criteria and 42,975 were too short. 4,115 reached their prefix instruction cap and 1 stopped at invalid decoding. All candidate rows were processed within the configured index budget; this does not establish valid full function bodies or full code coverage.

One indexing run recorded loading 210.97 ms and CPU prefix extraction 2032.83 ms; these are single observations, not repeated median/p95 values. No file-cache flush was performed. MCP peak working set for that load/index session was 741.31 MiB, sampled through the Windows process peak counter. CUDA algorithm buffers for the comparison were 21.14 MiB, excluding driver/context footprint. Continuous peak VRAM/utilization was not measured.

The initial large-DLL detailed export exceeded the reader's 64 MiB cap. That failure is retained under `performance-chrome-export-limit.*`; compact export retains every fingerprint without relaxing the cap. The corrected dataset is 43,650,085 bytes. Initial slower GPU measurements are retained in `initial/`.

## Verification

- CUDA-enabled build: 40/40 CTest suites; 50 direct accelerator checks using the real GPU.
- CUDA-disabled full application build: 40/40 CTest suites; 32 direct accelerator checks.
- Native CLI/MCP workflows: 33 CUDA checks and 32 CPU-only checks.
- Installed package: 33 CUDA checks; the same CUDA-enabled package also passed 32 checks with a missing compiler path, returning explicit CPU fallback.
- New panel emits headless draw commands for device and fallback states; desktop pixels were not inspected.
- Benchmarks include raw trials, hashes, median, p95 and variance. Fallback is excluded from CUDA results.

## Remaining work

GPU instruction decoding, CSR graph/data-flow kernels, broader compiler-grounded semantic validation, full crash-isolated dependency scheduling, sustained fuzzing, APK and additional GPU backends remain unfinished. This is a working incremental release, not a claim of full IDA/Ghidra/Binary Ninja parity. No full-application speedup has been established. The earlier Roblox 70% recovery target remains unresolved; these fingerprints do not increase its recovered-code coverage.

Research and design: `docs/hyperdecomp/research-core.md`, `research-external.md`, `architecture.md`. Usage/build: `docs/hyperdecomp/usage.md`. Raw results: `reports/hyperdecomp/performance*.json` and corresponding Markdown reports.
