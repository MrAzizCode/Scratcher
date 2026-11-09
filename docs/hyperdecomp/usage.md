# Scratcher build and compute guide

This release adds real CUDA-assisted function fingerprint search to Scratcher. Binary parsing, instruction decoding, control-flow recovery and pseudocode generation run on the CPU. Fingerprint similarity is an approximate navigation aid; equal fingerprints do not prove equal function behavior. The milestone does not establish full-application speed superiority or complete analysis parity.

For a portable installation, extract `Scratcher-v0.7.zip` into a new directory and run `Scratcher.exe`. Keep its `data/` and optional `cuda/` directories beside the executable. The package contains CLI/MCP programs, sample source/binary, licenses, reports and a SHA-256 file manifest. No analyzed third-party EXE or DLL is included.

## Build on Windows x64

Requirements: Visual Studio 2022 C++ build tools, a Windows SDK, CMake 3.24 or later, Git and Python 3.11+. CUDA execution additionally needs a supported NVIDIA GPU and installed NVIDIA display driver. A system CUDA toolkit or `nvcc` is unnecessary: the optional backend compiles its embedded CUDA C++ kernels with the pinned runtime compiler.

From your checkout:

```powershell
python scripts/setup-dependencies.py

# Validate/install pinned local CUDA components, configure, build and test.
./scripts/setup-hyperdecomp.ps1 -Build -Test

# Separate build with no CUDA code, headers or runtime compiler dependency.
./scripts/setup-hyperdecomp.ps1 -CpuOnly -Build -Test

# Install a release to a new package directory.
cmake --install build --config Release --prefix ./dist-v0.8
```

The setup scripts keep downloads, caches and temporary files under the repository. The base setup fetches missing dependencies under `vendor/`, applies the pinned native patch, and checks revisions or recorded hashes. Existing directories are checked and preserved. CUDA components are checked against `scripts/hyperdecomp-cuda-lock.json`; pass `-Python C:/path/to/python.exe` if Python is not on PATH. The scripts do not install a display driver or change system PATH.

To reconstruct the base dependencies, check out the recorded commits from their official repositories into `vendor/ghidra`, `vendor/imgui`, `vendor/zlib`, and `vendor/zydis`; initialize Zydis's pinned Zycore submodule. Apply `scripts/patches/ghidra-native.patch` from the dependency root. Obtain Capstone tag `5.0.6` at `vendor/capstone`, nlohmann JSON tag `v3.12.0`'s `single_include/nlohmann/json.hpp` and `LICENSE.MIT` at `vendor/json`, and the hash-locked official Lua `5.5.1` archive at `vendor/lua`. Preserve Lua's MIT notice as `LICENSE.txt`. The supplied `data/` processor specifications must also be retained. Verify hashes against the lock before building. These are reproducible manual prerequisites; a fully automated clean-machine source bootstrap has not been validated in this milestone.

Build outputs are `build/Release/` or `build-cpu/Release/`. Keep `data/` beside the programs. The CUDA-enabled package keeps both NVRTC DLLs together under its absolute `cuda/` directory. An explicit absolute `SCRATCHER_CUDA_PATH` can select another trusted directory containing the same two compiler DLLs. The current directory is not a compiler DLL search path. Without a usable accelerator the same application returns CPU results with an explicit reason.

## Command-line analysis

```powershell
$cli = 'D:/Scratcher/build/Release/HyperDecompCLI.exe'
& $cli --gpu-info
& $cli --inspect D:/sample.exe
& $cli --disassemble D:/sample.exe --count 256
& $cli --analyze D:/sample.exe --time-budget-ms 60000
& $cli --decompile D:/sample.exe --address 0x140001000
& $cli --similarity D:/sample.exe --address 0x140001000 --mode cuda --top-k 8
& $cli --export-fingerprints D:/sample.exe --max-functions 10000 --output D:/new-fingerprints.json
```

Commands emit JSON; choose a real address from that binary's function index. `--output` accepts a new absolute file path. Instruction listing reports its scope separately from reachable recovery. Inputs are mapped and analyzed without execution. The similarity CLI builds a bounded index for each invocation; desktop/MCP sessions retain it across searches. A short or invalid prefix can be excluded, so an arbitrary address may have no fingerprint.

## Desktop and MCP

Open `Scratcher.exe`, load a binary, and choose **Acceleration** from View. Refresh the hardware status, build the function index, select a function, then find similar functions. Choose CPU, CUDA, or Auto for fingerprint comparison. Double-click a result to navigate. The panel reports actual execution mode, fallbacks, index limits, timings and algorithm buffer usage. Results arrive through the existing background queue.

Configure stdio MCP with `ScratcherMCP.exe --mcp`. Four tools expose the same implementation:

| Tool | Purpose |
|---|---|
| `get_acceleration_info` | Actual device availability, index state and latest result |
| `build_function_similarity_index` | Bounded normalized instruction-prefix extraction, with skipped/truncated counts |
| `get_function_similarity_index` | Paginated fingerprints and source evidence |
| `find_similar_functions` | Exact CPU/CUDA top-k distances over the approximate fingerprints |

```json
{"name":"find_similar_functions","arguments":{"addresses":["0x140001000"],"top_k":8,"mode":"cuda","exclude_self":true}}
```

Use `tools/list` for current schemas. Load the binary and build an index first. Function boundary edits invalidate it; rebuild before searching. Renames resolve from current names. Detailed fingerprints and GPU memory are session-local. Project persistence retains the existing supported analysis state and a summary, not the full similarity index.

Auto selects for repeated searches against a retained corpus. Its first request measures cold GPU setup, optimized CPU and a second warm CUDA search, requiring exact result agreement and a warm gain of at least 10% before selecting CUDA. Calibration and total request timings include all this work; the first request can be much slower than CPU alone. Subsequent batches with the same shape reuse that decision. Explicit CUDA requests still report CPU fallback when the device fails. Automatic recalibration under changing hardware load remains future work.

## Reproduce the comparison

```powershell
python ./scripts/benchmark-hyperdecomp.py --help
python ./scripts/benchmark-hyperdecomp.py --exe D:/Scratcher/build/Release/HyperDecompBench.exe --mcp D:/Scratcher/build/Release/ScratcherMCP.exe --export-input D:/Scratcher/build/Release/ScratcherAnalysisFixture.exe --workers 16 --processes 3 --warm-repeats 5 --output D:/Scratcher/reports/hyperdecomp/performance.json
```

The fixture is compiled from the included `examples/analysis_fixture.cpp` and is read without being launched. Synthetic corpora test controlled large comparison workloads; they are not a claim about full-binary decompilation. Each forced CUDA result is compared with the CPU neighbor list, including deterministic tie order. Reports separate fresh-process setup from warm resident-data searches. Process creation, corpus generation and fingerprint extraction are outside per-search timing and are labeled separately. Operating-system and driver caches are not flushed.

Use a quiet machine, repeat trials, retain raw JSON, and compare the same worker count and corpus. NVIDIA SMI snapshots identify the device and report sampled state; they are not continuous peak utilization or peak VRAM measurement. Algorithm buffer sizes do not include the entire driver context. See the measured report under `reports/hyperdecomp/`; initial measurements are retained in `reports/hyperdecomp/initial/`.

## Current limits and next gates

The complete design and working-versus-planned boundaries are in [architecture.md](architecture.md). This release has functional native pseudocode integration and a real GPU workload. GPU decoding, GPU CFG/data-flow, fully concurrent dependency scheduling, automatic crash-isolated stage recovery, APK workflows and broad semantic equivalence validation remain unfinished. Existing parser checks and regression tests do not constitute a sustained fuzz campaign. None of the new fingerprint statistics increase recovered-code coverage on the earlier Roblox input.
