# HyperDecomp architecture — Scratcher 0.6 milestone

HyperDecomp is the hybrid-analysis development track inside Scratcher. The product remains Scratcher. This milestone adds working CUDA-assisted function-fingerprint comparison to the existing native C++ application; it does not claim GPU decompilation or complete parity with another application.

## First implementation milestone

Load and inspect an immutable input, export real x64 instructions and CPU pseudocode, build bounded function-prefix fingerprints, compare them through optimized CPU or actual CUDA execution, and inspect results in the desktop or MCP. Validate exact CPU/GPU neighbor order and measure cold setup, transfers, kernel time and complete search latency separately.

The fingerprint workload is regular, batched integer computation. Recursive decoding, uncertain control flow and function-specific decompilation remain on the CPU. No GPU instruction-boundary classifier is presented as recovered code.

## Components and ownership

| Stage | Current implementation | Execution and evidence |
|---|---|---|
| Format parsing and architecture detection | Existing bounds-checked native parser, immutable file mapping | CPU; PE first, existing additional format support retains its limitations |
| Candidate executable regions | Original section permissions plus validated PE metadata | CPU; declared code, metadata starts and recovered bodies remain distinct |
| Instruction decoding | Zydis x86/x64; existing Capstone paths for other architectures | CPU; invalid encodings stop reachable recovery |
| Functions and basic blocks | Existing bounded code paths, metadata, direct flow and selected-function graphs | CPU; original scope, gaps and unresolved edges are reported |
| IR and pseudocode | Existing native SLEIGH/p-code and decompiler integration | CPU; real lifting, native SSA/optimization and structuring, with incomplete recovery explicitly reported |
| Types, references, strings and symbols | Existing analysis and editing tools | CPU; metadata/type recovery does not establish full semantic equivalence |
| Fingerprint extraction | `feature_acceleration.cpp` | Parallel read-only CPU extraction of normalized instruction-prefix SimHash256 |
| Fingerprint top-k comparison | `accel/matcher.cpp` | Persistent CPU worker pool or two real CUDA kernels; exact 256-bit Hamming distances |
| Scheduling | Existing asynchronous workspace/job queue; extraction workers; matcher worker pool and CUDA stream | UI remains separate from analysis work; mutable decompiler state is serialized |
| Persistence | Existing projects/database tools and saved summaries | Detailed similarity index and GPU allocations are session-local and rebuilt after reopen |
| Interaction | Desktop Acceleration tab, four MCP controls, `HyperDecompCLI` | Same core implementation and provenance in each interface |

The application currently uses its existing parser. Integrating and independently cross-checking an additional established parser such as LLVM Object or a separately reviewed PE library remains work; this milestone does not claim that replacement has happened.

## Similarity representation

A fingerprint describes a bounded, metadata/index-anchored instruction prefix. The default extraction allowance is 64 instructions per candidate; callers can request 4–256. Bounds include immutable file availability, indexed ends/neighboring starts, original candidate regions and manual data classifications. Invalid encodings are not skipped. Prefixes shorter than four valid instructions are excluded.

Normalized mnemonic/operand-shape features and adjacent feature tokens feed a deterministic 256-bit SimHash. Immediate values and address displacements are omitted to reduce relocation sensitivity. This intentionally loses information. Fingerprint collisions, short-prefix ambiguity, unverified function starts and differing function bodies remain possible. Hamming similarity is a navigation heuristic, never a proof of semantic equivalence or a code-coverage counter.

CPU and GPU compare precisely the same fingerprints. Ties use the lower candidate index, giving deterministic complete top-k order. The public MCP interface accepts up to 16 matches and 128 query addresses. The internal matcher accepts k up to 32, at most one million candidates, 1,024 queries and 128 Mi pair comparisons. Per-call validation precedes device allocation.

## CUDA implementation

The initial backend uses the NVIDIA Driver API and pinned NVRTC 12.4.127, loaded dynamically. The system `nvcuda.dll` is loaded only from System32. Compiler and matching builtins DLLs are loaded from the executable's absolute `cuda` directory, or an explicitly configured absolute `SCRATCHER_CUDA_PATH`. No current-directory DLL lookup or global PATH changes are required.

The application-owned CUDA C++ kernels are embedded source compiled to PTX. The first kernel computes distances and tile-local top-k lists; the second merges tile results on the device. Only final top-k results return to the CPU. An immutable device corpus, reusable buffers, pinned staging memory and one CUDA stream avoid a full distance-matrix download. A default 256 MiB algorithm-buffer cap is checked before allocation. Reported device bytes cover these allocations, not the driver's entire context footprint.

CPU matching uses packed 256-bit fingerprints, hardware population counts, contiguous candidate partitions, bounded top-k insertion and a persistent worker pool. It is the performance baseline, separate from the scalar bit-by-bit correctness oracle used in tests.

`cpu` never requires GPU setup. `cuda` attempts real device execution and reports any CPU fallback explicitly. `auto` selects for repeated searches against a retained corpus. The first request records the initial GPU setup/upload, measures optimized CPU and a second warm CUDA search, and validates both GPU neighbor lists against CPU. CUDA needs a measured warm gain of at least 10%; otherwise CPU is selected. The measured choice and baselines are cached by query count and effective k. Initial compilation/setup, both GPU passes, CPU computation and comparisons are included in calibration and total request time. The first Auto request can be much slower than CPU alone; no break-even or one-shot speedup is claimed. Adaptive recalibration and hardware-load changes remain optimization work.

Any compiler, driver, allocation or kernel error resets accelerator state and returns CPU results with a reason. Calibration disagreement also disables that accelerator state. CPU fallback is never counted as successful CUDA execution in benchmarks.

## Reliability boundaries

- Analyzed inputs are never launched or granted network access by this pipeline.
- CPU extraction checks cancellation and deadlines; instruction, candidate and output sizes are bounded.
- The matcher bounds each submitted GPU workload. GPU calls are not preempted by the application's cooperative cancellation token; kernel preemption/timeouts rely on the driver and OS.
- UI requests use the existing background queue; independent selected-function native decompilations still share serialized mutable state.
- The CLI/MCP can run in a separate process. Full automatic stage-by-stage crash isolation, restartable DAG scheduling and transactional per-stage checkpoints are not yet implemented.
- Existing parser/decoder tests plus new GPU bounds/fallback tests are not a substitute for a sustained sanitizer/fuzz campaign. Broader fuzzing and IR transformation fuzzing remain required.

## Incremental roadmap and release gates

| Phase | Working capability available | Remaining gate |
|---|---|---|
| Research/prototype | Source reports, CPU CLI disassembly/export and existing application | Broader independent parser validation and labeled corpus |
| GPU | Exact batched similarity kernels, CPU-only build option, measured benchmark harness | Additional winning workloads; no full-application speedup claim yet |
| Program analysis | Existing CFG/references/data-flow, bounded background work and caches | Dependency-aware concurrent stage scheduler, CSR graph kernels, full persistent detail indices |
| Decompilation | Functional native IR/pseudocode integration and editing | Broader type/argument/switch/EH recovery and behavioral validation |
| Desktop | Existing synchronized views plus compute mode/status/similarity navigation | Wider usability/performance validation under sustained background workloads |
| Optimization | Reproducible CPU/GPU microbenchmarks and explicit fallback | Profiles, larger labeled binaries, comparable full-pipeline trials |
| Extended targets | Existing limited non-PE/manual architecture capabilities | Stable audited ELF/ARM64/APK workflows and additional GPU backends |

AI explanations, GPU Datalog, GPU SSA/data-flow, Vulkan/HIP, and complete decompilation on the GPU are research/planned items, not enabled interfaces. The existing Roblox 70% goal remains independently blocked by its missing fuller verifiable readable code source; GPU similarity does not change that result.
