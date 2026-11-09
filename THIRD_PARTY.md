# Attribution

Scratcher is an independent application and is not an official NSA/Ghidra distribution.

- Ghidra 12.1.4 native decompiler, SLEIGH engine, and x86 processor specifications: National Security Agency and contributors, Apache License 2.0. Source: https://github.com/NationalSecurityAgency/ghidra ; pinned tag `Ghidra_12.1.4_build`, commit `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`. Scratcher modifies function-name accessors in `funcdata.hh` so edits to existing function symbols appear in pseudocode. Scratcher also adds private-translator ownership in `sleigh_arch.hh` and `sleigh_arch.cc` to isolate independent workspaces. Other linked upstream implementation files retain their original behavior. The application has a custom C++ executable loader and architecture adapter. Ghidra LICENSE and NOTICE are included in the package.
- Dear ImGui: Omar Cornut and contributors, MIT License, docking branch. Exact checked-out commit is in `scripts/dependency-lock.json`. https://github.com/ocornut/imgui
- nlohmann JSON 3.12.0: Niels Lohmann and contributors, MIT License. https://github.com/nlohmann/json
- zlib 1.3.1: Jean-loup Gailly and Mark Adler, zlib license. https://github.com/madler/zlib
- Zydis 4.1.1: Florian Bernd, Joel Hoener and contributors, MIT License. https://github.com/zyantific/zydis ; pinned commit `a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`. Zycore dependency pinned commit `0b2432ced0884fd152b471d97ecf0258ff4d859f`, MIT License. Both licenses are included.
- CMake: Kitware and contributors, BSD 3-clause; used only as a build tool. Its license remains in the downloaded tool distribution.

The downloaded full Ghidra archive contains additional components under their respective licenses; only the native engine and processor specifications named above are linked or packaged with Scratcher. See Ghidra's source licenses for the full distribution.

The source checkout includes the processor specifications in `data/languages/`, with their corresponding [LICENSE](licenses/ghidra/LICENSE) and [NOTICE](licenses/ghidra/NOTICE). The remaining build dependencies are obtained separately using the pinned setup script.

- Capstone 5.0.6: contributors, BSD license with LLVM-covered architecture tables. Both LICENSE.TXT and LICENSE_LLVM.TXT are packaged. https://github.com/capstone-engine/capstone/tree/5.0.6
- Lua 5.5.1: Lua.org, PUC-Rio and contributors, MIT License. Embedded statically; licenses/lua/LICENSE.txt included. Official archive https://www.lua.org/ftp/lua-5.5.1.tar.gz; SHA256 1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce.
- Additional packaged processor specifications cover ARM/AArch64, RISC-V, and MIPS under the processor-specification license above.

## Optional CUDA backend

- NVIDIA CUDA Runtime headers and NVRTC 12.4.127: NVIDIA Corporation, CUDA Toolkit End User License Agreement and component-specific conditions. Official Python distributions `nvidia-cuda-runtime-cu12==12.4.127` and `nvidia-cuda-nvrtc-cu12==12.4.127` supply headers and the two runtime compiler DLLs. The application dynamically loads the installed NVIDIA display driver's `nvcuda.dll`; no display driver is redistributed. NVRTC DLLs are packaged in `cuda/`, with the supplied notices in `licenses/cuda-nvrtc/` and header notices in `licenses/cuda-headers/`. These components are not covered by the application's open-source dependencies' licenses. The CPU-only build does not require them. Locked wheel URLs, hashes, and installed-file hashes are in `scripts/hyperdecomp-cuda-lock.json`. Official terms: https://docs.nvidia.com/cuda/eula/ .
- The fingerprint extraction, CPU comparison, CUDA kernels, and benchmark harness in `src/feature_acceleration.cpp`, `src/accel/`, and `src/hyperdecomp_bench.cpp` are application source. No DeepDiCore, proprietary IDA Pro code, angr, RetDec, LLVM, CUB, Thrust, or research GPU graph/Datalog implementation is linked by this milestone. Reviewing those projects does not confer redistribution rights to their separate artifacts.

The research reports distinguish upstream project licenses from model, dependency, and separately distributed binary licenses. See `docs/hyperdecomp/research-core.md` and `docs/hyperdecomp/research-external.md`.
