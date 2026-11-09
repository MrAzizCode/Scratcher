# Scratcher

Scratcher is a native C++ reverse engineering workbench for Windows x64. It combines disassembly, C-like pseudocode, control-flow graphs, cross-references, and an MCP server that can drive the same workspace as the desktop app.

**Current development snapshot: 0.8.** Static x86/x64 PE analysis is the main focus. CUDA is optional and currently accelerates function similarity searches. Loading, disassembly, code recovery, and pseudocode run on the CPU.

## What works

- Browse disassembly, pseudocode, hex, strings, imports, exports, functions, and graphs. Follow references and search byte or text patterns.
- Rename functions, edit types and signatures, add comments and bookmarks, and save projects tied to the input's SHA-256. Export staged patches to a separate copy.
- Run bounded reachable-code analysis, unwind and RTTI inspection, and cross-reference indexing. Inspect exact failure addresses and indirect-transfer evidence without marking uncertain paths as resolved.
- Use 150 built-in MCP tools for analysis, editing, background jobs, or desktop control. Extend the workbench with Lua or the [native plugin SDK](docs/sdk.md).
- Compare function fingerprints on the CPU or a supported NVIDIA GPU. The matcher checks exact distances between fingerprints; the fingerprints themselves are heuristic.

Inputs include Windows PE, little-endian ELF and Mach-O, raw binaries, and captured ranges in Windows minidumps. Decoder support includes x86/x64, ARM/Thumb, ARM64, RISC-V, and MIPS; analysis and pseudocode coverage vary by architecture and format. Ordinary static analysis does not execute the input. Debugger operations are separate and explicitly target a process.

## Build and run

Install Visual Studio 2022 with Desktop development with C++, a Windows SDK, Git, Python 3.11+, and CMake 3.24+. Run these commands from the checkout. To keep files on `D:`, clone to a directory such as `D:/Scratcher`.

```powershell
python scripts/setup-dependencies.py
./scripts/setup-hyperdecomp.ps1 -CpuOnly -Build -Test
./build-cpu/Release/Scratcher.exe
```

Open or drop a binary. Select a function to see its disassembly, press `F5` for pseudocode, `Space` for the graph, or `X` for references. `Ctrl+S` saves a project. Keep `data/` beside the executables when moving a build.

For optional CUDA support, install a compatible NVIDIA driver and run:

```powershell
./scripts/setup-hyperdecomp.ps1 -Build -Test
./build/Release/Scratcher.exe
```

The setup script downloads and checks the pinned CUDA compiler components. It does not require `nvcc` or a system CUDA Toolkit. See the [build and CUDA guide](docs/hyperdecomp/usage.md) for packaging, CLI commands, and benchmark reproduction.

## MCP and command line

Point your client at the absolute path to `ScratcherMCP.exe`:

```json
{
  "mcpServers": {
    "scratcher": {
      "command": "D:/Scratcher/build-cpu/Release/ScratcherMCP.exe",
      "args": ["--mcp"]
    }
  }
}
```

Call `open_binary`, then `list_functions`, `disassemble`, `decompile`, or `get_control_flow`. To drive an existing Scratcher window, call `discover_sessions`, then `attach_session` with that session ID. Use `tools/list` for current arguments and limits. The desktop can also copy its connection configuration.

```powershell
./build-cpu/Release/HyperDecompCLI.exe --inspect D:/path/to/sample.exe
./build-cpu/Release/HyperDecompCLI.exe --analyze D:/path/to/sample.exe --time-budget-ms 10000
```

## Analysis status

The current update adds optional stop pages, cuts unnecessary operand decoding, and lets callers pass explicitly selected indexed functions for guarded read-only switch recovery. The switch targets keep their provenance and uncertainty in bulk traversal and cross-references. See the [analysis controls](docs/analysis.md) and [0.8 validation notes](docs/analysis-0.8.md).

Coverage reports count unique decoded instruction-candidate bytes against the original file-backed candidate scope. They do not measure decompilation accuracy or the percentage of all true program code. The original Roblox 0.742 sample remains at **3.248546%** under the measured pass. The new diagnostics show why most paths stop; they do not establish a recovery gain on that file.

This is a source snapshot. Build products, local test inputs, memory captures, generated reports, and downloaded dependencies stay outside Git. Required third-party attribution and notices are in [THIRD_PARTY.md](THIRD_PARTY.md) and [licenses/](licenses/).
