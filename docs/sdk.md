# Scratcher extension SDK

Scratcher includes an embedded Lua 5.5.1 interpreter and a versioned native C ABI. Both use the same validated analysis tools as MCP. Native extensions publish additional tools visible to MCP and the local tool workspace after loading. This is a first SDK version; it does not provide compiler intermediate-representation hooks or compatibility with another application's plugins.

## Embedded scripts

Call `exec_script` with exactly one of `source` or an absolute UTF-8 `path`:

```json
{"source":"local f = scratcher.call('list_functions', {limit=10}); for _, item in ipairs(f.items) do print(item.address, item.name) end; return {count=#f.items}","timeout_ms":5000,"instruction_limit":10000000,"memory_limit_mb":64}
```

`scratcher.call(name, arguments)` invokes any local tool, including loaded extension tools. Arguments/results are ordinary Lua tables and scalar values. Tool schemas are validated before execution; tool errors terminate the script. Use address strings such as `0x140001000` to preserve exact addresses. JSON unsigned integers larger than signed 64-bit are returned as decimal strings. Empty Lua tables become JSON objects; use `scratcher.array()` for empty arrays. `scratcher.null` represents JSON null. Mixed keys, sparse arrays, cyclic tables and values that cannot be represented as JSON are rejected. `scratcher.json_encode` and `scratcher.json_decode` provide explicit JSON conversion. `print` captures a bounded log instead of writing into the MCP protocol stream.

Each execution starts with a fresh Lua state. Available standard libraries: base, table, string, math and utf8. No os, io, package, debug or coroutine library is exposed; dynamic Lua loading and `pcall`/`xpcall` are disabled so resource-limit errors cannot be suppressed. These limits restrict the interpreter; host tools can still perform their documented file edits, exports, debugger launches and native extension loads when explicitly called by the script. Scripts are trusted workspace automation, not an isolation boundary for untrusted tasks.

Limits: 256 KiB source, 1,000 tool calls, eight extension/script recursion levels, 32 JSON nesting levels, 100,000 JSON elements, 4 MiB result and 64 KiB captured log. Defaults: 10 million VM instructions, 5 seconds, 64 MiB Lua allocations. Configurable bounds: 1,000–100 million instructions, 1–60,000 ms and 4–128 MiB. Cancellation/deadlines are checked at VM hooks and before/after each tool call. A host operation follows its own cancellation behavior and can overrun the script deadline before returning. Native plugin execution is cooperative and cannot be safely interrupted by the VM hook. Earlier edits remain if a later script statement fails; scripts are not transactions.

## Native extensions

Include `src/plugin_api.h` and export the unmangled C symbol `scratcher_plugin_v1`. Its returned `ScratcherPluginV1` descriptor declares a unique simple identifier, a version string, up to 128 tool descriptors and optional event/shutdown callbacks. V1 requires matching struct sizes and ABI version. The supplied example in `examples/scratcher_plugin.cpp` demonstrates JSON echo, a call to `get_binary_info`, and event counting.

Build a DLL with the same host architecture. Call `load_plugin` with its absolute `.dll` path. Tools are named `plugin.<id>.<tool>` and have their supplied JSON object schemas validated before callbacks. Refresh MCP `tools/list` after loading/unloading in a headless workspace. For an attached desktop, use the stable `call_plugin` tool with `id`, `tool` and `arguments`; this validates against the extension loaded in that exact desktop workspace, even when the MCP client's local workspace has different extensions. `list_plugins` reports descriptors, paths, schemas and recent events; `unload_plugin` removes declarations and unloads an idle DLL. Extensions remain loaded when the current binary changes. Project metadata can record loaded extension identities but never automatically loads native code when a project opens.

Callbacks receive a versioned `ScratcherHostV1` with `call_tool`, `is_cancelled`, `allocate` and `release`. Allocate all result/error UTF-8 buffers with the host allocator, terminate them with NUL and return them through the callback output pointers. The host releases them exactly once. Release buffers received from `host->call_tool` with `host->release`, or transfer them directly as callback outputs. Never pass C++ objects across the ABI or retain host context/callback pointers. Tool callbacks are synchronous and serialized within the workspace; nested calls are bounded. Return 1 for success with valid JSON, or 0 with an optional UTF-8 error buffer. Results are limited to 4 MiB. Check `is_cancelled` during long native operations.

Events currently cover `binary_opened`, `analysis_completed` and `workspace_edited`. Event callbacks receive a bounded JSON payload; host tool calls are disabled during events to prevent recursive edits. Native code is fully trusted and runs in the process: the host cannot prevent crashes, arbitrary process access or DLL initialization side effects. Unload and shutdown are cooperative. This API is intended for locally chosen extensions, not automatic execution of code supplied with a binary.

## Build integration

Lua is compiled statically as C++ so Lua exceptions correctly unwind C++ host callback temporaries. Build every `vendor/lua/src/*.c` except `lua.c`, `luac.c` and `onelua.c`, set their CMake source language to CXX, and include `vendor/lua/src`. Do not wrap Lua headers in `extern "C"` for this configuration. No external Lua installation is required.

Official source: https://www.lua.org/ftp/lua-5.5.1.tar.gz

SHA-256: `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`.

The portable package includes the Lua copyright/license in `licenses/lua/LICENSE.txt` and SDK headers/examples in `sdk/`.
