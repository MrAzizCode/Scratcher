#ifndef SCRATCHER_PLUGIN_API_H
#define SCRATCHER_PLUGIN_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define SCRATCHER_PLUGIN_CALL __cdecl
#define SCRATCHER_PLUGIN_EXPORT __declspec(dllexport)
#else
#define SCRATCHER_PLUGIN_CALL
#define SCRATCHER_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define SCRATCHER_PLUGIN_ABI_V1 1u
/* UTF-8 JSON crosses the ABI; C++ objects and allocator ownership never do.
   Host and plugin callbacks are synchronous. Result/error buffers must be
   allocated through host->allocate, and are released by the caller with
   host->release. No callback or host pointer may be retained after return. */
typedef struct ScratcherHostV1 {
 uint32_t struct_size, abi_version;
 void* context;
 void* (SCRATCHER_PLUGIN_CALL *allocate)(void* context,size_t bytes);
 void (SCRATCHER_PLUGIN_CALL *release)(void* context,void* memory);
 int (SCRATCHER_PLUGIN_CALL *call_tool)(void* context,const char* name,const char* arguments_json,char** result_json,char** error_utf8);
 int (SCRATCHER_PLUGIN_CALL *is_cancelled)(void* context);
} ScratcherHostV1;
typedef int (SCRATCHER_PLUGIN_CALL *ScratcherToolCallbackV1)(void* user,const ScratcherHostV1* host,const char* arguments_json,char** result_json,char** error_utf8);
typedef struct ScratcherToolV1 {
 uint32_t struct_size;
 const char* name;
 const char* description;
 const char* input_schema_json;
 uint32_t read_only;
 ScratcherToolCallbackV1 invoke;
} ScratcherToolV1;
typedef struct ScratcherPluginV1 {
 uint32_t struct_size,abi_version;
 const char* id;
 const char* version;
 uint32_t tool_count;
 const ScratcherToolV1* tools;
 void* user;
 /* Event names: binary_opened, analysis_completed, workspace_edited.
    Events contain JSON payloads; event callbacks must not call host tools. */
 void (SCRATCHER_PLUGIN_CALL *on_event)(void* user,const ScratcherHostV1* host,const char* event,const char* payload_json);
 void (SCRATCHER_PLUGIN_CALL *shutdown)(void* user);
} ScratcherPluginV1;
typedef const ScratcherPluginV1* (SCRATCHER_PLUGIN_CALL *ScratcherPluginEntryV1)(void);
/* DLLs export this exact unmangled symbol. Descriptors/strings remain valid
   until unload; the host copies declarations and serializes invocations. */
SCRATCHER_PLUGIN_EXPORT const ScratcherPluginV1* SCRATCHER_PLUGIN_CALL scratcher_plugin_v1(void);
#ifdef __cplusplus
}
#endif
#endif
