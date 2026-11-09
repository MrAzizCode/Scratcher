#include "plugin_api.h"
#include <cstring>
#include <cstdio>
namespace {
unsigned events=0;
int SCRATCHER_PLUGIN_CALL echo(void*,const ScratcherHostV1* host,const char* args,char** result,char** error){
 (void)error;size_t n=std::strlen(args);*result=static_cast<char*>(host->allocate(host->context,n+1));if(!*result)return 0;std::memcpy(*result,args,n+1);return 1;
}
int SCRATCHER_PLUGIN_CALL inspect(void*,const ScratcherHostV1* host,const char*,char** result,char** error){
 return host->call_tool(host->context,"get_binary_info","{}",result,error);
}
int SCRATCHER_PLUGIN_CALL eventCount(void*,const ScratcherHostV1* host,const char*,char** result,char** error){
 (void)error;char text[80];std::snprintf(text,sizeof(text),"{\"events\":%u}",events);return echo(nullptr,host,text,result,error);
}
void SCRATCHER_PLUGIN_CALL onEvent(void*,const ScratcherHostV1*,const char*,const char*){++events;}
void SCRATCHER_PLUGIN_CALL shutdown(void*){events=0;}
const ScratcherToolV1 tools[]={
 {sizeof(ScratcherToolV1),"echo","Return the supplied message through the native C ABI.","{\"type\":\"object\",\"properties\":{\"message\":{\"type\":\"string\",\"maxLength\":256}},\"required\":[\"message\"],\"additionalProperties\":false}",1,echo},
 {sizeof(ScratcherToolV1),"inspect_binary","Read the current binary through a host tool callback.","{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}",1,inspect},
 {sizeof(ScratcherToolV1),"event_count","Read received extension event count.","{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}",1,eventCount}
};
const ScratcherPluginV1 plugin={sizeof(ScratcherPluginV1),SCRATCHER_PLUGIN_ABI_V1,"sample","1.0",3,tools,nullptr,onEvent,shutdown};
}
extern "C" SCRATCHER_PLUGIN_EXPORT const ScratcherPluginV1* SCRATCHER_PLUGIN_CALL scratcher_plugin_v1(void){return &plugin;}
