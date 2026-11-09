#include <windows.h>
#include <cstdio>
extern "C" __declspec(dllexport) volatile LONG scratcher_debug_value=7;
extern "C" __declspec(dllexport) __declspec(noinline) int scratcher_debug_target(int x){scratcher_debug_value+=x;return static_cast<int>(scratcher_debug_value);}
int main(int argc,char** argv){if(argc>1){if(argc>2){HANDLE ready=OpenEventA(EVENT_MODIFY_STATE,FALSE,argv[2]);if(!ready)return 2;SetEvent(ready);CloseHandle(ready);}Sleep(30000);return 0;}DebugBreak();for(int i=0;i<3;++i)scratcher_debug_target(i+1);DebugBreak();return scratcher_debug_value==13?0:1;}
