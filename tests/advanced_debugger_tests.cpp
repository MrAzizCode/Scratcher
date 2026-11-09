#include "feature_advanced_debugger.hpp"
#include <windows.h>
#include <iostream>
#include <algorithm>
using namespace scratcher;
namespace {
int checks=0;
void check(bool yes,const char* message){++checks;if(!yes)throw std::runtime_error(message);}
Json call(Engine& e,const std::string& n,Json a=Json::object()){auto result=callDebuggerTool(e,n,a);if(!result)throw std::runtime_error("Debugger tool was not dispatched");return *result;}
Json wait(Engine& e){auto s=call(e,"debugger_wait",{{"timeout_ms",5000}});check(s["timed_out"]==false,"Debuggee reached stop before deadline");check(s["paused"]==true,"Debuggee paused");return s;}
template<class F>void rejects(F fn,const char* message){bool rejected=false;try{fn();}catch(const std::exception&){rejected=true;}check(rejected,message);}
struct Child{HANDLE process=nullptr;~Child(){if(process){TerminateProcess(process,0);WaitForSingleObject(process,3000);CloseHandle(process);}}};
struct Event{HANDLE handle=nullptr;~Event(){if(handle)CloseHandle(handle);}};
Address exportAddress(const Binary& b,const std::string& name){auto offset=[&](uint32_t rva){for(const auto& s:b.sections)if(rva+b.base>=s.va&&rva+b.base-s.va<s.fileSize)return s.offset+rva+b.base-s.va;throw std::runtime_error("Unmapped fixture export RVA");};auto pe=b.read<uint32_t>(0x3c);auto dir=offset(b.read<uint32_t>(pe+24+112));auto count=b.read<uint32_t>(dir+24);auto names=offset(b.read<uint32_t>(dir+32)),ordinals=offset(b.read<uint32_t>(dir+36)),functions=offset(b.read<uint32_t>(dir+28));for(uint64_t i=0;i<count;++i)if(b.cstring(offset(b.read<uint32_t>(names+i*4)))==name)return b.base+b.read<uint32_t>(functions+b.read<uint16_t>(ordinals+i*2)*4);return 0;}
}
int main(){try{
 auto fixture=executableDir()/"ScratcherDebugFixture.exe";check(std::filesystem::is_regular_file(fixture),"Built safe fixture exists");
 Engine e;check(!callDebuggerTool(e,"unknown",Json::object()),"Unknown operation falls through");check(debuggerTools().size()==22,"Debugger exposes 22 tools");
 rejects([&]{call(e,"debugger_registers");},"Register reads reject no session");
 rejects([&]{call(e,"debugger_attach",{{"process_id",GetCurrentProcessId()}});},"Self attachment rejected");
 e.open(fixture);Address target=exportAddress(*e.binary(),"scratcher_debug_target"),global=exportAddress(*e.binary(),"scratcher_debug_value");check(target!=0&&global!=0,"Fixture exports provide test code and data addresses");Address fileBase=e.binary()->base;
 auto state=call(e,"debugger_launch",{{"path",pathText(fixture)}});DWORD pid=state["process_id"].get<DWORD>();Child cleanup{OpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid)};check(state["active"]==true,"Real process launched");state=wait(e);
 Address liveBase=0;for(auto& module:state["modules"])if(module["path"].get<std::string>().find("ScratcherDebugFixture.exe")!=std::string::npos)liveBase=address(module["base"]);check(liveBase!=0,"Debug events enumerate executable image");target=liveBase+target-fileBase;global=liveBase+global-fileBase;
 auto regs=call(e,"debugger_registers");check(address(regs["rip"])!=0,"x64 context has instruction pointer");auto originalRax=regs["rax"];call(e,"debugger_set_register",{{"register","rax"},{"value","0x1234"}});check(call(e,"debugger_registers")["rax"]=="0x1234","Integer register write applies");call(e,"debugger_set_register",{{"register","rax"},{"value",originalRax}});
 check(!call(e,"debugger_threads")["threads"].empty(),"Live threads enumerated");check(!call(e,"debugger_modules")["modules"].empty(),"Live modules enumerated");auto frames=call(e,"debugger_stack",{{"limit",8}});check(!frames["frames"].empty(),"Stack walker returns current frame");
 check(call(e,"debugger_read_memory",{{"address",hex(global)},{"size",4}})["bytes"]=="07 00 00 00","Live exported data read");call(e,"debugger_write_memory",{{"address",hex(global)},{"bytes","08 00 00 00"}});check(call(e,"debugger_read_memory",{{"address",hex(global)},{"size",4}})["bytes"]=="08 00 00 00","Live data write applies");call(e,"debugger_write_memory",{{"address",hex(global)},{"bytes","07 00 00 00"}});
 auto watch=call(e,"debugger_watch_add",{{"address",hex(global)},{"size",4}});check(call(e,"debugger_watches")["watches"].size()==1,"Memory watch registered");
 auto originalByte=call(e,"debugger_read_memory",{{"address",hex(target)},{"size",1}})["bytes"];call(e,"debugger_breakpoint_add",{{"address",hex(target)}});check(call(e,"debugger_read_memory",{{"address",hex(target)},{"size",1}})["bytes"]=="cc","Breakpoint installs real INT3");rejects([&]{call(e,"debugger_write_memory",{{"address",hex(target)},{"bytes","90"}});},"Overlapping live patch rejected");
 call(e,"debugger_continue");state=wait(e); // The fixture's deliberate first DebugBreak.
 call(e,"debugger_continue");state=wait(e);check(state["registers"]["rip"]==hex(target),"Software breakpoint rewinds instruction pointer");check(call(e,"debugger_read_memory",{{"address",hex(target)},{"size",1}})["bytes"]==originalByte,"Breakpoint restores displaced instruction");
 call(e,"debugger_step");state=wait(e);check(state["state"]=="step"&&state["registers"]["rip"]!=hex(target),"Single step executes displaced instruction");check(call(e,"debugger_read_memory",{{"address",hex(target)},{"size",1}})["bytes"]=="cc","Single step reinstalls breakpoint");
 call(e,"debugger_breakpoint_remove",{{"address",hex(target)}});check(call(e,"debugger_read_memory",{{"address",hex(target)},{"size",1}})["bytes"]==originalByte,"Removal restores original instruction");
 call(e,"debugger_trace",{{"count",8}});state=wait(e);check(state["state"]=="trace_complete"&&state["trace"].size()==8,"Bounded trace records eight executed destinations");
 call(e,"debugger_continue");state=wait(e);check(call(e,"debugger_read_memory",{{"address",hex(global)},{"size",4}})["bytes"]=="0d 00 00 00","Debuggee resumed through target calls");bool changed=false;for(auto& event:state["events"])if(event["kind"]=="watch_changed")changed=true;check(changed,"Stopped memory watch detects value change");check(call(e,"debugger_watch_remove",{{"id",watch["id"]}})["removed"]==true,"Memory watch removed");call(e,"debugger_continue");state=call(e,"debugger_wait",{{"timeout_ms",5000}});check(state["active"]==false&&state["state"]=="exited"&&state["exit_code"]==0,"Normal debuggee exit reported");
 // Exercise attach/detach against a second explicitly created safe fixture.
 // Wait until the non-debugged fixture has finished loader startup. Attaching
 // during loader initialization can legitimately yield two system breaks.
 std::wstring readyName=L"Local\\ScratcherDebugFixtureReady-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());Event ready{CreateEventW(nullptr,TRUE,FALSE,readyName.c_str())};check(ready.handle!=nullptr,"Attach fixture ready event created");std::wstring command=L"\""+fixture.wstring()+L"\" hold \""+readyName+L"\"";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};check(CreateProcessW(fixture.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)!=FALSE,"Attach fixture launched");CloseHandle(pi.hThread);Child attached{pi.hProcess};check(WaitForSingleObject(ready.handle,5000)==WAIT_OBJECT_0,"Attach fixture completed loader startup");call(e,"debugger_attach",{{"process_id",pi.dwProcessId}});wait(e);call(e,"debugger_continue");check(call(e,"debugger_wait",{{"timeout_ms",50}})["timed_out"]==true,"Bounded wait reports running-process timeout");std::atomic_bool cancelled=true;e.setCancellation(&cancelled);check(call(e,"debugger_wait",{{"timeout_ms",5000}})["cancelled"]==true,"Wait supports cooperative cancellation");e.setCancellation(nullptr);call(e,"debugger_pause");wait(e);call(e,"debugger_detach");check(call(e,"debugger_status")["active"]==false,"Debugger detached");check(WaitForSingleObject(pi.hProcess,50)==WAIT_TIMEOUT,"Detach leaves debuggee running");
 // Execute the explicit termination API against a third safe fixture.
 state=call(e,"debugger_launch",{{"path",pathText(fixture)},{"arguments",{"hold"}}});Child terminated{OpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,FALSE,state["process_id"].get<DWORD>())};wait(e);state=call(e,"debugger_terminate");check(state["active"]==false,"Explicit termination cleans up session");
 // Runtime destruction detaches safely and must not kill an attached/launched
 // process merely because the analysis session or application is closed.
 Child detached;{Engine ephemeral;state=call(ephemeral,"debugger_launch",{{"path",pathText(fixture)},{"arguments",{"hold"}}});detached.process=OpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,FALSE,state["process_id"].get<DWORD>());wait(ephemeral);}check(detached.process&&WaitForSingleObject(detached.process,50)==WAIT_TIMEOUT,"Runtime destruction detaches and resumes a paused debuggee");
 std::cout<<checks<<" native debugger checks passed\n";return 0;
}catch(const std::exception& e){std::cerr<<"Native debugger test failure: "<<e.what()<<"\n";return 1;}}
