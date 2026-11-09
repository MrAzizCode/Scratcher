#include "feature_advanced_debugger.hpp"
#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <functional>
#include <iomanip>
#include <thread>
#include <cctype>
#include <tuple>

namespace scratcher { namespace {
std::runtime_error failure(const char* action){return std::runtime_error(std::string(action)+" failed (Windows error "+std::to_string(GetLastError())+")");}
std::wstring wide(const std::string& s){if(s.empty())return {};int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);if(!n)throw failure("UTF-8 conversion");std::wstring r(n,0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),r.data(),n);return r;}
std::string utf8(const std::wstring& s){if(s.empty())return {};int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);std::string r(n,0);WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),r.data(),n,nullptr,nullptr);return r;}
std::wstring quote(const std::wstring& s){std::wstring r=L"\"";size_t slashes=0;for(wchar_t c:s){if(c==L'\\'){++slashes;continue;}if(c==L'\"')r.append(slashes*2+1,L'\\');else r.append(slashes,L'\\');slashes=0;r+=c;}r.append(slashes*2,L'\\');return r+L"\"";}
std::string fileName(HANDLE h){if(!h||h==INVALID_HANDLE_VALUE)return {};std::wstring s(32768,0);DWORD n=GetFinalPathNameByHandleW(h,s.data(),static_cast<DWORD>(s.size()),FILE_NAME_NORMALIZED);if(n==0||n>=s.size())return {};s.resize(n);return utf8(s);}
uint64_t bounded(const Json& a,const char* key,uint64_t fallback,uint64_t lo,uint64_t hi){uint64_t n=a.value(key,fallback);if(n<lo||n>hi)throw std::runtime_error(std::string(key)+" exceeds allowed range");return n;}
std::vector<uint8_t> parseBytes(const std::string& s){std::string digits;for(unsigned char c:s){if(std::isspace(c))continue;if(!std::isxdigit(c))throw std::runtime_error("Bytes must be hexadecimal");digits+=static_cast<char>(c);}if(digits.empty()||digits.size()%2||digits.size()>131072)throw std::runtime_error("Bytes must contain 1 to 65536 bytes");std::vector<uint8_t> r;for(size_t i=0;i<digits.size();i+=2)r.push_back(static_cast<uint8_t>(std::stoul(digits.substr(i,2),nullptr,16)));return r;}
std::string bytesText(const uint8_t* bytes,size_t n){static constexpr char h[]="0123456789abcdef";std::string s;s.reserve(n*3);for(size_t i=0;i<n;++i){if(i)s+=' ';s+=h[bytes[i]>>4];s+=h[bytes[i]&15];}return s;}

class Debugger {
 struct Breakpoint {uint8_t original=0;bool installed=false;};
 struct Watch {Address address=0;size_t size=0;std::vector<uint8_t> previous;};
 HANDLE process_=nullptr;DWORD pid_=0;bool active_=false,paused_=false,launched_=false,shutdown_=false;
 DEBUG_EVENT pending_{};DWORD eventThread_=0;std::string reason_="idle",error_;DWORD exitCode_=0;
 std::map<DWORD,HANDLE> threads_;std::map<Address,Json> modules_;std::map<Address,Breakpoint> breakpoints_;std::map<uint64_t,Watch> watches_;uint64_t nextWatch_=1;std::vector<HANDLE> stepHeld_;
 Address displaced_=0;bool hasDisplaced_=false,reinsert_=false,userStep_=false;size_t traceRemaining_=0;Json trace_=Json::array(),events_=Json::array();
 // The worker starts in its initializer, so every synchronization primitive
 // and all state it touches must be constructed before the thread object.
 std::mutex queueMutex_;std::condition_variable cv_;std::deque<std::function<void()>> queue_;std::thread worker_;
 void eventLog(const std::string& kind,Json detail=Json::object()){detail["kind"]=kind;detail["thread_id"]=eventThread_;events_.push_back(std::move(detail));if(events_.size()>256)events_.erase(events_.begin());}
 HANDLE thread(DWORD tid){if(tid==0)tid=eventThread_;auto it=threads_.find(tid);if(it==threads_.end())throw std::runtime_error("Unknown debuggee thread");return it->second;}
 void require(bool stopped=false){if(!active_||!process_)throw std::runtime_error("No active debugger session");if(stopped&&!paused_)throw std::runtime_error("Pause the debuggee before this operation");}
 CONTEXT context(DWORD tid=0){require(true);CONTEXT c{};c.ContextFlags=CONTEXT_ALL;if(!GetThreadContext(thread(tid),&c))throw failure("GetThreadContext");return c;}
 void setContext(CONTEXT& c,DWORD tid=0){if(!SetThreadContext(thread(tid),&c))throw failure("SetThreadContext");}
 void checkArchitecture(){USHORT machine=0,native=0;if(!IsWow64Process2(process_,&machine,&native))throw failure("IsWow64Process2");if(machine!=IMAGE_FILE_MACHINE_UNKNOWN||native!=IMAGE_FILE_MACHINE_AMD64)throw std::runtime_error("Local debugger currently supports native x64 processes only");}
 std::vector<uint8_t> read(Address va,size_t n){std::vector<uint8_t> out(n);SIZE_T done=0;if(!ReadProcessMemory(process_,reinterpret_cast<LPCVOID>(va),out.data(),n,&done)||done!=n)throw failure("ReadProcessMemory");return out;}
 void write(Address va,const uint8_t* bytes,size_t n){DWORD old=0;if(!VirtualProtectEx(process_,reinterpret_cast<LPVOID>(va),n,PAGE_EXECUTE_READWRITE,&old))throw failure("VirtualProtectEx");SIZE_T done=0;BOOL ok=WriteProcessMemory(process_,reinterpret_cast<LPVOID>(va),bytes,n,&done);DWORD error=GetLastError(),ignored=0;BOOL restored=VirtualProtectEx(process_,reinterpret_cast<LPVOID>(va),n,old,&ignored);FlushInstructionCache(process_,reinterpret_cast<LPCVOID>(va),n);if(!ok||done!=n){SetLastError(error);throw failure("WriteProcessMemory");}if(!restored)throw failure("Restore memory protection");}
 void install(Address va){auto& b=breakpoints_.at(va);const uint8_t cc=0xcc;write(va,&cc,1);b.installed=true;}
 void restore(Address va){auto& b=breakpoints_.at(va);if(b.installed){write(va,&b.original,1);b.installed=false;}}
 Json registers(DWORD tid=0){auto c=context(tid);return {{"thread_id",tid?tid:eventThread_},{"rip",hex(c.Rip)},{"rsp",hex(c.Rsp)},{"rbp",hex(c.Rbp)},{"rax",hex(c.Rax)},{"rbx",hex(c.Rbx)},{"rcx",hex(c.Rcx)},{"rdx",hex(c.Rdx)},{"rsi",hex(c.Rsi)},{"rdi",hex(c.Rdi)},{"r8",hex(c.R8)},{"r9",hex(c.R9)},{"r10",hex(c.R10)},{"r11",hex(c.R11)},{"r12",hex(c.R12)},{"r13",hex(c.R13)},{"r14",hex(c.R14)},{"r15",hex(c.R15)},{"eflags",hex(c.EFlags)}};}
 void sampleWatches(){for(auto& [id,w]:watches_)try{auto now=read(w.address,w.size);if(!w.previous.empty()&&now!=w.previous)eventLog("watch_changed",{{"id",id},{"address",hex(w.address)},{"before",bytesText(w.previous.data(),w.previous.size())},{"after",bytesText(now.data(),now.size())}});w.previous=std::move(now);}catch(const std::exception& e){eventLog("watch_read_error",{{"id",id},{"error",e.what()}});}}
 void stop(const DEBUG_EVENT& e,const std::string& why){pending_=e;eventThread_=e.dwThreadId;paused_=true;reason_=why;sampleWatches();}
 void continueEvent(DWORD disposition=DBG_CONTINUE){if(!ContinueDebugEvent(pending_.dwProcessId,pending_.dwThreadId,disposition))throw failure("ContinueDebugEvent");paused_=false;reason_="running";}
 void releaseStepThreads(){for(auto h:stepHeld_)ResumeThread(h);stepHeld_.clear();}
 void resume(bool step,DWORD disposition){require(true);auto c=context();userStep_=step;reinsert_=hasDisplaced_;if(step||reinsert_||traceRemaining_)c.EFlags|=0x100;else c.EFlags&=~0x100u;setContext(c);if(reinsert_)for(auto [id,h]:threads_)if(id!=eventThread_){if(SuspendThread(h)==DWORD(-1)){releaseStepThreads();throw failure("Suspend breakpoint peer thread");}stepHeld_.push_back(h);}try{continueEvent(disposition);}catch(...){releaseStepThreads();throw;}}
 void releaseHandles(){releaseStepThreads();for(auto [id,h]:threads_)CloseHandle(h);threads_.clear();if(process_)CloseHandle(process_);process_=nullptr;active_=false;paused_=false;}
 void detach(bool terminate){if(!active_){releaseHandles();return;}if(terminate){if(!TerminateProcess(process_,0))throw failure("TerminateProcess");if(paused_)continueEvent();for(int i=0;i<200&&active_;++i){DEBUG_EVENT e{};if(WaitForDebugEventEx(&e,10))handle(e);}if(active_)DebugActiveProcessStop(pid_);releaseHandles();reason_="terminated";return;}
  // Every debug event suspends the process. Outside a pause, suspend threads only
  // for breakpoint restoration; the detach itself resumes normal execution.
  std::vector<HANDLE> suspended;for(auto [id,h]:threads_)if(SuspendThread(h)!=DWORD(-1))suspended.push_back(h);
  try{for(auto [va,b]:breakpoints_)restore(va);for(auto [id,h]:threads_){CONTEXT c{};c.ContextFlags=CONTEXT_CONTROL;if(GetThreadContext(h,&c)){c.EFlags&=~0x100u;SetThreadContext(h,&c);}}if(paused_)continueEvent();if(!DebugActiveProcessStop(pid_))throw failure("DebugActiveProcessStop");}catch(...){for(auto h:suspended)ResumeThread(h);throw;}
  for(auto h:suspended)ResumeThread(h);releaseHandles();reason_="detached";breakpoints_.clear();hasDisplaced_=false;
 }
 void handle(DEBUG_EVENT& e){eventThread_=e.dwThreadId;DWORD status=DBG_CONTINUE;
  switch(e.dwDebugEventCode){
   // Event-owned process/thread handles are automatically closed by Windows
   // after their exit events. Store independent duplicates for debugger use.
   case CREATE_PROCESS_DEBUG_EVENT:{auto& d=e.u.CreateProcessInfo;HANDLE owned=nullptr;if(!DuplicateHandle(GetCurrentProcess(),d.hThread,GetCurrentProcess(),&owned,0,FALSE,DUPLICATE_SAME_ACCESS))throw failure("Duplicate debug thread handle");threads_[e.dwThreadId]=owned;Address base=reinterpret_cast<Address>(d.lpBaseOfImage);modules_[base]={{"base",hex(base)},{"path",fileName(d.hFile)}};if(d.hFile)CloseHandle(d.hFile);break;}
   case CREATE_THREAD_DEBUG_EVENT:{HANDLE owned=nullptr;if(!DuplicateHandle(GetCurrentProcess(),e.u.CreateThread.hThread,GetCurrentProcess(),&owned,0,FALSE,DUPLICATE_SAME_ACCESS))throw failure("Duplicate debug thread handle");threads_[e.dwThreadId]=owned;if(reinsert_&&SuspendThread(owned)!=DWORD(-1))stepHeld_.push_back(owned);break;}
   case EXIT_THREAD_DEBUG_EVENT:{auto it=threads_.find(e.dwThreadId);if(it!=threads_.end()){CloseHandle(it->second);threads_.erase(it);}break;}
   case LOAD_DLL_DEBUG_EVENT:{auto& d=e.u.LoadDll;Address base=reinterpret_cast<Address>(d.lpBaseOfDll);modules_[base]={{"base",hex(base)},{"path",fileName(d.hFile)}};if(d.hFile)CloseHandle(d.hFile);break;}
   case UNLOAD_DLL_DEBUG_EVENT:modules_.erase(reinterpret_cast<Address>(e.u.UnloadDll.lpBaseOfDll));break;
   case EXIT_PROCESS_DEBUG_EVENT:exitCode_=e.u.ExitProcess.dwExitCode;reason_="exited";eventLog("process_exit",{{"exit_code",exitCode_}});ContinueDebugEvent(e.dwProcessId,e.dwThreadId,DBG_CONTINUE);releaseHandles();return;
   case EXCEPTION_DEBUG_EVENT:{auto& ex=e.u.Exception;auto code=ex.ExceptionRecord.ExceptionCode;Address va=reinterpret_cast<Address>(ex.ExceptionRecord.ExceptionAddress);eventLog("exception",{{"code",hex(code)},{"address",hex(va)},{"first_chance",ex.dwFirstChance!=0}});
    if(code==EXCEPTION_BREAKPOINT){stop(e,"breakpoint");auto it=breakpoints_.find(va);if(it!=breakpoints_.end()&&it->second.installed){restore(va);auto c=context();c.Rip=va;setContext(c);displaced_=va;hasDisplaced_=true;}return;}
    if(code==EXCEPTION_SINGLE_STEP){stop(e,"step");auto c=context();c.EFlags&=~0x100u;setContext(c);if(reinsert_){auto it=breakpoints_.find(displaced_);if(it!=breakpoints_.end())install(displaced_);hasDisplaced_=false;reinsert_=false;releaseStepThreads();}if(traceRemaining_){trace_.push_back({{"thread_id",eventThread_},{"address",hex(c.Rip)}});--traceRemaining_;if(traceRemaining_){resume(true,DBG_CONTINUE);return;}reason_="trace_complete";userStep_=false;return;}if(userStep_){userStep_=false;return;}continueEvent();return;}
    if(!ex.dwFirstChance){stop(e,"unhandled_exception");return;}status=DBG_EXCEPTION_NOT_HANDLED;break;}
   default:break;
  }if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,status))throw failure("ContinueDebugEvent");
 }
 Json state(){Json b=Json::array(),m=Json::array();for(auto [va,bp]:breakpoints_)b.push_back({{"address",hex(va)},{"installed",bp.installed}});for(auto& [va,module]:modules_)m.push_back(module);Json r={{"active",active_},{"paused",paused_},{"process_id",pid_},{"thread_id",eventThread_},{"state",reason_},{"launched",launched_},{"exit_code",exitCode_},{"breakpoints",b},{"modules",m},{"thread_count",threads_.size()},{"events",events_},{"trace",trace_},{"trace_remaining",traceRemaining_},{"error",error_},{"architecture","x64"},{"transport","local"}};if(paused_)r["registers"]=registers();return r;}
 Json stack(const Json& a){require(true);DWORD tid=static_cast<DWORD>(a.value("thread_id",uint64_t(0)));CONTEXT c=context(tid);size_t limit=static_cast<size_t>(bounded(a,"limit",32,1,256));HANDLE mutex=CreateMutexW(nullptr,FALSE,L"Local\\ScratcherDbgHelp");if(!mutex)throw failure("CreateMutex");DWORD lock=WaitForSingleObject(mutex,3000);if(lock!=WAIT_OBJECT_0&&lock!=WAIT_ABANDONED){CloseHandle(mutex);throw std::runtime_error("Symbol service busy");}Json frames=Json::array();bool initialized=false;DWORD previousOptions=SymGetOptions();try{SymSetOptions(SYMOPT_DEFERRED_LOADS|SYMOPT_UNDNAME|SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_NO_PROMPTS|SYMOPT_IGNORE_NT_SYMPATH|SYMOPT_DISABLE_SYMSRV_AUTODETECT);std::wstring image(32768,0);DWORD imageLength=static_cast<DWORD>(image.size());std::wstring search;if(QueryFullProcessImageNameW(process_,0,image.data(),&imageLength)){image.resize(imageLength);search=std::filesystem::path(image).parent_path().wstring();}initialized=SymInitializeW(process_,search.c_str(),TRUE)!=FALSE;STACKFRAME64 f{};f.AddrPC={c.Rip,0,AddrModeFlat};f.AddrStack={c.Rsp,0,AddrModeFlat};f.AddrFrame={c.Rbp,0,AddrModeFlat};Address previous=0;for(size_t i=0;i<limit&&f.AddrPC.Offset;++i){if(f.AddrPC.Offset==previous)break;previous=f.AddrPC.Offset;Json row={{"index",i},{"address",hex(f.AddrPC.Offset)},{"stack_pointer",hex(f.AddrStack.Offset)}};alignas(SYMBOL_INFO) char storage[sizeof(SYMBOL_INFO)+MAX_SYM_NAME]{};auto* symbol=reinterpret_cast<SYMBOL_INFO*>(storage);symbol->SizeOfStruct=sizeof(SYMBOL_INFO);symbol->MaxNameLen=MAX_SYM_NAME;DWORD64 displacement=0;if(initialized&&SymFromAddr(process_,f.AddrPC.Offset,&displacement,symbol)){row["symbol"]=std::string(symbol->Name,symbol->NameLen);row["displacement"]=displacement;}frames.push_back(std::move(row));if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,process_,thread(tid),&f,&c,nullptr,SymFunctionTableAccess64,SymGetModuleBase64,nullptr))break;}if(initialized)SymCleanup(process_);SymSetOptions(previousOptions);ReleaseMutex(mutex);CloseHandle(mutex);return {{"thread_id",tid?tid:eventThread_},{"frames",frames},{"partial",frames.size()>=limit},{"symbols_available",initialized}};}catch(...){if(initialized)SymCleanup(process_);SymSetOptions(previousOptions);ReleaseMutex(mutex);CloseHandle(mutex);throw;}}
 Json execute(const std::string& name,const Json& a){
  if(name=="debugger_status")return state();
  if(name=="debugger_launch"||name=="debugger_attach"){if(active_)throw std::runtime_error("Detach or terminate the active debuggee first");releaseHandles();breakpoints_.clear();modules_.clear();watches_.clear();trace_=Json::array();events_=Json::array();error_.clear();hasDisplaced_=reinsert_=userStep_=false;traceRemaining_=0;exitCode_=0;eventThread_=0;launched_=name=="debugger_launch";
   if(launched_){auto path=std::filesystem::absolute(std::filesystem::u8path(a.at("path").get<std::string>()));if(!std::filesystem::is_regular_file(path))throw std::runtime_error("Executable path does not exist");std::wstring command=quote(path.wstring());for(const auto& arg:a.value("arguments",Json::array())){command+=L" ";command+=quote(wide(arg.get<std::string>()));}if(command.size()>32766)throw std::runtime_error("Command line exceeds Windows limit");std::wstring cwd=a.contains("working_directory")?wide(a["working_directory"].get<std::string>()):path.parent_path().wstring();STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION pi{};if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,nullptr,cwd.c_str(),&startup,&pi))throw failure("CreateProcess");process_=pi.hProcess;pid_=pi.dwProcessId;CloseHandle(pi.hThread);try{checkArchitecture();}catch(...){TerminateProcess(process_,0);active_=true;detach(true);throw;}}
   else{pid_=static_cast<DWORD>(bounded(a,"process_id",0,1,0xffffffff));if(pid_==GetCurrentProcessId())throw std::runtime_error("Cannot attach the debugger to itself");process_=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid_);if(!process_)throw failure("OpenProcess");try{checkArchitecture();if(!DebugActiveProcess(pid_))throw failure("DebugActiveProcess");}catch(...){releaseHandles();throw;}}
   DebugSetProcessKillOnExit(FALSE);active_=true;paused_=false;reason_="running";return state();
  }
  if(name=="debugger_detach"){detach(false);return state();}
  if(name=="debugger_terminate"){require();detach(true);return state();}
  if(name=="debugger_pause"){require();if(!paused_&&!DebugBreakProcess(process_))throw failure("DebugBreakProcess");return state();}
  if(name=="debugger_continue"){traceRemaining_=0;resume(false,a.value("pass_exception",false)?DBG_EXCEPTION_NOT_HANDLED:DBG_CONTINUE);return state();}
  if(name=="debugger_step"){traceRemaining_=0;resume(true,DBG_CONTINUE);return state();}
  if(name=="debugger_trace"){require(true);trace_=Json::array();traceRemaining_=static_cast<size_t>(bounded(a,"count",100,1,10000));resume(true,DBG_CONTINUE);return state();}
  if(name=="debugger_registers")return registers(static_cast<DWORD>(a.value("thread_id",uint64_t(0))));
  if(name=="debugger_set_register"){auto c=context(static_cast<DWORD>(a.value("thread_id",uint64_t(0))));auto reg=a.at("register").get<std::string>();Address value=address(a.at("value"));DWORD64* field=nullptr;
   if(reg=="rip")field=&c.Rip;else if(reg=="rsp")field=&c.Rsp;else if(reg=="rbp")field=&c.Rbp;else if(reg=="rax")field=&c.Rax;else if(reg=="rbx")field=&c.Rbx;else if(reg=="rcx")field=&c.Rcx;else if(reg=="rdx")field=&c.Rdx;else if(reg=="rsi")field=&c.Rsi;else if(reg=="rdi")field=&c.Rdi;else if(reg=="r8")field=&c.R8;else if(reg=="r9")field=&c.R9;else if(reg=="r10")field=&c.R10;else if(reg=="r11")field=&c.R11;else if(reg=="r12")field=&c.R12;else if(reg=="r13")field=&c.R13;else if(reg=="r14")field=&c.R14;else if(reg=="r15")field=&c.R15;else throw std::runtime_error("Unsupported register name");*field=value;setContext(c,static_cast<DWORD>(a.value("thread_id",uint64_t(0))));return registers(static_cast<DWORD>(a.value("thread_id",uint64_t(0))));}
  if(name=="debugger_threads"){require();Json out=Json::array();for(auto [id,h]:threads_)out.push_back({{"thread_id",id},{"event_thread",id==eventThread_}});return {{"threads",out}};}
  if(name=="debugger_modules"){require();Json out=Json::array();for(auto& [va,module]:modules_)out.push_back(module);return {{"modules",out}};}
  if(name=="debugger_read_memory"){require();Address va=address(a.at("address"));auto data=read(va,static_cast<size_t>(bounded(a,"size",64,1,65536)));return {{"address",hex(va)},{"size",data.size()},{"bytes",bytesText(data.data(),data.size())},{"includes_breakpoints",true}};}
  if(name=="debugger_write_memory"){require(true);Address va=address(a.at("address"));auto data=parseBytes(a.at("bytes").get<std::string>());for(auto [bp,b]:breakpoints_)if(bp>=va&&bp-va<data.size())throw std::runtime_error("Remove overlapping breakpoints before writing memory");write(va,data.data(),data.size());return {{"address",hex(va)},{"written",data.size()},{"runtime_only",true}};}
  if(name=="debugger_breakpoint_add"){require(true);Address va=address(a.at("address"));if(breakpoints_.contains(va))return {{"address",hex(va)},{"existing",true}};if(breakpoints_.size()>=1024)throw std::runtime_error("Breakpoint limit reached");auto data=read(va,1);if(data[0]==0xcc)throw std::runtime_error("Address already contains an INT3 instruction");breakpoints_[va]={data[0],false};try{install(va);}catch(...){breakpoints_.erase(va);throw;}return {{"address",hex(va)},{"installed",true}};}
  if(name=="debugger_breakpoint_remove"){require(true);Address va=address(a.at("address"));auto it=breakpoints_.find(va);if(it==breakpoints_.end())return {{"removed",false}};restore(va);breakpoints_.erase(it);if(hasDisplaced_&&displaced_==va)hasDisplaced_=false;return {{"removed",true}};}
  if(name=="debugger_stack")return stack(a);
  if(name=="debugger_watch_add"){require(true);if(watches_.size()>=128)throw std::runtime_error("Watch limit reached");Watch w;w.address=address(a.at("address"));w.size=static_cast<size_t>(bounded(a,"size",8,1,256));w.previous=read(w.address,w.size);uint64_t id=nextWatch_++;watches_[id]=w;return {{"id",id},{"address",hex(w.address)},{"size",w.size},{"bytes",bytesText(w.previous.data(),w.previous.size())},{"sampling","on debugger stops; not a hardware data breakpoint"}};}
  if(name=="debugger_watches"){require();Json result=Json::array();for(auto& [id,w]:watches_)result.push_back({{"id",id},{"address",hex(w.address)},{"size",w.size},{"last_bytes",bytesText(w.previous.data(),w.previous.size())}});return {{"watches",result},{"sampling","on debugger stops"}};}
  if(name=="debugger_watch_remove")return {{"removed",watches_.erase(a.at("id").get<uint64_t>())!=0}};
  throw std::runtime_error("Unknown debugger operation");
 }
 void loop(){while(!shutdown_){std::deque<std::function<void()>> work;{std::lock_guard lock(queueMutex_);work.swap(queue_);}for(auto& fn:work)fn();if(shutdown_)break;if(active_&&!paused_){DEBUG_EVENT e{};if(WaitForDebugEventEx(&e,10))try{handle(e);}catch(const std::exception& ex){error_=ex.what();pending_=e;paused_=true;reason_="debugger_error";}else if(GetLastError()!=ERROR_SEM_TIMEOUT){error_=failure("WaitForDebugEventEx").what();}}else{std::unique_lock lock(queueMutex_);cv_.wait_for(lock,std::chrono::milliseconds(10),[&]{return !queue_.empty();});}}
  try{detach(false);}catch(...){if(active_)DebugActiveProcessStop(pid_);releaseHandles();}
 }
 public:
 Debugger():worker_([this]{loop();}){}
 ~Debugger(){auto job=std::make_shared<std::packaged_task<Json()>>([this]{shutdown_=true;return Json();});{std::lock_guard lock(queueMutex_);queue_.push_back([job]{(*job)();});}cv_.notify_one();if(worker_.joinable())worker_.join();}
 Json call(const std::string& name,const Json& a){auto task=std::make_shared<std::packaged_task<Json()>>([this,name,a]{return execute(name,a);});auto future=task->get_future();{std::lock_guard lock(queueMutex_);queue_.push_back([task]{(*task)();});}cv_.notify_one();return future.get();}
};
Json textSchema(){return {{"type","string"},{"minLength",1},{"maxLength",32768}};}
Json addrSchema(){return {{"type","string"},{"format","address"},{"minLength",1},{"maxLength",32}};}
Json numberSchema(uint64_t hi){return {{"type","integer"},{"minimum",1},{"maximum",hi}};}
Json definition(const char* name,const char* description,Json props=Json::object(),Json required=Json::array(),bool readOnly=false){return {{"name",name},{"description",description},{"inputSchema",{{"type","object"},{"properties",props},{"required",required},{"additionalProperties",false}}},{"annotations",{{"readOnlyHint",readOnly},{"destructiveHint",!readOnly},{"idempotentHint",readOnly},{"openWorldHint",false}}}};}
} // namespace
Json debuggerTools(){auto addr=addrSchema(),tid=numberSchema(0xffffffff);Json out=Json::array();
 out.push_back(definition("debugger_launch","Execute an explicitly chosen local x64 executable under the debugger. Stops at the initial breakpoint; use debugger_wait. This executes the program.",{{"path",textSchema()},{"arguments",{{"type","array"},{"items",textSchema()},{"maxItems",256}}},{"working_directory",textSchema()}},{"path"}));
 out.push_back(definition("debugger_attach","Attach to an explicitly chosen local x64 process ID. This interrupts the process.",{{"process_id",tid}},{"process_id"}));
 for(auto [name,description,readOnly]:std::vector<std::tuple<const char*,const char*,bool>>{{"debugger_status","Inspect local debug session, stop reason, events and trace.",true},{"debugger_detach","Restore software breakpoints and detach, leaving the debuggee running.",false},{"debugger_terminate","Terminate the active debuggee process. This destroys the debuggee process.",false},{"debugger_pause","Request a debug break; use debugger_wait to await the stop.",false},{"debugger_step","Step one x64 instruction in the stopped event thread; use debugger_wait.",false},{"debugger_threads","List live debuggee threads.",true},{"debugger_modules","List modules observed by the debug event loop.",true},{"debugger_watches","Inspect sampled memory watches; sampling occurs at debugger stops.",true}})out.push_back(definition(name,description,Json::object(),Json::array(),readOnly));
 out.push_back(definition("debugger_wait","Wait up to a bounded timeout for a debugger pause or process exit. Cancellation leaves the debuggee unchanged.",{{"timeout_ms",numberSchema(30000)}},Json::array(),true));
 out.push_back(definition("debugger_continue","Resume stopped process. Pass unhandled exceptions explicitly with pass_exception=true.",{{"pass_exception",{{"type","boolean"}}}}));
 out.push_back(definition("debugger_registers","Read x64 integer registers of a stopped thread.",{{"thread_id",tid}},Json::array(),true));
 out.push_back(definition("debugger_set_register","Change an x64 integer register in a stopped thread.",{{"thread_id",tid},{"register",{{"type","string"},{"enum",{"rip","rsp","rbp","rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"}}}},{"value",addr}},{"register","value"}));
 out.push_back(definition("debugger_read_memory","Read at most 65536 bytes of live debuggee memory; includes installed INT3 breakpoint bytes.",{{"address",addr},{"size",numberSchema(65536)}},{"address"},true));
 out.push_back(definition("debugger_write_memory","Write live process memory while paused; does not edit the binary file. Overlapping breakpoints must first be removed.",{{"address",addr},{"bytes",{{"type","string"},{"minLength",2},{"maxLength",196608}}}},{"address","bytes"}));
 out.push_back(definition("debugger_breakpoint_add","Install a software execution breakpoint at a live address while paused.",{{"address",addr}},{"address"}));
 out.push_back(definition("debugger_breakpoint_remove","Restore the original byte and remove a software breakpoint while paused.",{{"address",addr}},{"address"}));
 out.push_back(definition("debugger_stack","Unwind a stopped x64 thread with Windows unwind metadata and local symbols; no symbol downloads.",{{"thread_id",tid},{"limit",numberSchema(256)}},Json::array(),true));
 out.push_back(definition("debugger_trace","Record up to 10000 instruction-step destinations; pauses when complete. Tracing executes the debuggee.",{{"count",numberSchema(10000)}},Json::array()));
 out.push_back(definition("debugger_watch_add","Add a sampled byte watch, checked on debugger stops. This is not a hardware data breakpoint.",{{"address",addr},{"size",numberSchema(256)}},{"address"}));
 out.push_back(definition("debugger_watch_remove","Remove a sampled byte watch.",{{"id",numberSchema(UINT64_MAX)}},{"id"}));
 return out;
}
std::optional<Json> callDebuggerTool(Engine& e,const std::string& name,const Json& args){bool known=false;for(auto& t:debuggerTools())if(t["name"]==name){known=true;break;}if(!known)return std::nullopt;auto& slot=e.runtimeSlots()["native_debugger"];if(!slot)slot=std::make_shared<Debugger>();auto runtime=std::static_pointer_cast<Debugger>(slot);if(name=="debugger_wait"){auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(bounded(args,"timeout_ms",5000,1,30000));for(;;){auto s=runtime->call("debugger_status",Json::object());if(!s["active"].get<bool>()||s["paused"].get<bool>()){s["timed_out"]=false;return s;}if(e.cancelled()){s["cancelled"]=true;return s;}if(std::chrono::steady_clock::now()>=deadline){s["timed_out"]=true;return s;}std::this_thread::sleep_for(std::chrono::milliseconds(10));}}return runtime->call(name,args);}
} // namespace scratcher

