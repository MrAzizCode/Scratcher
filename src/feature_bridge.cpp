#include "feature_bridge.hpp"
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <array>
#include <chrono>
#include <fstream>
#include <thread>

namespace scratcher {
namespace {
constexpr uint32_t maximumFrame=8*1024*1024;
constexpr size_t maximumClients=8;
constexpr DWORD idleTimeout=120000;
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle()=default;
    explicit Handle(HANDLE handle):value(handle){}
    ~Handle(){if(value!=INVALID_HANDLE_VALUE&&value!=nullptr)CloseHandle(value);}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    bool valid()const{return value!=INVALID_HANDLE_VALUE&&value!=nullptr;}
};
[[noreturn]] void fail(const char* message){throw std::runtime_error(std::string(message)+" (Windows error "+std::to_string(GetLastError())+")");}
std::wstring wide(const std::string& text){
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count<=0)throw std::runtime_error("Invalid session text");
    std::wstring result(static_cast<size_t>(count),L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count);
    return result;
}
std::wstring currentSid(){
    Handle token;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))fail("Cannot identify current user");
    DWORD size=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> data(size);
    if(!GetTokenInformation(token.value,TokenUser,data.data(),size,&size))fail("Cannot identify current user");
    LPWSTR sid=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid))fail("Cannot identify current user");
    std::wstring result(sid);LocalFree(sid);return result;
}
struct Security {
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,FALSE};
    Security(){
        const std::wstring sddl=L"D:P(A;;GA;;;"+currentSid()+L")";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))fail("Cannot secure desktop connection");
        attributes.lpSecurityDescriptor=descriptor;
    }
    ~Security(){if(descriptor)LocalFree(descriptor);}
};
uint64_t deadlineAfter(DWORD timeout){return GetTickCount64()+timeout;}
DWORD remaining(uint64_t deadline){auto now=GetTickCount64();return now>=deadline?0:static_cast<DWORD>(deadline-now);}
bool pending(HANDLE pipe,OVERLAPPED& overlapped,HANDLE stop,uint64_t deadline,DWORD& transferred){
    HANDLE events[]={overlapped.hEvent,stop};
    DWORD result=WaitForMultipleObjects(stop?2:1,events,FALSE,remaining(deadline));
    if(result!=WAIT_OBJECT_0){
        CancelIoEx(pipe,&overlapped);
        // Cancelling the pending operation must complete before OVERLAPPED dies.
        GetOverlappedResult(pipe,&overlapped,&transferred,TRUE);
        if(result==WAIT_TIMEOUT)throw std::runtime_error("Desktop request timed out");
        throw std::runtime_error("Desktop connection stopped");
    }
    if(!GetOverlappedResult(pipe,&overlapped,&transferred,FALSE))return false;
    return true;
}
void transfer(HANDLE pipe,void* buffer,DWORD count,bool writing,HANDLE stop,uint64_t deadline){
    auto* bytes=static_cast<unsigned char*>(buffer);
    Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!event.valid())fail("Cannot create desktop connection event");
    while(count){
        if(remaining(deadline)==0)throw std::runtime_error("Desktop request timed out");
        if(stop&&WaitForSingleObject(stop,0)==WAIT_OBJECT_0)throw std::runtime_error("Desktop connection stopped");
        ResetEvent(event.value);OVERLAPPED overlapped{};overlapped.hEvent=event.value;
        DWORD done=0;
        BOOL success=writing?WriteFile(pipe,bytes,count,&done,&overlapped):ReadFile(pipe,bytes,count,&done,&overlapped);
        if(!success){
            if(GetLastError()!=ERROR_IO_PENDING)throw std::runtime_error("Desktop connection closed");
            if(!pending(pipe,overlapped,stop,deadline,done))throw std::runtime_error("Desktop connection closed");
        }
        if(!done)throw std::runtime_error("Desktop connection closed");
        bytes+=done;count-=done;
    }
}
Json receive(HANDLE pipe,HANDLE stop,uint64_t deadline){
    uint32_t length=0;transfer(pipe,&length,sizeof(length),false,stop,deadline);
    if(!length||length>maximumFrame)throw std::runtime_error("Desktop message exceeds the 8 MiB limit");
    std::string body(length,'\0');transfer(pipe,body.data(),length,false,stop,deadline);
    return Json::parse(body,[](int depth,Json::parse_event_t,Json&){
        if(depth>128)throw std::runtime_error("Desktop message nesting exceeds the limit");
        return true;
    });
}
void send(HANDLE pipe,const Json& packet,HANDLE stop,uint64_t deadline){
    auto body=packet.dump();
    if(body.empty()||body.size()>maximumFrame)throw std::runtime_error("Desktop message exceeds the 8 MiB limit");
    uint32_t length=static_cast<uint32_t>(body.size());
    transfer(pipe,&length,sizeof(length),true,stop,deadline);
    transfer(pipe,body.data(),length,true,stop,deadline);
}
bool validId(const std::string& id,DWORD pid){
    auto prefix=std::to_string(pid)+"-";
    if(id.size()!=prefix.size()+32||id.compare(0,prefix.size(),prefix)!=0)return false;
    return std::all_of(id.begin()+static_cast<ptrdiff_t>(prefix.size()),id.end(),[](char ch){return (ch>='0'&&ch<='9')||(ch>='a'&&ch<='f');});
}
bool validEndpoint(const Json& endpoint){
    try{
    if(!endpoint.is_object()||!endpoint.contains("pid")||!endpoint["pid"].is_number_unsigned())return false;
    auto pid=endpoint["pid"].get<uint64_t>();if(!pid||pid>MAXDWORD)return false;
    if(!endpoint.contains("id")||!endpoint["id"].is_string()||!endpoint.contains("pipe")||!endpoint["pipe"].is_string())return false;
    const auto id=endpoint["id"].get<std::string>();
    return validId(id,static_cast<DWORD>(pid))&&endpoint["pipe"]=="\\\\.\\pipe\\Scratcher."+id&&endpoint.value("name",std::string())=="Scratcher"&&endpoint.value("version",std::string())=="0.3.0";
    }catch(...){return false;}
}
bool alive(DWORD pid){
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));
    if(!process.valid())return false;
    DWORD code=0;return GetExitCodeProcess(process.value,&code)&&code==STILL_ACTIVE;
}
std::string makeId(){
    std::array<unsigned char,16> random{};
    if(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("Cannot create desktop session identity");
    const char* digits="0123456789abcdef";
    std::string id=std::to_string(GetCurrentProcessId())+"-";
    for(auto value:random){id+=digits[value>>4];id+=digits[value&15];}return id;
}
bool validRequest(const Json& request){
    return request.is_object()&&request.contains("name")&&request["name"].is_string()&&!request["name"].get_ref<const std::string&>().empty()&&request["name"].get_ref<const std::string&>().size()<=256&&request.contains("arguments")&&request["arguments"].is_object();
}
}

struct BridgeServer::State {
    BridgeHandler handler;
    Json identity;
    std::filesystem::path file;
    Handle stopping{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    std::array<std::unique_ptr<Handle>,maximumClients> pipes;
    std::vector<std::thread> workers;
    std::mutex stopMutex;
    bool stopped=false;
    explicit State(BridgeHandler callback):handler(std::move(callback)){
        if(!stopping.valid())fail("Cannot create desktop connection event");
    }
    void serve(HANDLE pipe){
        while(WaitForSingleObject(stopping.value,0)!=WAIT_OBJECT_0){
            try{
                Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
                if(!event.valid())break;
                OVERLAPPED connect{};connect.hEvent=event.value;DWORD count=0;
                BOOL connected=ConnectNamedPipe(pipe,&connect);
                if(!connected){
                    auto error=GetLastError();
                    if(error==ERROR_IO_PENDING){
                        HANDLE events[]={event.value,stopping.value};
                        DWORD result=WaitForMultipleObjects(2,events,FALSE,INFINITE);
                        if(result!=WAIT_OBJECT_0){CancelIoEx(pipe,&connect);GetOverlappedResult(pipe,&connect,&count,TRUE);break;}
                        if(!GetOverlappedResult(pipe,&connect,&count,FALSE))throw std::runtime_error("Desktop connection closed");
                    }else if(error!=ERROR_PIPE_CONNECTED)throw std::runtime_error("Cannot accept desktop connection");
                }
                auto deadline=deadlineAfter(idleTimeout);
                Json response;
                try{
                    auto request=receive(pipe,stopping.value,deadline);
                    if(!validRequest(request))throw std::runtime_error("Desktop request requires a name and an arguments object");
                    if(WaitForSingleObject(stopping.value,0)==WAIT_OBJECT_0)throw std::runtime_error("Desktop connection stopped");
                    response={{"ok",true},{"result",handler(request)}};
                    if(response.dump().size()>maximumFrame)throw std::runtime_error("Desktop result exceeds the 8 MiB limit");
                }catch(const std::exception& error){
                    // An error must itself be bounded even if a callback emits an enormous message.
                    std::string message=error.what();
                    if(message.size()>4096){
                        size_t limit=4096;
                        while(limit&&((static_cast<unsigned char>(message[limit])&0xc0)==0x80))--limit;
                        message.resize(limit);
                    }
                    try{Json(message).dump();}catch(...){message="Desktop request failed";}
                    response={{"ok",false},{"error",message}};
                }catch(...){response={{"ok",false},{"error","Desktop request failed"}};}
                send(pipe,response,stopping.value,deadlineAfter(idleTimeout));
                // DisconnectNamedPipe discards unread bytes. A bounded acknowledgement
                // keeps the response intact without blocking in FlushFileBuffers.
                unsigned char acknowledgement=0;
                transfer(pipe,&acknowledgement,1,false,stopping.value,deadlineAfter(idleTimeout));
            }catch(...){/* A closed client cannot prevent accepting its successor. */}
            DisconnectNamedPipe(pipe);
        }
    }
    void stop(){
        std::lock_guard lock(stopMutex);
        if(stopped)return;stopped=true;
        SetEvent(stopping.value);
        for(auto& pipe:pipes)if(pipe)CancelIoEx(pipe->value,nullptr);
        for(auto& worker:workers)if(worker.joinable())worker.join();
        // Closing listeners makes a stopped endpoint fail immediately instead of
        // accepting a connection that has no worker left to service it.
        for(auto& pipe:pipes)pipe.reset();
        std::error_code error;if(!file.empty())std::filesystem::remove(file,error);
    }
    ~State(){stop();}
};

BridgeServer::BridgeServer(const std::filesystem::path& endpointDirectory,BridgeHandler handler):state_(std::make_unique<State>(std::move(handler))){
    if(!state_->handler)throw std::runtime_error("Desktop handler is required");
    std::filesystem::create_directories(endpointDirectory);
    if(!std::filesystem::is_directory(endpointDirectory))throw std::runtime_error("Desktop session directory is unavailable");
    const auto id=makeId();const auto pipe="\\\\.\\pipe\\Scratcher."+id;
    state_->identity={{"id",id},{"pipe",pipe},{"pid",static_cast<uint64_t>(GetCurrentProcessId())},{"name","Scratcher"},{"version","0.3.0"},{"transport","local_pipe"},{"max_message_bytes",maximumFrame}};
    Security security;
    auto pipeName=wide(pipe);
    for(size_t index=0;index<maximumClients;++index){
        auto handle=CreateNamedPipeW(pipeName.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|(index==0?FILE_FLAG_FIRST_PIPE_INSTANCE:0),PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,static_cast<DWORD>(maximumClients),65536,65536,0,&security.attributes);
        if(handle==INVALID_HANDLE_VALUE)fail("Cannot create desktop connection");
        state_->pipes[index]=std::make_unique<Handle>(handle);
    }
    // Publish only after all secured instances exist. A unique name avoids replacing
    // another session; readers ignore incomplete or invalid files.
    state_->file=endpointDirectory/std::filesystem::u8path(id+".json");
    auto text=state_->identity.dump();
    Handle file(CreateFileW(state_->file.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&security.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(!file.valid())fail("Cannot publish desktop session");
    DWORD written=0;
    if(!WriteFile(file.value,text.data(),static_cast<DWORD>(text.size()),&written,nullptr)||written!=text.size())fail("Cannot publish desktop session");
    for(auto& handle:state_->pipes)state_->workers.emplace_back([state=state_.get(),pipe=handle->value]{state->serve(pipe);});
}
BridgeServer::~BridgeServer()=default;
void BridgeServer::stop(){state_->stop();}
Json BridgeServer::endpoint()const{return state_->identity;}

Json discoverDesktopSessions(const std::filesystem::path& directory){
    Json items=Json::array();std::error_code error;
    if(!std::filesystem::is_directory(directory,error))return {{"items",items}};
    size_t inspected=0;
    for(std::filesystem::directory_iterator iterator(directory,std::filesystem::directory_options::skip_permission_denied,error),end;iterator!=end&&!error;iterator.increment(error)){
        if(++inspected>4096)break;
        const auto& entry=*iterator;
        auto filename=pathText(entry.path().filename());
        if(filename.size()<39||filename.substr(filename.size()-5)!=".json")continue;
        auto id=filename.substr(0,filename.size()-5);auto dash=id.find('-');
        if(dash==std::string::npos||dash==0||dash>10)continue;
        DWORD pid=0;
        try{auto value=std::stoull(id.substr(0,dash));if(!value||value>MAXDWORD)continue;pid=static_cast<DWORD>(value);}catch(...){continue;}
        if(!validId(id,pid))continue;
        // Never follow directory entries to unrelated files.
        auto status=entry.symlink_status(error);if(error){error.clear();continue;}
        if(!std::filesystem::is_regular_file(status)||std::filesystem::is_symlink(status))continue;
        auto attributes=GetFileAttributesW(entry.path().c_str());if(attributes==INVALID_FILE_ATTRIBUTES||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))continue;
        auto size=entry.file_size(error);if(error||size==0||size>16384){error.clear();continue;}
        try{
            Handle file(CreateFileW(entry.path().c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            if(!file.valid())continue;
            BY_HANDLE_FILE_INFORMATION information{};
            if(!GetFileInformationByHandle(file.value,&information)||(information.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)))continue;
            if(information.nFileSizeHigh||information.nFileSizeLow!=size)continue;
            std::string text(static_cast<size_t>(size),'\0');DWORD read=0;
            if(!ReadFile(file.value,text.data(),static_cast<DWORD>(size),&read,nullptr)||read!=size)continue;
            auto endpoint=Json::parse(text);
            if(!validEndpoint(endpoint)||endpoint["id"]!=id)continue;
            if(!alive(pid)){std::filesystem::remove(entry.path(),error);error.clear();continue;}
            items.push_back(std::move(endpoint));
        }catch(...){/* Malformed or disappearing session files are not sessions. */}
    }
    std::sort(items.begin(),items.end(),[](const Json& left,const Json& right){return left["id"].get<std::string>()<right["id"].get<std::string>();});
    return {{"items",std::move(items)}};
}

Json callDesktopSession(const Json& endpoint,const Json& request,uint32_t timeoutMs){
    if(!validEndpoint(endpoint))throw std::runtime_error("Invalid desktop session endpoint");
    if(!validRequest(request))throw std::runtime_error("Desktop request requires a name and an arguments object");
    if(!timeoutMs||timeoutMs>600000)throw std::runtime_error("Desktop timeout must be between 1 and 600000 milliseconds");
    // Reject excessive requests before touching a transport.
    if(request.dump().size()>maximumFrame)throw std::runtime_error("Desktop message exceeds the 8 MiB limit");
    auto deadline=deadlineAfter(timeoutMs);auto pipeName=wide(endpoint["pipe"].get<std::string>());
    Handle pipe;
    while(!pipe.valid()){
        pipe.value=CreateFileW(pipeName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
        if(pipe.valid())break;
        if(GetLastError()!=ERROR_PIPE_BUSY)throw std::runtime_error("Desktop session is unavailable");
        DWORD wait=remaining(deadline);if(!wait)throw std::runtime_error("Desktop request timed out");
        if(!WaitNamedPipeW(pipeName.c_str(),wait)){
            if(GetLastError()==ERROR_SEM_TIMEOUT)throw std::runtime_error("Desktop request timed out");
            throw std::runtime_error("Desktop session is unavailable");
        }
    }
    ULONG serverPid=0;
    if(!GetNamedPipeServerProcessId(pipe.value,&serverPid)||serverPid!=endpoint["pid"].get<DWORD>())throw std::runtime_error("Desktop session identity changed");
    send(pipe.value,request,nullptr,deadline);
    auto response=receive(pipe.value,nullptr,deadline);
    unsigned char acknowledgement=1;
    transfer(pipe.value,&acknowledgement,1,true,nullptr,deadline);
    if(!response.is_object()||!response.contains("ok")||!response["ok"].is_boolean())throw std::runtime_error("Invalid desktop response");
    if(!response["ok"].get<bool>())throw std::runtime_error(response.value("error",std::string("Desktop request failed")));
    if(!response.contains("result"))throw std::runtime_error("Invalid desktop response");
    return response["result"];
}
}
