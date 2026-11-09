#include "feature_bridge.hpp"
#include <windows.h>
#include <aclapi.h>
#include <chrono>
#include <fstream>
#include <future>
#include <iostream>
#include <thread>

using namespace scratcher;
namespace {
int checks=0;
void check(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
template<class F>void rejects(F&& fn,const char* message){bool threw=false;try{fn();}catch(const std::exception&){threw=true;}check(threw,message);}
struct Handle{HANDLE value=INVALID_HANDLE_VALUE;explicit Handle(HANDLE v):value(v){}~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
HANDLE connect(const Json& endpoint){
    auto name=endpoint["pipe"].get<std::string>();std::wstring wideName(name.begin(),name.end());
    return CreateFileW(wideName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
}
void rawWrite(HANDLE handle,const void* data,DWORD length){DWORD done=0;check(WriteFile(handle,data,length,&done,nullptr)&&done==length,"raw transport write");}
Json rawRead(HANDLE handle){DWORD done=0;uint32_t length=0;check(ReadFile(handle,&length,4,&done,nullptr)&&done==4,"raw transport prefix");check(length>0&&length<8*1024*1024,"raw transport response is bounded");std::string body(length,'\0');size_t offset=0;while(offset<length){check(ReadFile(handle,body.data()+offset,static_cast<DWORD>(length-offset),&done,nullptr)&&done>0,"raw transport payload");offset+=done;}return Json::parse(body);}
Json request(const char* name,Json args=Json::object()){return {{"name",name},{"arguments",std::move(args)}};}
}
int main(){try{
    auto directory=executableDir()/std::filesystem::u8path("bridge-fixtures-جلسة-"+std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    std::atomic_int entered=0;std::atomic_bool releaseHeld=false;
    BridgeServer server(directory,[&](const Json& req)->Json{
        auto name=req["name"].get<std::string>();
        if(name=="fail")throw std::runtime_error("Requested failure");
        if(name=="large")return std::string(8*1024*1024,'x');
        if(name=="hold"){++entered;while(!releaseHeld.load())std::this_thread::sleep_for(std::chrono::milliseconds(1));}
        if(name=="slow"){++entered;std::this_thread::sleep_for(std::chrono::milliseconds(200));}
        return req["arguments"];
    });
    auto endpoint=server.endpoint();
    check(endpoint["name"]=="Scratcher"&&endpoint["version"]=="0.3.0","published identity");
    auto discovered=discoverDesktopSessions(directory);
    check(discovered["items"].size()==1&&discovered["items"][0]["id"]==endpoint["id"],"discover running session in Unicode directory");
    // Verify the endpoint ACL grants only the current user rather than Everyone.
    auto endpointPath=directory/std::filesystem::u8path(endpoint["id"].get<std::string>()+".json");
    PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    check(GetNamedSecurityInfoW(endpointPath.c_str(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS,"endpoint security descriptor");
    check(acl&&acl->AceCount==1,"endpoint has one explicit user grant");
    void* ace=nullptr;check(GetAce(acl,0,&ace)!=0,"endpoint access entry");
    check(static_cast<ACE_HEADER*>(ace)->AceType==ACCESS_ALLOWED_ACE_TYPE,"endpoint access grant");
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=0,"current user token");
    DWORD tokenSize=0;GetTokenInformation(token,TokenUser,nullptr,0,&tokenSize);std::vector<unsigned char> tokenData(tokenSize);
    check(GetTokenInformation(token,TokenUser,tokenData.data(),tokenSize,&tokenSize)!=0,"current user identity");
    check(EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart,reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid)!=0,"endpoint ACL belongs to current user");
    CloseHandle(token);LocalFree(descriptor);
    Json unicode={{"text","مرحبا • café 日本語"},{"nested",{{"list",Json::array({1,true,nullptr})}}}};
    check(callDesktopSession(endpoint,request("echo",unicode))==unicode,"Unicode and nested values round trip");
    auto exactError=[&](const char* name,const char* expected){std::string message;try{callDesktopSession(endpoint,request(name),2000);}catch(const std::exception& error){message=error.what();}check(message==expected,expected);};
    exactError("fail","Requested failure");
    exactError("large","Desktop result exceeds the 8 MiB limit");
    rejects([&]{callDesktopSession(endpoint,request("echo",{{"text",std::string(8*1024*1024,'x')}}));},"oversized outgoing request rejected");
    auto forged=endpoint;forged["pipe"]="\\\\.\\pipe\\Other";
    rejects([&]{callDesktopSession(forged,request("echo"));},"arbitrary pipe rejected");
    auto wrongPid=endpoint;wrongPid["pid"]=static_cast<uint64_t>(MAXDWORD);
    rejects([&]{callDesktopSession(wrongPid,request("echo"));},"identity mismatch rejected");
    rejects([&]{callDesktopSession(endpoint,{{"name","echo"},{"arguments",Json::array()}});},"invalid argument shape rejected");
    rejects([&]{callDesktopSession(endpoint,request("echo"),0);},"zero deadline rejected");
    // Write one frame in tiny pieces to exercise partial packet reads.
    {
        Handle pipe(connect(endpoint));check(pipe.value!=INVALID_HANDLE_VALUE,"raw partial client connects");
        auto packet=request("echo",unicode).dump();uint32_t length=static_cast<uint32_t>(packet.size());
        for(size_t offset=0;offset<4;++offset)rawWrite(pipe.value,reinterpret_cast<unsigned char*>(&length)+offset,1);
        for(size_t offset=0;offset<packet.size();offset+=7)rawWrite(pipe.value,packet.data()+offset,static_cast<DWORD>(std::min<size_t>(7,packet.size()-offset)));
        auto response=rawRead(pipe.value);check(response["ok"]==true&&response["result"]==unicode,"partial frame round trip");
        unsigned char ack=1;rawWrite(pipe.value,&ack,1);
    }
    // An oversized inbound length is rejected without allocating its payload.
    {
        Handle pipe(connect(endpoint));check(pipe.value!=INVALID_HANDLE_VALUE,"raw oversized client connects");
        uint32_t length=8*1024*1024+1;rawWrite(pipe.value,&length,4);
        auto response=rawRead(pipe.value);check(response["ok"]==false,"oversized wire frame rejected");
        unsigned char ack=1;rawWrite(pipe.value,&ack,1);
    }
    auto slow=std::async(std::launch::async,[&]{return callDesktopSession(endpoint,request("hold",{{"slow",true}}));});
    auto waitUntil=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!entered.load()&&std::chrono::steady_clock::now()<waitUntil)std::this_thread::yield();
    check(entered.load()>0,"slow callback entered");
    auto fast=std::async(std::launch::async,[&]{return callDesktopSession(endpoint,request("echo",{{"fast",true}}));});
    const bool ready=fast.wait_for(std::chrono::seconds(2))==std::future_status::ready;
    releaseHeld=true;
    check(ready,"parallel request completes while slow callback is held");
    check(fast.get()["fast"]==true,"parallel control while a request runs");
    check(slow.get()["slow"]==true,"slow request completes");
    std::vector<std::future<Json>> clients;
    for(int index=0;index<8;++index)clients.emplace_back(std::async(std::launch::async,[&,index]{return callDesktopSession(endpoint,request("echo",{{"index",index}}));}));
    for(size_t index=0;index<clients.size();++index)check(clients[index].get()["index"]==index,"eight simultaneous clients complete");
    rejects([&]{callDesktopSession(endpoint,request("slow"),20);},"client deadline interrupts a delayed response");
    std::this_thread::sleep_for(std::chrono::milliseconds(220));
    check(callDesktopSession(endpoint,request("echo",{{"recovered",true}}))["recovered"]==true,"timed out client does not poison server");
    // Discovery ignores unrelated, malformed, and linked files; it removes only
    // syntactically valid endpoints belonging to exited processes.
    auto stale=endpoint;stale["pid"]=static_cast<uint64_t>(MAXDWORD);stale["id"]=std::to_string(MAXDWORD)+"-"+std::string(32,'a');stale["pipe"]="\\\\.\\pipe\\Scratcher."+stale["id"].get<std::string>();
    auto stalePath=directory/(stale["id"].get<std::string>()+".json");{std::ofstream stream(stalePath);stream<<stale.dump();}
    auto unrelated=directory/"important.json";{std::ofstream stream(unrelated);stream<<"do not touch";}
    auto malformed=directory/(std::to_string(GetCurrentProcessId())+"-"+std::string(32,'b')+".json");{std::ofstream stream(malformed);stream<<"{}";}
    check(discoverDesktopSessions(directory)["items"].size()==1,"discovery ignores invalid and stale entries");
    check(!std::filesystem::exists(stalePath)&&std::filesystem::exists(unrelated)&&std::filesystem::exists(malformed),"pruning does not delete unrelated files");
    {
        Handle idle(connect(endpoint));check(idle.value!=INVALID_HANDLE_VALUE,"idle client connects");
        uint32_t partial=10;rawWrite(idle.value,&partial,2);
        auto before=std::chrono::steady_clock::now();server.stop();
        check(std::chrono::steady_clock::now()-before<std::chrono::seconds(2),"stop interrupts partial frame and idle accepts");
    }
    check(discoverDesktopSessions(directory)["items"].empty()&&!std::filesystem::exists(endpointPath),"stopped endpoint removed");
    rejects([&]{callDesktopSession(endpoint,request("echo"));},"stopped server rejects client");
    server.stop();check(true,"stop is idempotent");
    std::filesystem::remove(unrelated);std::filesystem::remove(malformed);std::filesystem::remove(directory);
    std::cout<<checks<<" bridge checks passed\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
