#include <windows.h>
#include <dbghelp.h>
#include "core.hpp"
#include <fstream>
#include <iostream>
using namespace scratcher;
int main(){try{
 std::vector<uint8_t> data(4160);
 auto put=[&](size_t offset,const auto& value){std::memcpy(data.data()+offset,&value,sizeof(value));};
 MINIDUMP_HEADER header{};header.Signature=MINIDUMP_SIGNATURE;header.Version=MINIDUMP_VERSION;header.NumberOfStreams=6;header.StreamDirectoryRva=32;put(0,header);
 MINIDUMP_DIRECTORY system{};system.StreamType=SystemInfoStream;system.Location={sizeof(MINIDUMP_SYSTEM_INFO),128};put(32,system);
 MINIDUMP_SYSTEM_INFO cpu{};cpu.ProcessorArchitecture=PROCESSOR_ARCHITECTURE_AMD64;put(128,cpu);
 MINIDUMP_DIRECTORY memory{};memory.StreamType=Memory64ListStream;memory.Location={32,256};put(44,memory);
 put(256,uint64_t(1));put(264,uint64_t(4096));MINIDUMP_MEMORY_DESCRIPTOR64 range{0x140001000,64};put(272,range);
 MINIDUMP_DIRECTORY info{};info.StreamType=MemoryInfoListStream;info.Location={sizeof(MINIDUMP_MEMORY_INFO_LIST)+sizeof(MINIDUMP_MEMORY_INFO),320};put(56,info);
 MINIDUMP_MEMORY_INFO_LIST list{sizeof(MINIDUMP_MEMORY_INFO_LIST),sizeof(MINIDUMP_MEMORY_INFO),1};put(320,list);
 MINIDUMP_MEMORY_INFO protection{};protection.BaseAddress=range.StartOfMemoryRange;protection.RegionSize=64;protection.State=MEM_COMMIT;protection.Protect=PAGE_EXECUTE_READ;put(336,protection);
 MINIDUMP_DIRECTORY threads{};threads.StreamType=ThreadListStream;threads.Location={4+sizeof(MINIDUMP_THREAD),448};put(68,threads);put(448,uint32_t(1));
 MINIDUMP_THREAD thread{};thread.ThreadId=42;thread.ThreadContext={sizeof(CONTEXT),512};put(452,thread);CONTEXT context{};context.Rip=range.StartOfMemoryRange;put(512,context);
 data[4096]=0xb8;data[4097]=42;data[4101]=0xc3;
 const auto path=executableDir()/"fixture.dmp", malformed=executableDir()/"malformed.dmp", writable=executableDir()/"data-only.dmp";
 auto write=[&](const std::filesystem::path& destination){std::ofstream out(destination,std::ios::binary);out.write(reinterpret_cast<const char*>(data.data()),data.size());if(!out)throw std::runtime_error("Cannot write fixture");};write(path);
 {Engine e;auto meta=e.open(path);if(meta["format"]!="Minidump"||meta["entry"]!="0x140001000"||e.readBytes(0x140001000,6)["hex"]!="b82a000000c3")throw std::runtime_error("Captured virtual-memory mapping");
 if(e.disassemble(0x140001000,2).back().mnemonic!="RET")throw std::runtime_error("Dump instruction decoding");
 if(e.decompile(0x140001000)["code"].get<std::string>().find("0x2a")==std::string::npos&&e.decompile(0x140001000)["code"].get<std::string>().find("42")==std::string::npos)throw std::runtime_error("Dump pseudocode");
 put(256,uint64_t(UINT64_MAX));write(malformed);bool rejected=false;try{e.open(malformed);}catch(const std::exception&){rejected=true;}if(!rejected||e.binary()->format!="Minidump")throw std::runtime_error("Malformed dump rejection preserves workspace");
 put(256,uint64_t(1));protection.Protect=PAGE_READWRITE;put(336,protection);write(writable);e.open(writable);if(e.binary()->executable(0x140001000)||e.analyze(100)["executable_bytes"]!=0)throw std::runtime_error("Data protection honored");}
 std::filesystem::remove(path);std::filesystem::remove(malformed);std::filesystem::remove(writable);std::cout<<"PASS: minidump maps, processor, permissions, captured IP, pseudocode and malformed data\n";return 0;
}catch(const std::exception&error){std::cerr<<error.what()<<'\n';return 1;}}
