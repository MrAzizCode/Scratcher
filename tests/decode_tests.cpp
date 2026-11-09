#include "core.hpp"
#include "feature_decode.hpp"
#include <fstream>
#include <iostream>
using namespace scratcher;
int main(){try{
 auto path=executableDir()/"decoder-fixture.bin";
 // CALL [RAX+0x1000] must not be mistaken for a direct call to 0x1000.
 const uint8_t bytes[]={0xff,0x90,0x00,0x10,0x00,0x00,0xe8,0x01,0x00,0x00,0x00,0xc3,0xc3,0xe8};
 {std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes),sizeof(bytes));}
 {Engine e;e.open(path);auto rows=e.disassemble(0x1000,20);
 if(rows.size()!=5||rows[0].length!=6||rows[1].length!=5||rows[1].operands.find("100c")==std::string::npos||rows.back().mnemonic!="db")throw std::runtime_error("Bounded decoding and exact branch targets");
 auto partial=e.analyze(1);if(partial["complete"]!=false||partial["functions_added"]!=0||partial["scanned_bytes"]!=6)throw std::runtime_error("Indirect call was indexed or coverage incorrect");
 auto full=e.analyze(20);if(full["functions_added"]!=1||full["invalid_bytes"]!=1||full["complete"]!=true||full["scanned_bytes"]!=sizeof(bytes))throw std::runtime_error("Full direct-call scan");
 if(e.analyze(20)["cached"]!=true)throw std::runtime_error("Scan cache missing");
 std::atomic_bool cancelled=true;e.setCancellation(&cancelled);bool rejected=false;try{e.analyze(20);}catch(const std::exception&){rejected=true;}if(!rejected)throw std::runtime_error("Cancelled cache request accepted");e.setCancellation(nullptr);
 e.open(path,0x1000,32);if(e.disassemble(0x1000,2)[1].length!=5)throw std::runtime_error("x86 decoding");
 if(!e.analyze(0,true)["complete"].get<bool>())throw std::runtime_error("Full scan incorrectly uses a zero budget");
 }
 const auto large=executableDir()/"parallel-decoder.bin";
 std::vector<uint8_t> memory(6*1024*1024,0x90);
 // Three independently indexed 2 MiB ranges, with direct calls spanning each range.
 for(size_t offset=0;offset<memory.size();offset+=2*1024*1024){memory[offset]=0xe8;int32_t relative=64-5;std::memcpy(memory.data()+offset+1,&relative,4);memory[offset+64]=0xc3;}
 {std::ofstream out(large,std::ios::binary);out.write(reinterpret_cast<const char*>(memory.data()),memory.size());}
 {Binary binary(large);for(size_t offset=0;offset<memory.size();offset+=2*1024*1024)binary.functions.push_back({0x1000+offset,0x1000+offset+65,"block","ELF symbol"});
 std::sort(binary.functions.begin(),binary.functions.end(),[](auto&a,auto&b){return a.va<b.va;});
 std::vector<Function> serial,parallel;auto noCancel=[]{return false;};
 auto first=scanDirectCalls(binary,SIZE_MAX,serial,noCancel,false),second=scanDirectCalls(binary,SIZE_MAX,parallel,noCancel,true);
 if(first["scanned_bytes"]!=second["scanned_bytes"]||first["instructions_examined"]!=second["instructions_examined"]||second["parallel_workers"].get<size_t>()<2||serial.size()!=parallel.size()||serial.size()!=3)throw std::runtime_error("Parallel scan differs from serial coverage or discovery");
 for(size_t i=0;i<serial.size();++i)if(serial[i].va!=parallel[i].va)throw std::runtime_error("Parallel targets differ");
 }
 std::filesystem::remove(large);
 const auto prefixed=executableDir()/"prefixed-return.bin";{std::ofstream out(prefixed,std::ios::binary);const uint8_t code[]={0xf3,0xc3,0xf3,0xa4};out.write(reinterpret_cast<const char*>(code),sizeof(code));}
 {Engine e;e.open(prefixed);auto rows=e.disassemble(0x1000,2);auto&row=rows.at(0);if(row.mnemonic!="RET"||row.operands!=""||row.length!=2||rows.at(1).mnemonic!="MOVSB"||rows.at(1).prefixes!="REP")throw std::runtime_error("Instruction prefix obscures canonical flow");auto graph=e.controlFlow(0x1000,8);if(graph["instruction_count"]!=1||graph["nodes"][0]["exit"]!="return")throw std::runtime_error("Prefixed return graph traversal");}
 std::filesystem::remove(prefixed);
 std::filesystem::remove(path);std::cout<<"PASS: decode bounds, x86/x64, direct calls, coverage, caching and cancellation\n";return 0;
}catch(const std::exception&error){std::cerr<<error.what()<<'\n';return 1;}}
