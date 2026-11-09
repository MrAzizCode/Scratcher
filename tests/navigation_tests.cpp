#include "feature_navigation.hpp"
#include <fstream>
#include <iostream>

using namespace scratcher;
namespace {
int checks=0;
void check(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
void target(const Binary& image,const std::string& operands,std::optional<Address> expected,int length=5,Address va=0x1000){
    check(operandTarget(image,{va,length,"MOV",operands,""})==expected,operands.c_str());
}
}
int main(){try{
    NavigationHistory history;
    check(!history.current()&&!history.back()&&!history.forward(),"empty history");
    history.visit(0x1000);history.visit(0x1000);check(!history.canBack(),"duplicate visit coalesces");
    history.visit(0x1010);history.visit(0x1020);
    check(history.back()==0x1010&&history.back()==0x1000&&!history.back(),"back stops at first item");
    check(history.forward()==0x1010&&history.canForward(),"forward restores visited address");
    history.visit(0x1030);check(!history.canForward()&&history.back()==0x1010,"new navigation discards old forward branch");
    history.visit(0x1010);check(history.canForward(),"duplicate current keeps forward branch");
    history.clear();for(Address i=0;i<600;++i)history.visit(i);
    int backCount=0;while(history.back())++backCount;
    check(backCount==511&&history.current()==88,"history is capped at 512 entries");
    history.clear();check(!history.current()&&!history.canBack()&&!history.canForward(),"clear resets cursor");

    const auto root=executableDir()/"navigation-fixtures";std::filesystem::create_directories(root);
    const auto path=root/"addresses.bin";
    {std::ofstream out(path,std::ios::binary);std::string bytes(512,'\x90');out.write(bytes.data(),bytes.size());}
    Binary binary(path);
    binary.sections={{".text",0x1000,0x100,0,0x100,true,false},{".data",0x2000,0x100,0x100,0x80,false,true},{".high",UINT64_MAX-0x20,0x20,0x180,0x20,true,false},{".zero",0,16,0x1a0,16,false,false}};
    binary.functions={{0x1000,0x1020,"start","test"},{0x1040,0,"unknown_end","test"},{0x1060,0x1070,"bounded","test"}};
    binary.imports={{0x2000,"system.dll","read_file"}};
    target(binary,"0x1040",0x1040);target(binary,"short 1040h",0x1040);target(binary,"NEAR 0X1040",0x1040);
    target(binary,"RAX,0x2000",0x2000);target(binary,"RAX, OFFSET 2000h",0x2000);
    target(binary,"qword ptr [0x2000]",0x2000);target(binary,"RAX,qword ptr [RIP + 0xffb]",0x2000);
    target(binary,"[RIP-0x5]",0x1000);target(binary,"[RIP]",0x1005);target(binary,"[EIP + 0x100000ffb]",0x2000);
    target(binary,"[RAX+0x2000]",{});target(binary,"FS:[0x2000]",{});target(binary,"[RIP + RAX*4 + 0xffb]",{});
    target(binary,"RAX",{});target(binary,"0x3000",{});target(binary,"[0x2000],[0x2008]",{});target(binary,"0x1000,0x2000",{});
    target(binary,"0x10000000000000000",{});target(binary,"[RIP+0x20]",{},5,UINT64_MAX-0x10);target(binary,"[RIP-0x1006]",{});
    target(binary,"[RIP]",{},5,UINT64_MAX-1);target(binary,"[RIP]",{},0);target(binary,"0",Address(0));

    auto description=describeAddress(binary,0x1008);
    check(description["mapped"]==true&&description["executable"]==true&&description["section"]["name"]==".text","mapped code metadata");
    check(description["function"]["name"]=="start"&&description["offset"]==8&&description["file_offset"]==8,"function and file offsets");
    check(describeAddress(binary,0x1020)["function"].is_null(),"known function end excludes boundary");
    check(describeAddress(binary,0x1050)["function"]["name"]=="unknown_end","unknown function extends to next function");
    check(describeAddress(binary,0x1080)["function"].is_null(),"unknown function does not cross next bounded function");
    description=describeAddress(binary,0x2004);
    check(description["import"]["name"]=="read_file"&&description["offset"]==4&&description["names"].size()==2,"import slot metadata");
    check(describeAddress(binary,0x2008)["import"].is_null(),"import slot width is bounded");
    check(describeAddress(binary,0x2080)["file_offset"].is_null(),"zero-filled memory has no file offset");
    description=describeAddress(binary,0x3000);
    check(description["mapped"]==false&&description["section"].is_null()&&description["function"].is_null(),"unmapped address metadata");
    std::cout<<"PASS: "<<checks<<" navigation checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
