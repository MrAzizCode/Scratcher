#include "feature_advanced_type_library.hpp"
#include "feature_types.hpp"
#include <fstream>
#include <iostream>
using namespace scratcher;
void check(bool c,const char* m){if(!c)throw std::runtime_error(m);}
int main(){try{
 auto dir=executableDir()/"advanced-type-fixtures";std::filesystem::create_directories(dir);auto path=dir/"typed.bin";
 {std::ofstream out(path,std::ios::binary);char code[]={char(0x48),char(0x89),char(0xf8),char(0xc3)};out.write(code,4);char padding[32]{};out.write(padding,32);}
 Engine e;e.open(path);
 auto call=[&](const std::string& n,Json a=Json::object()){return callTypeLibraryTool(e,n,a).value();};
 auto types=call("import_c_header",{{"text","// Supported aggregate declarations\nstruct Packet { char flag; int value; uint64_t serial; }; union Payload { int small; uint64_t large; }; enum Mode { OFF=0, ON=1 }; typedef struct Packet *PacketPtr; typedef uint8_t Buffer[16];"}});
 check(types["count"]==5,"five types registered");check(types["types"][0]["size"]==16,"struct ABI padding");check(types["types"][0]["fields"][1]["offset"]==4,"struct field offset");check(types["types"][1]["size"]==8,"union layout");check(types["types"][4]["size"]==16,"array layout");
 e.setSignature(0x1000,"PacketPtr inspect_packet(PacketPtr packet);");auto code=e.decompile(0x1000)["code"].get<std::string>();check(code.find("PacketPtr")!=std::string::npos,"aggregate native signature reaches pseudocode");
 e.setVariableType(0x1000,"packet","PacketPtr renamed_packet;");check(e.decompile(0x1000)["code"].get<std::string>().find("renamed_packet")!=std::string::npos,"native type applies to recovered variable");
 bool failed=false;try{call("import_c_header",{{"text","struct Good { int field; }; struct Broken { Missing field; };"}});}catch(...){failed=true;}check(failed,"malformed dependency rejects entire import");check(call("list_types")["count"]==5,"failed import leaves no partial types");
 failed=false;try{call("delete_type",{{"name","Packet"}});}catch(...){failed=true;}check(failed,"referenced type deletion rejected");check(call("list_types")["count"]==5,"deletion preserves library");
 call("define_type",{{"declaration","enum Mode { OFF=0, ON=1, AUTO=2 };"},{"replace",true}});check(call("list_types")["types"][2]["values"].size()==3,"enum edit applied");
 auto lib=dir/"types.json";call("save_type_library",{{"path",pathText(lib)}});Engine loaded;loaded.open(path);callTypeLibraryTool(loaded,"load_type_library",{{"path",pathText(lib)}});check(callTypeLibraryTool(loaded,"list_types",Json::object())->at("count")==5,"type library roundtrip");
 failed=false;try{call("import_c_header",{{"text","#pragma pack(1)\nstruct Packed { int v; };"}});}catch(...){failed=true;}check(failed,"unsupported preprocessor rejected explicitly");
 std::cout<<"PASS: native aggregate layouts, enum/array/typedef, pseudocode signatures and variables, atomic header rejection, dependency-safe edit/delete and library roundtrip\n";return 0;
}catch(const std::exception& ex){std::cerr<<"FAIL: "<<ex.what()<<'\n';return 1;}}
