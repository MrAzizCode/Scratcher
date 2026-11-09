#include "feature_patches.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>

using namespace scratcher;
namespace {
int checks=0;
void check(bool value,const char* label){++checks;if(!value)throw std::runtime_error(label);}
template<class F>void rejects(F action,const char* label){bool failed=false;try{action();}catch(const std::exception&){failed=true;}check(failed,label);}
std::vector<uint8_t> readFile(const std::filesystem::path& path){std::ifstream stream(path,std::ios::binary);return std::vector<uint8_t>(std::istreambuf_iterator<char>(stream),{});}
}
int main(){try {
 auto dir=executableDir()/"patch-fixtures"/std::to_string(GetCurrentProcessId());
 std::filesystem::create_directories(dir);
 const auto source=dir/"source.bin";
 std::vector<uint8_t> data(64);for(size_t i=0;i<data.size();i++)data[i]=static_cast<uint8_t>(i);
 {std::ofstream stream(source,std::ios::binary);stream.write(reinterpret_cast<const char*>(data.data()),data.size());}
 {
  Binary binary(source);
  PatchStore patches;
  auto staged=patches.stage(binary,0x1002,"90 cc AABB");
  check(staged["file_offset"]==2&&staged["size"]==4,"patch address mapped to file");
  check(staged["original"]=="02 03 04 05","original bytes retained");
  check(patches.list().size()==1,"one patch staged");
  check(readFile(source)==data,"staging leaves source unchanged");
  for(auto bad:{"","0","G0","0x90","9 0","90 ?0","90,cc"})
   rejects([&]{patches.stage(binary,0x1010,bad);},"malformed hex rejected");
  rejects([&]{patches.stage(binary,0x1004,"ff");},"virtual overlap rejected");
  rejects([&]{patches.stage(binary,0x0fff,"ff");},"unmapped address rejected");
  rejects([&]{patches.stage(binary,0x103f,"ff ff");},"file boundary rejected");
  rejects([&]{patches.stage(binary,UINT64_MAX,"ff ff");},"address overflow rejected");
  check(patches.list().size()==1,"failed staging preserves patches");
  patches.stage(binary,0x1002,"FF");
  check(patches.list()[0]["size"]==1,"same address patch replaced");
  patches.stage(binary,0x1003,"c3");
  rejects([&]{patches.stage(binary,0x1002,"00 00");},"replacement overlap rejected");
  binary.sections.push_back({"alias",0x2000,16,0,16,true,false});
  rejects([&]{patches.stage(binary,0x2002,"cc");},"aliased file-offset overlap rejected");
  binary.sections.push_back({"zero_fill",0x3000,16,0,0,false,true});
  rejects([&]{patches.stage(binary,0x3000,"cc");},"zero-filled memory rejected");
  auto state=patches.exportState();PatchStore restored;restored.importState(binary,Json::parse(state.dump()));
  check(restored.list()==state,"state round trip");
  auto invalid=state;invalid[0]["original"]="00";
  rejects([&]{restored.importState(binary,invalid);},"original mismatch rejected");
  check(restored.list()==state,"failed state import transactional");
  invalid=state;invalid.push_back(state[0]);
  rejects([&]{restored.importState(binary,invalid);},"duplicate state patch rejected");
  invalid=state;invalid[0]["file_offset"]=999;
  rejects([&]{restored.importState(binary,invalid);},"state offset mismatch rejected");
  invalid=state;invalid[0]["size"]=2;
  rejects([&]{restored.importState(binary,invalid);},"state size mismatch rejected");
  rejects([&]{restored.importState(binary,Json::object());},"invalid state schema rejected");
  rejects([&]{restored.exportPatched(binary,source);},"source destination rejected");
  auto hardlink=dir/"source-link.bin";
  std::filesystem::create_hard_link(source,hardlink);
  rejects([&]{restored.exportPatched(binary,hardlink);},"hardlink destination rejected");
  auto exported=dir/"patched.bin";
  auto result=restored.exportPatched(binary,exported);
  auto expected=data;expected[2]=0xff;expected[3]=0xc3;
  check(readFile(exported)==expected,"copy contains patches and all other bytes");
  check(readFile(source)==data,"export leaves source unchanged");
  check(result["patch_count"]==2&&result["bytes_patched"]==2,"export reports patch count");
  rejects([&]{restored.exportPatched(binary,exported);},"existing destination rejected");
  check(readFile(exported)==expected,"existing destination preserved");
  rejects([&]{restored.exportPatched(binary,dir/"missing"/"output.bin");},"missing parent rejected");
  check(restored.remove(0x1002)["removed"]==true,"remove staged patch");
  check(restored.remove(0x1002)["removed"]==false,"remove missing patch");
  restored.clear();check(restored.list().empty(),"clear patches");
  restored.exportPatched(binary,dir/"unmodified.bin");
  check(readFile(dir/"unmodified.bin")==data,"empty patch set exports exact copy");
  // Contiguous virtual sections backed by contiguous file spans can be patched together.
  binary.sections={{"a",0x4000,8,0,8,true,false},{"b",0x4008,8,8,8,true,false}};
  restored.stage(binary,0x4006,"01 02 03 04");
  check(restored.list()[0]["file_offset"]==6,"contiguous section patch supported");
  binary.sections[1].offset=16;
  rejects([&]{restored.exportPatched(binary,dir/"invalid-map.bin");},"changed section mapping rejected on export");
  restored.clear();
  rejects([&]{restored.stage(binary,0x4006,"01 02 03 04");},"noncontiguous backing rejected");
  size_t temporary=0;for(const auto& entry:std::filesystem::directory_iterator(dir))
   if(entry.path().filename().wstring().starts_with(L".scratcher-patch-"))temporary++;
  check(temporary==0,"temporary export files cleaned up");
 }
 std::filesystem::remove_all(dir);
 std::cout<<"PASS: "<<checks<<" patch checks\n";
 return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
