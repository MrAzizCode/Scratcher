#include "core.hpp"
#include "feature_project.hpp"
#include <fstream>
#include <iostream>
using namespace scratcher;
static void check(bool ok,const char*message){if(!ok)throw std::runtime_error(message);}
int main(){try{
 auto dir=executableDir()/"workspace-fixtures";std::filesystem::create_directories(dir);
 auto raw=dir/"add.bin",project=dir/"notes.scratcher",bad=dir/"invalid.scratcher";
 {std::ofstream out(raw,std::ios::binary);std::vector<char> bytes(64,char(0x90));const char add[]={char(0x89),char(0xf8),char(0x01),char(0xf0),char(0xc3)};std::memcpy(bytes.data(),add,sizeof(add));out.write(bytes.data(),bytes.size());}
 Engine session;session.open(raw);session.setSignature(0x1000,"int add_values(int left, int right);");session.setVariableType(0x1000,"left","unsigned int first;");session.setVariableType(0x1000,"first","unsigned int input;");session.rename(0x1000,"calculate");
 session.setComment(0x1000,"Check addition");session.setBookmark(0x1000,"Start");session.setLabel(0x1001,"operand");session.stagePatch(0x1000,"90");session.saveProject(project);
 auto saved=session.workspaceState();Engine reopened;reopened.loadProject(project);
 check(reopened.workspaceState()==saved,"workspace metadata round trip");auto code=reopened.decompile(0x1000)["code"].get<std::string>();check(code.find("calculate")!=std::string::npos&&code.find("input")!=std::string::npos,"typed and renamed pseudocode survives load");check(reopened.listPatches().size()==1,"staged patch survives load");check(reopened.readBytes(0x1000,1)["hex"]=="89","staging preserves mapped bytes");
 auto data=readProjectFile(project);data["workspace"]["variable_edits"].push_back({{"address","0x1000"},{"name","missing"},{"declaration","int value;"}});writeProjectAtomic(bad,data,raw);bool rejected=false;try{reopened.loadProject(bad);}catch(...){rejected=true;}check(rejected&&reopened.workspaceState()==saved,"malformed project leaves workspace intact");check(reopened.decompile(0x1000)["code"]==code,"malformed project leaves pseudocode intact");
 data["workspace"]=Json::object();data["fingerprint"]["sha256"]=std::string(64,'0');writeProjectAtomic(bad,data,raw);rejected=false;try{reopened.loadProject(bad);}catch(...){rejected=true;}check(rejected&&reopened.workspaceState()==saved,"binary identity mismatch leaves workspace intact");
 check(reopened.disassemble(0x1000,1)[0].bytes=="89 f8","analysis remains usable after rejected project");
 auto otherFile=dir/"other.bin";{std::ofstream out(otherFile,std::ios::binary);std::vector<char> other(64,char(0x90));out.write(other.data(),other.size());}Engine other;other.open(otherFile);check(other.disassemble(0x1000,1)[0].bytes=="90","second workspace decodes own binary");check(reopened.disassemble(0x1000,1)[0].bytes=="89 f8","switching workspaces preserves binary isolation");
 std::cout<<"PASS: typed workspace persistence, patches, atomic load and binary identity\n";return 0;
}catch(const std::exception&e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
