#include "core.hpp"
#include <iostream>
#include <algorithm>
namespace {
void printHelp() {
 std::cout<<"Scratcher 0.8.0\n"
  <<"Usage: ScratcherMCP [--mcp | --inspect <binary> | --decompile <binary> <address>]\n"
  <<"  --mcp        Serve MCP requests over standard input/output (default).\n"
  <<"  --desktop ID Attach MCP to an open Scratcher workspace (requires --mcp).\n"
  <<"  --inspect    Print file metadata and section information as JSON.\n"
  <<"  --decompile  Print function pseudocode at a virtual address as JSON.\n"
  <<"  --version    Print the version.\n"
  <<"  --help       Show this help.\n"
  <<"Use absolute file paths. MCP requests run sequentially; close standard input\n"
  <<"to end a session, or terminate the process to stop an active request.\n";
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
 using namespace scratcher;
 try {
  const std::wstring option=argc>1?argv[1]:L"--mcp";
  if(option==L"--help"||option==L"-h"){printHelp();return 0;}
  if(option==L"--version"){std::cout<<"Scratcher 0.8.0\n";return 0;}
  if(option==L"--mcp"&&argc<=2)return runMCP();
  if(option==L"--mcp"&&argc==4&&std::wstring(argv[2])==L"--desktop"){const std::wstring id=argv[3];if(id.empty()||id.size()>128||std::any_of(id.begin(),id.end(),[](wchar_t ch){return ch>127;}))throw std::runtime_error("Invalid desktop identifier");return runMCP(std::string(id.begin(),id.end()));}
  Engine engine;
  if(option==L"--inspect"&&argc==3){std::cout<<engine.open(std::filesystem::path(argv[2])).dump(2)<<'\n';return 0;}
  if(option==L"--decompile"&&argc==4){engine.open(std::filesystem::path(argv[2]));const std::wstring wideAddress=argv[3];const std::string location(wideAddress.begin(),wideAddress.end());std::cout<<engine.decompile(address(Json(location))).dump(2)<<'\n';return 0;}
  std::cerr<<"Invalid arguments. Use ScratcherMCP --help for usage.\n";return 2;
 }catch(const std::exception& exception){std::cerr<<exception.what()<<'\n';return 1;}
}
#else
int main(int argc,char** argv) {
 using namespace scratcher;
 try {
  const std::string option=argc>1?argv[1]:"--mcp";
  if(option=="--help"||option=="-h"){printHelp();return 0;}
  if(option=="--version"){std::cout<<"Scratcher 0.8.0\n";return 0;}
  if(option=="--mcp"&&argc<=2)return runMCP();
  if(option=="--mcp"&&argc==4&&std::string(argv[2])=="--desktop"){const std::string id=argv[3];if(id.empty()||id.size()>128)throw std::runtime_error("Invalid desktop identifier");return runMCP(id);}
  Engine engine;
  if(option=="--inspect"&&argc==3){std::cout<<engine.open(std::filesystem::u8path(argv[2])).dump(2)<<'\n';return 0;}
  if(option=="--decompile"&&argc==4){engine.open(std::filesystem::u8path(argv[2]));std::cout<<engine.decompile(address(Json(argv[3]))).dump(2)<<'\n';return 0;}
  std::cerr<<"Invalid arguments. Use ScratcherMCP --help for usage.\n";return 2;
 }catch(const std::exception& exception){std::cerr<<exception.what()<<'\n';return 1;}
}
#endif
