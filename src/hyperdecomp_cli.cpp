#include "core.hpp"
#include <windows.h>
#include <iostream>
#include <map>

using namespace scratcher;
namespace {
void writeNew(const std::filesystem::path& path,const std::string& body) {
 // CREATE_NEW enforces the no-overwrite rule atomically, including aliases.
 auto file=CreateFileW(path.c_str(),GENERIC_WRITE|DELETE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create output; existing files are preserved");
 try {
  for(size_t at=0;at<body.size();){DWORD written=0;auto count=static_cast<DWORD>(std::min<size_t>(body.size()-at,1024*1024));
   if(!WriteFile(file,body.data()+at,count,&written,nullptr)||!written)throw std::runtime_error("Cannot write output");at+=written;}
  if(!FlushFileBuffers(file))throw std::runtime_error("Cannot flush output");
 }catch(...){FILE_DISPOSITION_INFO disposition{TRUE};SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof(disposition));CloseHandle(file);throw;}
 if(!CloseHandle(file))throw std::runtime_error("Cannot close output");
}
std::string narrow(const std::wstring& value) {
 if(value.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-xX:")!=std::wstring::npos)
  throw std::runtime_error("Expected an ASCII command, address or numeric option");
 return std::string(value.begin(),value.end());
}
size_t number(const std::wstring& value,size_t low,size_t high) {
 auto text=narrow(value);if(text.empty()||text.find_first_not_of("0123456789")!=std::string::npos)throw std::runtime_error("Expected a decimal integer");
 size_t used=0;auto n=std::stoull(text,&used);if(used!=text.size()||n<low||n>high)throw std::runtime_error("Numeric option is outside its supported range");return static_cast<size_t>(n);
}
void help() {
 std::cout<<"HyperDecomp 0.8 - Scratcher hybrid analysis milestone\n"
  <<"  --gpu-info\n"
  <<"  --inspect <binary>\n"
  <<"  --disassemble <binary> [--address 0xVA] [--count 256]\n"
  <<"  --analyze <binary> [--time-budget-ms 60000]\n"
  <<"  --decompile <binary> --address 0xVA\n"
  <<"  --similarity <binary> --address 0xVA [--mode auto|cpu|cuda] [--top-k 8]\n"
  <<"  --export-fingerprints <binary> [--max-functions 10000]\n"
  <<"All commands emit JSON. Optional --output <new-file.json> writes a new artifact.\n"
  <<"Input binaries are parsed and analyzed, never executed. GPU mode currently\n"
  <<"accelerates fingerprint comparison; decoding and pseudocode run on CPU.\n";
}
}
int wmain(int argc,wchar_t** argv) {
 try {
  if(argc<2||std::wstring(argv[1])==L"--help"){help();return 0;}
  auto command=narrow(argv[1]);
  const bool info=command=="--gpu-info";
  if(!info&&argc<3)throw std::runtime_error("Missing binary path");
  std::map<std::wstring,std::wstring> options;
  for(int i=info?2:3;i<argc;i+=2){if(i+1>=argc)throw std::runtime_error("Missing option value");auto key=std::wstring(argv[i]);
   if(key!=L"--address"&&key!=L"--count"&&key!=L"--time-budget-ms"&&key!=L"--mode"&&key!=L"--top-k"&&key!=L"--max-functions"&&key!=L"--output")throw std::runtime_error("Unknown option");
   if(!options.emplace(key,argv[i+1]).second)throw std::runtime_error("Duplicate option");}
  auto option=[&](const wchar_t* key,const wchar_t* fallback){auto found=options.find(key);return found==options.end()?std::wstring(fallback):found->second;};
  Engine engine;Tools tools(engine);Json result;
  Json metadata;
  if(!info)metadata=tools.call("open_binary",{{"path",pathText(std::filesystem::path(argv[2]))}});
  auto location=[&]{auto value=option(L"--address",L"");if(value.empty())throw std::runtime_error("--address is required for this command");return hex(address(Json(narrow(value))));};
  if(info)result=tools.call("get_acceleration_info",Json::object());
  else if(command=="--inspect")result=metadata;
  else if(command=="--disassemble"){
   auto at=options.contains(L"--address")?location():metadata.at("entry").get<std::string>();
   result=tools.call("disassemble",{{"address",at},{"count",number(option(L"--count",L"256"),1,10000)}});
   result["listing_only"]=true;result["whole_program_recovery_proven"]=false;result["binary"]=metadata;
  }else if(command=="--analyze")result=tools.call("run_auto_analysis",{{"time_budget_ms",number(option(L"--time-budget-ms",L"60000"),1,600000)}});
  else if(command=="--decompile")result=tools.call("decompile",{{"address",location()}});
  else if(command=="--similarity"||command=="--export-fingerprints"){
   auto built=tools.call("build_function_similarity_index",{{"max_functions",number(option(L"--max-functions",L"10000"),1,1000000)}});
   if(command=="--similarity"){
    result=tools.call("find_similar_functions",{{"addresses",Json::array({location()})},{"mode",narrow(option(L"--mode",L"auto"))},{"top_k",number(option(L"--top-k",L"8"),1,16)}});
    result["index"]=built;
   }else{
    Json rows=Json::array();size_t offset=0;for(;;){auto page=tools.call("get_function_similarity_index",{{"offset",offset},{"limit",5000}});
     if(page.value("cache_stale",false))throw std::runtime_error("Index became stale during export");
     for(auto& row:page["items"])rows.push_back(std::move(row));offset+=page["items"].size();if(offset>=page["total"].get<size_t>())break;if(page["items"].empty())throw std::runtime_error("Index pagination stopped early");}
    result={{"items",rows},{"summary",built},{"binary",metadata},{"semantic_equivalence_proven",false}};
   }
  }else throw std::runtime_error("Unknown command; use --help");
  result["hyperdecomp_version"]="0.8.0";result["input_executed"]=false;
  auto output=option(L"--output",L"");
  if(output.empty())std::cout<<result.dump(2)<<'\n';
  else{auto path=std::filesystem::path(output);if(!path.is_absolute()||std::filesystem::exists(path))throw std::runtime_error("Output must be a new absolute path");
   if(!path.parent_path().empty())std::filesystem::create_directories(path.parent_path());writeNew(path,result.dump(2)+'\n');}
  return 0;
 }catch(const std::exception& error){std::cerr<<Json{{"error",error.what()}}.dump()<<'\n';return 1;}
}
