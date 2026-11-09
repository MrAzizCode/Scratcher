#include "feature_search.hpp"
#include <fstream>
#include <iostream>
#include <chrono>
using namespace scratcher;
namespace {
size_t checks=0;
void check(bool value,const char* label) {++checks;if(!value)throw std::runtime_error(label);}
template<class F> void rejects(F f,const char* label) {bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}check(rejected,label);}
void writeFile(const std::filesystem::path& path,const std::vector<uint8_t>& data) {
 std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(data.data()),static_cast<std::streamsize>(data.size()));
 if(!out)throw std::runtime_error("Cannot write search fixture");
}
}
int main() {try {
 const auto directory=executableDir()/"search-fixtures";std::filesystem::create_directories(directory);
 const auto path=directory/"search.bin";
 std::vector<uint8_t> data(200,0);
 data[0]=0xaa;data[1]=0xbb;data[2]=0xaa;data[3]=0xbb;data[4]=0xaa;
 const std::string ascii="Scratcher Hello Strings";
 std::copy(ascii.begin(),ascii.end(),data.begin()+16);
 const std::u16string wide=u"Wide Hello \u03a9 \U0001f680";
 for(size_t i=0;i<wide.size();++i) {data[80+i*2]=static_cast<uint8_t>(wide[i]);data[81+i*2]=static_cast<uint8_t>(wide[i]>>8);}
 data[140]=0x00;data[141]=0xd8; // An unpaired surrogate must not be printable.
 writeFile(path,data);Binary binary(path,0);
 auto found=searchBytePattern(binary,"aa ?? aa",0,1);
 check(found["items"].size()==1,"bounded pattern page");
 check(found["items"][0]["file_offset"]==0,"overlapping first match");
 check(found["items"][0]["address"]=="0x0"&&found["items"][0]["mapped"]==true,"VA zero stays mapped");
 check(found["next_offset"]==1&&found["has_more"]==true,"pattern continuation");
 found=searchBytePattern(binary,"AABBaa",found["next_offset"].get<size_t>(),1);
 check(found["items"][0]["file_offset"]==2,"contiguous bytes and overlapping second match");
 check(searchBytePattern(binary,"FE ED",0)["items"].empty(),"no match");
 check(searchBytePattern(binary,"??",199)["items"][0]["file_offset"]==199,"wildcard at final byte");
 check(searchBytePattern(binary,"?? ??",199)["items"].empty(),"partial pattern at EOF");
 check(searchBytePattern(binary,"AA",200)["next_offset"].is_null(),"EOF cursor");
 rejects([&]{searchBytePattern(binary,"A ?B");},"invalid nibble pattern");
 rejects([&]{searchBytePattern(binary,std::string(514,'A'));},"oversized pattern");
 rejects([&]{searchBytePattern(binary,"AA",201);},"invalid cursor");
 rejects([&]{searchBytePattern(binary,"AA",0,0);},"zero page limit");
 binary.sections.clear();found=searchBytePattern(binary,"AA BB AA",0,1);
 check(found["items"][0]["address"].is_null()&&found["items"][0]["mapped"]==false,"explicit unmapped offset");
 auto strings=discoverStrings(binary,5,0,500,"hello");
 bool narrow=false,utf16=false;
 for(const auto& row:strings["items"]) {
  if(row["encoding"]=="ASCII"&&row["file_offset"]==16) {narrow=true;check(row["text"]==ascii,"ASCII text");check(row["length"]==ascii.size(),"ASCII length");}
  if(row["encoding"]=="UTF-16LE"&&row["file_offset"]==80) {utf16=true;check(row["text"]=="Wide Hello \xce\xa9 \xf0\x9f\x9a\x80","UTF-16 BMP and surrogate UTF-8 conversion");check(row["byte_length"]==wide.size()*2,"UTF-16 byte length");}
 }
 check(narrow&&utf16,"ASCII and Unicode strings with case insensitive filter");
 auto one=discoverStrings(binary,5,0,1,"hello");
 check(one["items"].size()==1&&one["next_offset"]==16+ascii.size(),"string page cursor");
 auto next=discoverStrings(binary,5,one["next_offset"].get<size_t>(),1,"hello");
 check(next["items"].size()==1&&next["items"][0]["file_offset"]==80,"next string page avoids earlier run");
 rejects([&]{discoverStrings(binary,0);},"minimum zero");
 rejects([&]{discoverStrings(binary,4097);},"minimum cap");
 rejects([&]{discoverStrings(binary,5,0,500,std::string(257,'x'));},"query cap");
 const auto largePath=directory/"large.bin";data.assign(17*1024*1024,0);data.back()=0xfe;writeFile(largePath,data);Binary large(largePath);
 found=searchBytePattern(large,"FE");
 check(found["items"].empty()&&found["next_offset"]==16*1024*1024,"pattern window continuation");
 check(searchBytePattern(large,"FE",found["next_offset"].get<size_t>())["items"][0]["file_offset"]==data.size()-1,"search reaches bytes after scan window");
 check(discoverStrings(large)["next_offset"]==16*1024*1024,"string bounded scan");
 const auto repeatedPath=directory/"repeated.bin";data.assign(8192,'A');writeFile(repeatedPath,data);Binary repeated(repeatedPath);
 strings=discoverStrings(repeated);check(strings["items"][0]["length"]==8192&&strings["items"][0]["text"].get<std::string>().size()==4096&&strings["items"][0]["truncated"]==true,"long text cap and original length");
 std::cout<<"PASS: "<<checks<<" search and string discovery checks\n";return 0;
 }catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<": "<<error.what()<<'\n';return 1;}}
