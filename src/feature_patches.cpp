#include "feature_patches.hpp"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <limits>

namespace scratcher {
namespace {
constexpr size_t maximumPatchBytes=16*1024*1024;
int nibble(char c) {
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10;
 return -1;
}
std::vector<uint8_t> parseBytes(const std::string& text) {
 std::vector<uint8_t> bytes;
 int high=-1;
 for(char c:text) {
  if(std::isspace(static_cast<unsigned char>(c))) {
   if(high>=0)throw std::runtime_error("Hex byte must contain two digits");
   continue;
  }
  int digit=nibble(c);
  if(digit<0)throw std::runtime_error("Patch bytes must be hexadecimal pairs");
  if(high<0)high=digit;
  else {
   if(bytes.size()>=maximumPatchBytes)throw std::runtime_error("Patch exceeds 16 MiB");
   bytes.push_back(static_cast<uint8_t>((high<<4)|digit));high=-1;
  }
 }
 if(high>=0)throw std::runtime_error("Hex byte must contain two digits");
 if(bytes.empty())throw std::runtime_error("Patch must contain at least one byte");
 return bytes;
}
std::string bytesText(const std::vector<uint8_t>& bytes) {
 constexpr char digits[]="0123456789abcdef";
 std::string out;out.reserve(bytes.size()*3);
 for(auto b:bytes) {
  if(!out.empty())out+=' ';
  out+=digits[b>>4];out+=digits[b&15];
 }
 return out;
}
uint64_t fileOffset(const Binary& binary,Address va,size_t count) {
 if(!count||count-1>UINT64_MAX-va)throw std::runtime_error("Patch address range overflow");
 uint64_t first=0;size_t consumed=0;
 while(consumed<count) {
  auto section=binary.section(va+consumed);
  if(!section)throw std::runtime_error("Patch address is unmapped");
  auto delta=va+consumed-section->va;
  if(delta>=section->fileSize)throw std::runtime_error("Patch address has no file bytes");
  if(section->offset>UINT64_MAX-delta)throw std::runtime_error("Patch file offset overflow");
  auto offset=section->offset+delta;
  if(!consumed)first=offset;
  else if(offset!=first+consumed)throw std::runtime_error("Patch crosses noncontiguous file ranges");
  auto take=static_cast<size_t>(std::min<uint64_t>(count-consumed,
   std::min(section->fileSize-delta,section->memorySize-delta)));
  if(!take||!binary.has(offset,take))throw std::runtime_error("Patch extends outside the file");
  consumed+=take;
 }
 if(!binary.has(first,count))throw std::runtime_error("Patch extends outside the file");
 return first;
}
bool overlaps(uint64_t a,size_t as,uint64_t b,size_t bs) {
 // Difference form avoids overflowing the exclusive end address.
 return a<=b ? b-a<as : a-b<bs;
}
class ExportFile {
public:
 HANDLE handle=INVALID_HANDLE_VALUE;
 std::filesystem::path path;
 ~ExportFile(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);if(!path.empty())DeleteFileW(path.c_str());}
 void write(const uint8_t* data,uint64_t count) {
  while(count) {
   auto chunk=static_cast<DWORD>(std::min<uint64_t>(count,1024*1024));
   DWORD written=0;
   if(!WriteFile(handle,data,chunk,&written,nullptr)||written!=chunk)
    throw std::runtime_error("Cannot write patched copy");
   data+=written;count-=written;
  }
 }
};
}
Json PatchStore::describe(const Patch& patch) {
 return {{"address",hex(patch.va)},{"file_offset",patch.offset},{"size",patch.bytes.size()},
  {"original",bytesText(patch.original)},{"bytes",bytesText(patch.bytes)}};
}
Json PatchStore::stage(const Binary& binary,Address va,const std::string& hexBytes) {
 Patch patch;patch.va=va;patch.bytes=parseBytes(hexBytes);
 patch.offset=fileOffset(binary,va,patch.bytes.size());
 for(const auto& [key,existing]:patches_) {
  if(key==va)continue;
  if(overlaps(va,patch.bytes.size(),existing.va,existing.bytes.size())||
     overlaps(patch.offset,patch.bytes.size(),existing.offset,existing.bytes.size()))
   throw std::runtime_error("Patch overlaps an existing patch");
 }
 patch.original.assign(binary.bytes()+patch.offset,binary.bytes()+patch.offset+patch.bytes.size());
 auto result=describe(patch);
 patches_.insert_or_assign(va,std::move(patch));
 return result;
}
Json PatchStore::list()const {
 Json result=Json::array();
 for(const auto& [va,patch]:patches_){(void)va;result.push_back(describe(patch));}
 return result;
}
Json PatchStore::remove(Address va){return {{"address",hex(va)},{"removed",patches_.erase(va)!=0}};}
void PatchStore::clear(){patches_.clear();}
Json PatchStore::exportState()const{return list();}
void PatchStore::importState(const Binary& binary,const Json& state) {
 if(!state.is_array())throw std::runtime_error("Patch state must be an array");
 if(state.size()>100000)throw std::runtime_error("Too many patches in saved state");
 PatchStore restored;
 for(const auto& item:state) {
  if(!item.is_object())throw std::runtime_error("Invalid patch record");
  auto va=address(item.at("address"));
  if(restored.patches_.contains(va))throw std::runtime_error("Duplicate patch address in saved state");
  auto record=restored.stage(binary,va,item.at("bytes").get<std::string>());
  if(!item.contains("original")||parseBytes(item.at("original").get<std::string>())!=restored.patches_.at(va).original)
   throw std::runtime_error("Saved patch original bytes do not match this file");
  if(item.contains("file_offset")&&item.at("file_offset")!=record.at("file_offset"))
   throw std::runtime_error("Saved patch file offset does not match this file");
  if(item.contains("size")&&item.at("size")!=record.at("size"))
   throw std::runtime_error("Saved patch size is inconsistent");
 }
 patches_.swap(restored.patches_);
}
Json PatchStore::exportPatched(const Binary& binary,const std::filesystem::path& destination) {
 if(destination.empty()||destination.filename().empty())throw std::runtime_error("Choose a filename for the patched copy");
 auto target=std::filesystem::absolute(destination).lexically_normal();
 std::error_code ec;
 if(std::filesystem::equivalent(binary.path,target,ec))throw std::runtime_error("Patched copy must use a different file");
 ec.clear();
 auto status=std::filesystem::symlink_status(target,ec);
 if(!ec&&std::filesystem::exists(status))throw std::runtime_error("Patched copy destination already exists");
 if(ec&&ec!=std::errc::no_such_file_or_directory)throw std::runtime_error("Cannot inspect patched copy destination");
 uint64_t total=0;
 for(const auto& [va,patch]:patches_) {
  if(fileOffset(binary,va,patch.bytes.size())!=patch.offset||
     !std::equal(patch.original.begin(),patch.original.end(),binary.bytes()+patch.offset))
   throw std::runtime_error("Staged patches do not match this file");
  total+=patch.bytes.size();
 }
 // CREATE_NEW plus an atomic no-replace rename protects both source and existing files.
 static std::atomic<uint64_t> sequence{0};
 ExportFile output;
 for(int attempt=0;attempt<100;attempt++) {
  output.path=target.parent_path()/(L".scratcher-patch-"+std::to_wstring(GetCurrentProcessId())+L"-"+
   std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence.fetch_add(1))+L".tmp");
  output.handle=CreateFileW(output.path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(output.handle!=INVALID_HANDLE_VALUE)break;
  auto error=GetLastError();output.path.clear();
  if(error!=ERROR_FILE_EXISTS&&error!=ERROR_ALREADY_EXISTS)throw std::runtime_error("Cannot create patched copy");
 }
 if(output.handle==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot allocate temporary patched copy");
 output.write(binary.bytes(),binary.size());
 for(const auto& [va,patch]:patches_) {
  (void)va;LARGE_INTEGER offset;offset.QuadPart=static_cast<LONGLONG>(patch.offset);
  if(!SetFilePointerEx(output.handle,offset,nullptr,FILE_BEGIN))throw std::runtime_error("Cannot seek patched copy");
  output.write(patch.bytes.data(),patch.bytes.size());
 }
 if(!FlushFileBuffers(output.handle))throw std::runtime_error("Cannot flush patched copy");
 if(!CloseHandle(output.handle))throw std::runtime_error("Cannot close patched copy");
 output.handle=INVALID_HANDLE_VALUE;
 if(!MoveFileExW(output.path.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH))throw std::runtime_error("Cannot publish patched copy; destination may already exist");
 output.path.clear();
 return {{"path",pathText(target)},{"patch_count",patches_.size()},{"bytes_patched",total},{"size",binary.size()}};
}
}
