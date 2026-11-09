#include <windows.h>
#include "core.hpp"
#include "feature_advanced_architectures.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <set>
#include <cctype>
#include <charconv>
#include <iterator>
namespace scratcher {
std::string hex(Address n){char text[18];text[0]='0';text[1]='x';auto converted=std::to_chars(text+2,text+sizeof(text),n,16);return std::string(text,converted.ptr);}
std::string pathText(const std::filesystem::path& p){auto u=p.u8string();return std::string(reinterpret_cast<const char*>(u.data()),u.size());}
Address address(const Json& j){if(j.is_number_unsigned())return j.get<Address>();if(j.is_number_integer()){auto n=j.get<int64_t>();if(n<0)throw std::runtime_error("Address must be nonnegative");return n;}if(!j.is_string())throw std::runtime_error("Expected an address string or integer");auto s=j.get<std::string>();if(s.empty()||s[0]=='-'||s[0]=='+'||std::isspace((unsigned char)s[0]))throw std::runtime_error("Invalid address");size_t used=0;auto v=std::stoull(s,&used,0);if(used!=s.size())throw std::runtime_error("Invalid address");return v;}
std::filesystem::path executableDir(){std::vector<wchar_t> p(32768);auto n=GetModuleFileNameW(nullptr,p.data(),(DWORD)p.size());if(!n||n>=p.size())throw std::runtime_error("Cannot resolve executable directory");return std::filesystem::path(std::wstring(p.data(),n)).parent_path();}
Binary::Binary(const std::filesystem::path& p,Address rawBase,int rawBits):path(std::filesystem::absolute(p)){
 file_=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(file_==INVALID_HANDLE_VALUE){file_=nullptr;throw std::runtime_error("Cannot open binary: "+pathText(path));}
 LARGE_INTEGER n{};if(!GetFileSizeEx(file_,&n)||n.QuadPart<=0){CloseHandle(file_);file_=nullptr;throw std::runtime_error("Binary is empty or unreadable");}size_=n.QuadPart;
 mapping_=CreateFileMappingW(file_,nullptr,PAGE_READONLY,0,0,nullptr);if(mapping_)bytes_=(const uint8_t*)MapViewOfFile(mapping_,FILE_MAP_READ,0,0,0);
 if(!bytes_){if(mapping_)CloseHandle(mapping_);CloseHandle(file_);file_=mapping_=nullptr;throw std::runtime_error("Cannot map binary");}
 try{
  if(size_>=2 && bytes_[0]=='M' && bytes_[1]=='Z')parsePE();
  else if(size_>=4 && std::memcmp(bytes_,"\x7f" "ELF",4)==0)parseELF();
  else if(size_>=4 && std::memcmp(bytes_,"MDMP",4)==0)parseMiniDump();
  else if(parseMachOImage(*this)){}
  else{if(rawBits!=32&&rawBits!=64)throw std::runtime_error("Raw mode supports 32 or 64 bits");if(size_>UINT64_MAX-rawBase)throw std::runtime_error("Raw address range overflow");format="Raw";bits=rawBits;base=entry=rawBase;sections.push_back({"binary",base,size_,0,size_,true,false});}
  if(language.empty())language=std::string("x86:LE:")+std::to_string(bits)+":default:"+((format=="PE"||format=="Minidump")?"windows":"gcc");
  if((format!="PE"||entry!=0)&&(format!="Minidump"||executable(entry))&&!std::any_of(functions.begin(),functions.end(),[&](const Function& f){return f.va==entry&&f.source=="mapped executable start";}))functions.push_back({entry,0,"entry","entry point"});
  std::sort(functions.begin(),functions.end(),[](auto&a,auto&b){if(a.va!=b.va)return a.va<b.va;auto rank=[](const Function&f){return f.source=="export"||f.source=="ELF symbol"||f.source=="Mach-O symbol"?0:f.source=="entry point"?1:f.source=="delay import thunk"?2:f.source=="Guard CF helper pointer"?3:f.source=="unwind metadata"?4:5;};return rank(a)<rank(b);});
  size_t unique=0;for(auto&f:functions){if(unique&&functions[unique-1].va==f.va){if(!functions[unique-1].end&&f.end)functions[unique-1].end=f.end;continue;}if(unique!=size_t(&f-functions.data()))functions[unique]=std::move(f);++unique;}functions.resize(unique);
  std::sort(analysisRanges.begin(),analysisRanges.end());analysisRanges.erase(std::unique(analysisRanges.begin(),analysisRanges.end()),analysisRanges.end());
 }catch(...){UnmapViewOfFile(bytes_);CloseHandle(mapping_);CloseHandle(file_);bytes_=nullptr;file_=mapping_=nullptr;throw;}
}
Binary::~Binary(){if(bytes_)UnmapViewOfFile(bytes_);if(mapping_)CloseHandle(mapping_);if(file_)CloseHandle(file_);}
void Binary::readFileBytes(uint64_t off,uint8_t* out,size_t count)const{
 if(!has(off,count)||(!out&&count))throw std::runtime_error("File read outside binary");
 for(size_t done=0;done<count;){
  uint64_t position=off+done;OVERLAPPED at{};at.Offset=static_cast<DWORD>(position);at.OffsetHigh=static_cast<DWORD>(position>>32);
  DWORD requested=static_cast<DWORD>(std::min<size_t>(count-done,1024*1024)),received=0;
  if(!ReadFile(file_,out+done,requested,&received,&at)||!received)throw std::runtime_error("Cannot read binary for checksum");
  done+=received;
 }
}
std::string Binary::cstring(uint64_t off,size_t limit)const{if(!has(off,1))throw std::runtime_error("String outside file");size_t len=0;while(len<limit && has(off+len,1)&&bytes_[off+len])++len;return std::string((const char*)bytes_+off,len);}
const Section* Binary::section(Address va)const{if(format=="Minidump"){auto it=std::upper_bound(sections.begin(),sections.end(),va,[](Address value,const Section&s){return value<s.va;});if(it==sections.begin())return nullptr;--it;return va-it->va<it->memorySize?&*it:nullptr;}for(auto&s:sections)if(va>=s.va&&va-s.va<s.memorySize)return &s;return nullptr;}
bool Binary::executable(Address va)const{auto*s=section(va);return s&&s->executable;}
void Binary::load(Address va,uint8_t* out,size_t count)const{
 if(count && count-1>UINT64_MAX-va)throw std::runtime_error("Address range overflow");
 for(size_t i=0;i<count;){auto*s=section(va+i);if(!s)throw std::runtime_error("Unmapped address "+hex(va+i));auto delta=va+i-s->va;auto take=(size_t)std::min<uint64_t>(count-i,s->memorySize-delta);auto actual=(size_t)std::min<uint64_t>(take,delta<s->fileSize?s->fileSize-delta:0);if(actual){if(!has(s->offset+delta,actual))throw std::runtime_error("Section outside binary");std::memcpy(out+i,bytes_+s->offset+delta,actual);}std::memset(out+i+actual,0,take-actual);i+=take;}
}
Address Binary::fileToVA(uint64_t off)const{for(auto&s:sections)if(off>=s.offset&&off-s.offset<s.fileSize)return s.va+off-s.offset;return 0;}
void Binary::parsePE(){
 uint64_t pe=read<uint32_t>(0x3c);if(!has(pe,24))throw std::runtime_error("Truncated PE file header");if(read<uint32_t>(pe)!=0x4550)throw std::runtime_error("Invalid PE signature");auto machine=read<uint16_t>(pe+4);if(machine!=0x8664&&machine!=0x14c&&machine!=0xaa64&&machine!=0x1c4)throw std::runtime_error("Unsupported PE CPU type");bits=(machine==0x8664||machine==0xaa64)?64:32;if(machine==0xaa64)language="AARCH64:LE:64:v8A:windows";if(machine==0x1c4)language="ARM:LE:32:v8T:default";
 auto count=read<uint16_t>(pe+6),optSize=read<uint16_t>(pe+20);uint64_t opt=(uint64_t)pe+24;if(optSize<(bits==64?112:96)||!has(opt,optSize))throw std::runtime_error("Truncated PE optional header");auto magic=read<uint16_t>(opt);if((bits==64&&magic!=0x20b)||(bits==32&&magic!=0x10b))throw std::runtime_error("PE machine/header mismatch");base=bits==64?read<uint64_t>(opt+24):read<uint32_t>(opt+28);auto entryRva=read<uint32_t>(opt+16);if(entryRva>UINT64_MAX-base)throw std::runtime_error("PE entry address overflow");entry=entryRva?base+entryRva:0;if(machine==0x1c4)entry&=~Address(1);format="PE";
 auto headers=read<uint32_t>(opt+60);if(headers>size_||headers>UINT64_MAX-base)throw std::runtime_error("PE headers outside file");sections.push_back({"headers",base,headers,0,headers,false,false});
 uint64_t sec=opt+optSize;for(unsigned i=0;i<count;i++){auto off=sec+i*40;if(!has(off,40))throw std::runtime_error("Truncated PE section");char nm[9]{};std::memcpy(nm,bytes_+off,8);auto mem=read<uint32_t>(off+8),rva=read<uint32_t>(off+12),sz=read<uint32_t>(off+16),fo=read<uint32_t>(off+20),flags=read<uint32_t>(off+36);if(!has(fo,sz))throw std::runtime_error("PE section outside file");if(base>UINT64_MAX-rva || std::max(mem,sz)>UINT64_MAX-(base+rva))throw std::runtime_error("PE address overflow");sections.push_back({nm,base+rva,std::max(mem,sz),fo,sz,(flags&0x20000000)!=0,(flags&0x80000000)!=0});}
 auto rvaAddress=[&](uint32_t rva)->Address{if(rva>UINT64_MAX-base)throw std::runtime_error("PE RVA overflow");return base+rva;};
 auto rvaOffset=[&](uint32_t rva)->uint64_t{auto va=rvaAddress(rva);auto*s=section(va);if(!s || va-s->va>=s->fileSize)throw std::runtime_error("PE RVA outside file");return s->offset+(va-s->va);};
 auto candidateRange=[&](Address va){auto*s=section(va);if(s&&va-s->va<s->fileSize&&s->fileSize<=UINT64_MAX-s->va){auto range=std::pair<Address,Address>{s->va,s->va+s->fileSize};if(std::find(analysisRanges.begin(),analysisRanges.end(),range)==analysisRanges.end())analysisRanges.push_back(range);}};
 if(entryRva)candidateRange(entry);
 auto dir=opt+(bits==64?112:96);auto nd=read<uint32_t>(opt+(bits==64?108:92));
 auto directory=[&](unsigned idx){if(idx>=nd||dir+idx*8+8>opt+optSize)return std::pair<uint32_t,uint32_t>{0,0};return std::pair{read<uint32_t>(dir+idx*8),read<uint32_t>(dir+idx*8+4)};};
 // Optional metadata is accepted only from complete, file-backed spans. A
 // malformed auxiliary table must not turn unrelated bytes into function seeds.
 auto mappedOffset=[&](Address va,uint64_t length)->uint64_t{
  auto*s=section(va);if(!s||va-s->va>s->fileSize||length>s->fileSize-(va-s->va))throw std::runtime_error("PE metadata outside file-backed section");
  auto off=s->offset+(va-s->va);if(!has(off,length))throw std::runtime_error("Truncated PE metadata");return off;
 };
 auto boundedName=[&](Address va)->std::string{
  auto*s=section(va);if(!s||va-s->va>=s->fileSize)throw std::runtime_error("PE metadata string outside file-backed section");
  auto available=std::min<uint64_t>(1024,s->fileSize-(va-s->va));auto off=mappedOffset(va,available);
  auto*zero=static_cast<const uint8_t*>(std::memchr(bytes_+off,0,static_cast<size_t>(available)));
  if(!zero)throw std::runtime_error("Unterminated PE metadata string");return std::string(reinterpret_cast<const char*>(bytes_+off),zero-(bytes_+off));
 };
 auto [cfgRva,cfgSize]=directory(10);
 if(cfgRva){
  Json status={{"present",true},{"imported",0},{"suppressed",0},{"export_suppressed",0},{"unmapped",0}};
  try{
   const uint64_t minimum=bits==64?148:92;if(cfgSize<minimum)throw std::runtime_error("Load configuration too short for CFG");
   auto off=mappedOffset(rvaAddress(cfgRva),minimum);auto declared=read<uint32_t>(off);if(declared<minimum)throw std::runtime_error("Load configuration size omits CFG fields");
   Address table=bits==64?read<uint64_t>(off+128):read<uint32_t>(off+80);
   uint64_t targets=bits==64?read<uint64_t>(off+136):read<uint32_t>(off+84);auto flags=read<uint32_t>(off+(bits==64?144:88));
   auto stride=4+((flags>>28)&15);status["entry_count"]=targets;status["stride"]=stride;status["guard_flags"]=flags;
   if(targets>1000000)throw std::runtime_error("Excessive CFG function count");
   if(targets&&(!(flags&0x400)||!table))throw std::runtime_error("CFG table missing presence flag or address");
   if(targets){
    auto tableOff=mappedOffset(table,targets*stride);uint32_t previous=0;
    // Validate ordering before adding anything; the documented GFIDS table is sorted.
    for(uint64_t i=0;i<targets;++i){auto rva=read<uint32_t>(tableOff+i*stride);if(i&&rva<previous)throw std::runtime_error("Unsorted CFG function table");previous=rva;}
    functions.reserve(functions.size()+static_cast<size_t>(targets));
    size_t imported=0,suppressed=0,exportSuppressed=0,unmapped=0;uint32_t last=0;bool haveLast=false;
    for(uint64_t i=0;i<targets;++i){auto at=tableOff+i*stride;auto rva=read<uint32_t>(at);if(haveLast&&rva==last)continue;last=rva;haveLast=true;
     if(!rva||rva>UINT64_MAX-base){++unmapped;continue;}auto va=base+rva;auto*s=section(va);if(!s||va-s->va>=s->fileSize){++unmapped;continue;}
     auto extra=stride>4?read<uint8_t>(at+4):0;const char*source="Guard CF metadata";
     if(extra&1){source="Guard CF suppressed metadata";++suppressed;}else if(extra&2){source="Guard CF export-suppressed metadata";++exportSuppressed;}
     functions.push_back({va,0,"sub_"+hex(va).substr(2),source});if(!(extra&1))candidateRange(va);++imported;
    }
    status["imported"]=imported;status["suppressed"]=suppressed;status["export_suppressed"]=exportSuppressed;status["unmapped"]=unmapped;
   }
   status["valid"]=true;
  }catch(const std::exception&e){status["valid"]=false;status["error"]=e.what();}
  peMetadata["guard_cf"]=std::move(status);
  // These load-configuration fields identify pointer slots, not direct code
  // addresses (Microsoft PE format: PE32 72/76, PE32+ 112/120).
  Json helpers={{"imported",0},{"entries",Json::array()},{"errors",Json::array()}};
  try{
   if(cfgSize<4)throw std::runtime_error("Truncated load configuration size");
   auto configVa=rvaAddress(cfgRva);auto declared=read<uint32_t>(mappedOffset(configVa,4));const uint64_t width=bits/8;
   for(unsigned helper=0;helper<2;++helper){auto field=(bits==64?112u:72u)+helper*static_cast<unsigned>(width);
    if(declared<field+width)continue;const char*name=helper?"_guard_dispatch_icall":"_guard_check_icall";
    try{
     if(cfgSize<field+width)throw std::runtime_error("Load configuration directory omits declared helper pointer");
     auto configOff=mappedOffset(configVa,field+width);Address slot=bits==64?read<uint64_t>(configOff+field):read<uint32_t>(configOff+field);
     if(!slot)continue;auto slotOff=mappedOffset(slot,width);Address target=bits==64?read<uint64_t>(slotOff):read<uint32_t>(slotOff);
     if(!target||target==slot)throw std::runtime_error("Invalid CFG helper target");mappedOffset(target,1);
     functions.push_back({target,0,name,"Guard CF helper pointer"});candidateRange(target);
     helpers["imported"]=helpers["imported"].get<size_t>()+1;helpers["entries"].push_back({{"name",name},{"pointer_slot",hex(slot)},{"target",hex(target)},{"body_validated",false}});
    }catch(const std::exception&e){helpers["errors"].push_back({{"name",name},{"message",e.what()}});}
   }
  }catch(const std::exception&e){helpers["errors"].push_back({{"message",e.what()}});}
  helpers["valid"]=helpers["errors"].empty();peMetadata["guard_cf_helpers"]=std::move(helpers);
 }
 auto [delayRva,delaySize]=directory(13);
 if(delayRva){
  Json status={{"present",true},{"descriptor_count",0},{"imported",0},{"thunk_candidates",0},{"errors",Json::array()}};
  try{
   auto start=mappedOffset(rvaAddress(delayRva),delaySize);if(delaySize<32)throw std::runtime_error("Truncated delay import directory");
   size_t descriptors=0,imported=0,candidates=0;
   for(uint64_t i=0;i+32<=delaySize&&descriptors<4096;i+=32){auto at=start+i;auto attrs=read<uint32_t>(at),name=read<uint32_t>(at+4),iat=read<uint32_t>(at+12),names=read<uint32_t>(at+16);
    bool empty=true;for(unsigned f=0;f<32;f+=4)empty=empty&&!read<uint32_t>(at+f);if(empty)break;++descriptors;
    try{
     if(attrs&~1u)throw std::runtime_error("Reserved delay import attributes");
     auto pointer=[&](uint64_t value)->Address{if(attrs&1){if(value>UINT32_MAX||value>UINT64_MAX-base)throw std::runtime_error("Invalid delay import RVA");return base+value;}return value;};
     if(!name||!iat||!names)throw std::runtime_error("Missing delay import table");
     auto module=boundedName(pointer(name));if(module.empty())throw std::runtime_error("Empty delay import module");
     auto namesVa=pointer(names),iatVa=pointer(iat);auto*nsec=section(namesVa);auto*isec=section(iatVa);
     if(!nsec||!isec||namesVa-nsec->va>=nsec->fileSize||iatVa-isec->va>=isec->fileSize)throw std::runtime_error("Delay import table outside file");
     auto width=static_cast<uint64_t>(bits/8);auto maximum=std::min<uint64_t>({65536,(nsec->fileSize-(namesVa-nsec->va))/width,(isec->fileSize-(iatVa-isec->va))/width});
     auto noff=mappedOffset(namesVa,maximum*width),ioff=mappedOffset(iatVa,maximum*width);bool terminated=false;
     std::vector<Import> pending;std::vector<Function> pendingThunks;
     for(uint64_t k=0;k<maximum;++k){auto v=bits==64?read<uint64_t>(noff+k*width):read<uint32_t>(noff+k*width);if(!v){terminated=true;break;}
      const uint64_t ordinalMask=bits==64?0x8000000000000000ULL:0x80000000ULL;std::string symbol;
      if(v&ordinalMask){if(v&~(ordinalMask|uint64_t(0xffff)))throw std::runtime_error("Invalid delay import ordinal");symbol="ordinal_"+std::to_string(v&0xffff);}
      else{auto hint=pointer(v);mappedOffset(hint,2);if(hint>UINT64_MAX-2)throw std::runtime_error("Delay name address overflow");symbol=boundedName(hint+2);if(symbol.empty())throw std::runtime_error("Empty delay import name");}
      pending.push_back({iatVa+k*width,module,symbol});auto target=bits==64?read<uint64_t>(ioff+k*width):read<uint32_t>(ioff+k*width);
      auto*s=section(target);if(target&&s&&target-s->va<s->fileSize&&target!=iatVa+k*width)pendingThunks.push_back({target,0,"delay_"+symbol,"delay import thunk"});
     }
     if(!terminated)throw std::runtime_error("Unterminated delay import table");imported+=pending.size();candidates+=pendingThunks.size();
     imports.insert(imports.end(),std::make_move_iterator(pending.begin()),std::make_move_iterator(pending.end()));for(auto&f:pendingThunks)candidateRange(f.va);functions.insert(functions.end(),std::make_move_iterator(pendingThunks.begin()),std::make_move_iterator(pendingThunks.end()));
    }catch(const std::exception&e){status["errors"].push_back({{"descriptor",descriptors-1},{"message",e.what()}});}
   }
   status["descriptor_count"]=descriptors;status["imported"]=imported;status["thunk_candidates"]=candidates;status["valid"]=status["errors"].empty();
  }catch(const std::exception&e){status["valid"]=false;status["error"]=e.what();}
  peMetadata["delay_imports"]=std::move(status);
 }
 peMetadata["analysis_range_basis"]="file-backed section candidates from declared entry, unsuppressed Guard CF targets, validated helper pointer targets and delay import thunks; function bodies remain unvalidated";
 auto [pdata,psize]=directory(3);if(pdata&&machine==0x8664){auto off=rvaOffset(pdata);if(!has(off,psize))throw std::runtime_error("Truncated exception directory");for(uint64_t i=0;i+12<=psize;i+=12){auto begin=read<uint32_t>(off+i),end=read<uint32_t>(off+i+4);if(begin&&end>begin&&executable(base+begin))functions.push_back({base+begin,base+end,"sub_"+hex(base+begin).substr(2),"unwind metadata"});}}
 if(pdata&&(machine==0xaa64||machine==0x1c4)){auto off=rvaOffset(pdata);if(psize%8||!has(off,psize))throw std::runtime_error("Invalid ARM exception directory");for(uint64_t i=0;i<psize;i+=8){auto begin=read<uint32_t>(off+i),unwind=read<uint32_t>(off+i+4);if(!begin||!executable(base+begin))continue;auto flag=unwind&3;uint64_t length=0;if(flag==1||flag==2)length=((unwind>>2)&0x7ff)*(machine==0xaa64?4:2);else if(flag==0&&unwind)length=(read<uint32_t>(rvaOffset(unwind))&0x3ffff)*(machine==0xaa64?4:2);else if(flag==3)throw std::runtime_error("Reserved ARM unwind encoding");auto* mapped=section(base+begin);if(length&&mapped&&length<=mapped->memorySize-(base+begin-mapped->va))functions.push_back({base+begin,base+begin+length,"sub_"+hex(base+begin).substr(2),"unwind metadata"});}}
 auto [imp,isize]=directory(1);if(imp){auto off=rvaOffset(imp);for(size_t i=0;i<4096&&i*20+20<=isize;i++){auto d=off+i*20;auto orig=read<uint32_t>(d),name=read<uint32_t>(d+12),iat=read<uint32_t>(d+16);if(!name)break;auto mod=cstring(rvaOffset(name));if(!orig)orig=iat;auto thunk=rvaOffset(orig);for(size_t k=0;k<65536;k++){auto v=bits==64?read<uint64_t>(thunk+k*8):read<uint32_t>(thunk+k*4);if(!v)break;auto ordinalMask=bits==64?0x8000000000000000ULL:0x80000000ULL;auto nm=(v&ordinalMask)?"ordinal_"+std::to_string(v&0xffff):cstring(rvaOffset((uint32_t)v)+2);imports.push_back({base+iat+k*(bits/8),mod,nm});}}}
 auto [exp,esize]=directory(0);if(exp){auto off=rvaOffset(exp);auto names=read<uint32_t>(off+24),funcCount=read<uint32_t>(off+20);if(names>1000000||funcCount>1000000)throw std::runtime_error("Excessive PE exports");auto fs=rvaOffset(read<uint32_t>(off+28)),ns=rvaOffset(read<uint32_t>(off+32)),os=rvaOffset(read<uint32_t>(off+36));for(uint64_t i=0;i<names;i++){auto ordinal=read<uint16_t>(os+i*2);if(ordinal>=funcCount)throw std::runtime_error("Invalid export ordinal");auto rva=read<uint32_t>(fs+ordinal*4);if(rva>=exp&&(uint64_t)rva<((uint64_t)exp+esize))continue;if(executable(base+rva))functions.push_back({base+rva,0,cstring(rvaOffset(read<uint32_t>(ns+i*4))),"export"});}}
}
void Binary::parseELF(){
 auto cls=read<uint8_t>(4);if(cls!=1&&cls!=2)throw std::runtime_error("Invalid ELF class");if(read<uint8_t>(5)!=1)throw std::runtime_error("This build supports little-endian ELF");bits=cls==2?64:32;auto machine=read<uint16_t>(18);if(machine==183&&bits==64)language="AARCH64:LE:64:v8A:default";else if(machine==40&&bits==32)language="ARM:LE:32:v8:default";else if(machine==243)language=std::string("RISCV:LE:")+std::to_string(bits)+(bits==64?":default:gcc":":default:gcc");else if(machine==8)language=std::string("MIPS:LE:")+std::to_string(bits)+":default:default";else if(machine!=(bits==64?62:3))throw std::runtime_error("Unsupported ELF CPU type");format="ELF";
 entry=bits==64?read<uint64_t>(24):read<uint32_t>(24);if(machine==40&&(entry&1)){entry&=~Address(1);language="ARM:LE:32:v8T:default";}auto ph=bits==64?read<uint64_t>(32):read<uint32_t>(28);auto ps=read<uint16_t>(bits==64?54:42),pn=read<uint16_t>(bits==64?56:44);if(ps<(bits==64?56:32))throw std::runtime_error("Invalid ELF program headers");base=UINT64_MAX;
 for(unsigned i=0;i<pn;i++){auto p=ph+(uint64_t)i*ps;if(!has(p,ps))throw std::runtime_error("Truncated ELF segment");if(read<uint32_t>(p)!=1)continue;uint64_t off=bits==64?read<uint64_t>(p+8):read<uint32_t>(p+4),va=bits==64?read<uint64_t>(p+16):read<uint32_t>(p+8),fs=bits==64?read<uint64_t>(p+32):read<uint32_t>(p+16),ms=bits==64?read<uint64_t>(p+40):read<uint32_t>(p+20);auto flags=read<uint32_t>(p+(bits==64?4:24));if(!has(off,fs)||fs>ms||ms>UINT64_MAX-va)throw std::runtime_error("Invalid ELF load segment");sections.push_back({"LOAD_"+std::to_string(i),va,ms,off,fs,(flags&1)!=0,(flags&2)!=0});base=std::min(base,va);}
 if(sections.empty())throw std::runtime_error("ELF has no loadable segments");
 // Symbols from SHT_SYMTAB and SHT_DYNSYM; stripped files still expose entry.
 auto sh=bits==64?read<uint64_t>(40):read<uint32_t>(32);auto ss=read<uint16_t>(bits==64?58:46),sn=read<uint16_t>(bits==64?60:48);if(sn&&(ss<(bits==64?64:40)||!has(sh,uint64_t(ss)*sn)))throw std::runtime_error("Invalid ELF section headers");
 for(unsigned i=0;i<sn;i++){auto p=sh+(uint64_t)i*ss;if(!has(p,ss))throw std::runtime_error("Truncated ELF section header");auto type=read<uint32_t>(p+4);if(type!=2&&type!=11)continue;auto off=bits==64?read<uint64_t>(p+24):read<uint32_t>(p+16),len=bits==64?read<uint64_t>(p+32):read<uint32_t>(p+20),es=bits==64?read<uint64_t>(p+56):read<uint32_t>(p+36);auto link=read<uint32_t>(p+(bits==64?40:24));if(link>=sn||es<(bits==64?24:16)||!has(off,len))throw std::runtime_error("Invalid ELF symbol table");auto strh=sh+(uint64_t)link*ss;auto stroff=bits==64?read<uint64_t>(strh+24):read<uint32_t>(strh+16);for(uint64_t j=0;j+es<=len;j+=es){auto s=off+j;auto info=read<uint8_t>(s+(bits==64?4:12));if((info&15)!=2)continue;auto va=bits==64?read<uint64_t>(s+8):read<uint32_t>(s+4),sz=bits==64?read<uint64_t>(s+16):read<uint32_t>(s+8);if(machine==40)va&=~Address(1);if(sz>UINT64_MAX-va)throw std::runtime_error("ELF symbol address overflow");if(va&&executable(va))functions.push_back({va,va+sz,cstring(stroff+read<uint32_t>(s)),"ELF symbol"});}}
}
std::vector<String> Binary::strings(size_t min,size_t max)const{std::vector<String> out;for(uint64_t i=0;i<size_&&out.size()<max;){auto start=i;while(i<size_&&bytes_[i]>=32&&bytes_[i]<127)++i;if(i-start>=min){auto n=(size_t)std::min<uint64_t>(i-start,4096);out.push_back({fileToVA(start),start,std::string((const char*)bytes_+start,n)});}if(i==start||i<size_)++i;}return out;}
Json Binary::info()const{Json s=Json::array();for(auto&x:sections)s.push_back({{"name",x.name},{"address",hex(x.va)},{"memory_size",x.memorySize},{"file_offset",x.offset},{"file_size",x.fileSize},{"executable",x.executable},{"writable",x.writable}});Json ranges=Json::array();for(auto&range:analysisRanges)ranges.push_back({{"start",hex(range.first)},{"end",hex(range.second)},{"body_validated",false}});return {{"path",pathText(path)},{"format",format},{"bits",bits},{"size",size_},{"base",hex(base)},{"entry",hex(entry)},{"architecture",binaryArchitecture(*this)},{"sections",s},{"function_count",functions.size()},{"import_count",imports.size()},{"pe_metadata",peMetadata},{"analysis_candidate_ranges",ranges}};}
}





