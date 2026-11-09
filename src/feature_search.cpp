#include "feature_search.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace scratcher {
namespace {
constexpr uint64_t ScanWindow=16ULL*1024*1024;
constexpr uint64_t ComparisonBudget=32ULL*1024*1024;
constexpr size_t MaximumPattern=256, MaximumResults=500, MaximumText=4096;
struct PatternByte { uint8_t value; bool wildcard; };
int nibble(char c) {
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10;
 return -1;
}
std::vector<PatternByte> parsePattern(const std::string& text) {
 if(text.empty()||text.size()>4096)throw std::runtime_error("Pattern must contain 1 to 256 byte pairs");
 std::vector<PatternByte> pattern;
 for(size_t i=0;i<text.size();) {
  if(std::isspace(static_cast<unsigned char>(text[i]))) {++i;continue;}
  if(i+1>=text.size())throw std::runtime_error("Pattern requires two hex digits or ?? per byte");
  const char a=text[i],b=text[i+1];
  if(a=='?'&&b=='?')pattern.push_back({0,true});
  else {const int hi=nibble(a),lo=nibble(b);if(hi<0||lo<0)throw std::runtime_error("Pattern contains an invalid byte pair");pattern.push_back({static_cast<uint8_t>((hi<<4)|lo),false});}
  if(pattern.size()>MaximumPattern)throw std::runtime_error("Pattern exceeds 256 bytes");
  i+=2;
 }
 if(pattern.empty())throw std::runtime_error("Pattern contains no bytes");
 return pattern;
}
size_t pageLimit(size_t limit) {
 if(limit==0)throw std::runtime_error("Limit must be at least one");
 return std::min(limit,MaximumResults);
}
Json location(const Binary& binary,uint64_t offset) {
 Json row={{"file_offset",offset},{"file_offset_hex",hex(offset)},{"address",nullptr},{"mapped",false}};
 for(const auto& section:binary.sections) {
  if(offset<section.offset)continue;
  const auto delta=offset-section.offset;
  if(delta>=section.fileSize||delta>=section.memorySize||delta>UINT64_MAX-section.va)continue;
  row["address"]=hex(section.va+delta);row["mapped"]=true;row["section"]=section.name;break;
 }
 return row;
}
std::string byteText(const Binary& binary,uint64_t offset,size_t count) {
 static constexpr char digits[]="0123456789ABCDEF";
 count=static_cast<size_t>(std::min<uint64_t>(count,binary.size()-offset));
 std::string out;out.reserve(count*3);
 for(size_t i=0;i<count;++i) {if(i)out+=' ';const auto value=binary.bytes()[offset+i];out+=digits[value>>4];out+=digits[value&15];}
 return out;
}
Json finish(Json items,uint64_t offset,uint64_t next,uint64_t end,size_t limit,
            uint64_t scanned,const char* kind) {
 return {{"items",std::move(items)},{"offset",offset},{"next_offset",next<end?Json(next):Json(nullptr)},
         {"has_more",next<end},{"scanned_bytes",scanned},{"limit",limit},{"kind",kind},
         {"scan_limit_bytes",ScanWindow}};
}
bool ascii(uint8_t c) {return c>=32&&c<127;}
uint16_t word(const uint8_t* bytes,uint64_t pos) {
 return static_cast<uint16_t>(bytes[pos]|(static_cast<uint16_t>(bytes[pos+1])<<8));
}
bool printable(uint32_t cp) {
 return cp>=0x20&&!(cp>=0x7f&&cp<=0x9f)&&!(cp>=0xd800&&cp<=0xdfff)&&
        !(cp>=0xfdd0&&cp<=0xfdef)&&(cp&0xffff)!=0xfffe&&(cp&0xffff)!=0xffff&&cp<=0x10ffff;
}
// Returns zero for a control character, a malformed surrogate, or a short unit.
size_t decode(const uint8_t* bytes,uint64_t pos,uint64_t end,uint32_t& cp) {
 if(pos>=end||end-pos<2)return 0;
 cp=word(bytes,pos);
 if(cp>=0xd800&&cp<=0xdbff) {
  if(end-pos<4)return 0;
  const auto low=word(bytes,pos+2);if(low<0xdc00||low>0xdfff)return 0;
  cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);
  return printable(cp)?4:0;
 }
 return printable(cp)?2:0;
}
void appendUTF8(std::string& out,uint32_t cp) {
 if(cp<0x80)out+=static_cast<char>(cp);
 else if(cp<0x800) {out+=static_cast<char>(0xc0|(cp>>6));out+=static_cast<char>(0x80|(cp&63));}
 else if(cp<0x10000) {out+=static_cast<char>(0xe0|(cp>>12));out+=static_cast<char>(0x80|((cp>>6)&63));out+=static_cast<char>(0x80|(cp&63));}
 else {out+=static_cast<char>(0xf0|(cp>>18));out+=static_cast<char>(0x80|((cp>>12)&63));out+=static_cast<char>(0x80|((cp>>6)&63));out+=static_cast<char>(0x80|(cp&63));}
}
std::string folded(std::string value) {
 for(char& c:value)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return value;
}
class FilterMatcher {
 const std::string& pattern_;std::vector<size_t> prefix_;size_t matched_=0;
public:
 bool found;
 explicit FilterMatcher(const std::string& pattern):pattern_(pattern),prefix_(pattern.size()),found(pattern.empty()) {
  for(size_t i=1,j=0;i<pattern.size();++i) {while(j&&pattern[i]!=pattern[j])j=prefix_[j-1];if(pattern[i]==pattern[j])++j;prefix_[i]=j;}
 }
 void push(char value) {
  if(found)return;if(value>='A'&&value<='Z')value=static_cast<char>(value-'A'+'a');
  while(matched_&&value!=pattern_[matched_])matched_=prefix_[matched_-1];
  if(value==pattern_[matched_])++matched_;if(matched_==pattern_.size())found=true;
 }
};
std::string excerpt(const std::string& text) {
 size_t length=std::min<size_t>(160,text.size());
 while(length<text.size()&&length&&((static_cast<unsigned char>(text[length])&0xc0)==0x80))--length;
 return text.substr(0,length);
}
}

Json searchBytePattern(const Binary& binary,const std::string& text,size_t offset,size_t limit) {
 const auto pattern=parsePattern(text);limit=pageLimit(limit);
 if(offset>binary.size())throw std::runtime_error("Search offset is outside the file");
 const auto start=static_cast<uint64_t>(offset),size=binary.size();
 const auto candidateEnd=size>=pattern.size()?size-pattern.size()+1:0;
 const auto stop=start+std::min<uint64_t>(ScanWindow,candidateEnd>start?candidateEnd-start:0);
 Json items=Json::array();uint64_t cursor=start,comparisons=0;
 size_t anchor=pattern.size();std::vector<size_t> fixed;
 for(size_t i=0;i<pattern.size();++i)if(!pattern[i].wildcard) {anchor=i;fixed.push_back(i);}
 while(cursor<stop&&items.size()<limit) {
  if(anchor<pattern.size()) {
   const auto* found=static_cast<const uint8_t*>(std::memchr(binary.bytes()+cursor+anchor,pattern[anchor].value,static_cast<size_t>(stop-cursor)));
   if(!found) {cursor=stop;break;}
   cursor=static_cast<uint64_t>(found-binary.bytes())-anchor;
  }
  // Stop before a candidate so the continuation never skips a partial match.
  if(comparisons+fixed.size()>ComparisonBudget)break;
  bool match=true;
  for(const auto index:fixed) {++comparisons;if(binary.bytes()[cursor+index]!=pattern[index].value) {match=false;break;}}
  if(match) {
   auto row=location(binary,cursor);row["length"]=pattern.size();
   row["bytes"]=byteText(binary,cursor,std::min<size_t>(pattern.size(),64));
   row["bytes_truncated"]=pattern.size()>64;
   const auto contextStart=cursor>8?cursor-8:0;
   row["excerpt_offset"]=contextStart;row["excerpt"]=byteText(binary,contextStart,48);
   items.push_back(std::move(row));
  }
  ++cursor;
 }
 // No valid candidate exists beyond candidateEnd, including short inputs.
 const auto next=cursor>=candidateEnd?size:cursor;
 auto result=finish(std::move(items),start,next,size,limit,cursor>=start?cursor-start:0,"bytes");
 result["pattern_length"]=pattern.size();result["comparisons"]=comparisons;return result;
}

Json discoverStrings(const Binary& binary,size_t minimum,size_t offset,size_t limit,const std::string& query) {
 if(minimum==0||minimum>4096)throw std::runtime_error("Minimum string length must be between 1 and 4096");
 if(query.size()>256)throw std::runtime_error("String filter exceeds 256 bytes");
 if(offset>binary.size())throw std::runtime_error("String offset is outside the file");
 limit=pageLimit(limit);const auto start=static_cast<uint64_t>(offset),size=binary.size();
 const auto stop=start+std::min<uint64_t>(ScanWindow,size-start);
 const auto* bytes=binary.bytes();const auto filter=folded(query);
 Json items=Json::array();uint64_t cursor=start,continuationCursor=stop;
 uint64_t wideRunEnd[2]={start,start};
 auto add=[&](uint64_t at,uint64_t end,size_t characters,std::string text,const char* encoding,bool continues,bool clipped,bool matches) {
  if(characters<minimum||!matches)return;
  auto row=location(binary,at);row["text"]=std::move(text);row["encoding"]=encoding;
  row["length"]=characters;row["byte_length"]=end-at;row["continues"]=continues;
  row["truncated"]=clipped || continues;
  row["excerpt"]=excerpt(row["text"].get_ref<const std::string&>());items.push_back(std::move(row));
  if(continues)continuationCursor=std::min(continuationCursor,end);
 };
 while(cursor<stop&&items.size()<limit) {
  bool emittedASCII=false;
  if(ascii(bytes[cursor])&&(cursor==start||!ascii(bytes[cursor-1]))) {
   FilterMatcher matcher(filter);auto end=cursor;while(end<stop&&ascii(bytes[end])) {matcher.push(static_cast<char>(bytes[end]));++end;}
   const auto length=end-cursor;
   const auto previousSize=items.size();
   add(cursor,end,static_cast<size_t>(length),std::string(reinterpret_cast<const char*>(bytes+cursor),static_cast<size_t>(std::min<uint64_t>(MaximumText,length))),"ASCII",end==stop&&end<size&&ascii(bytes[end]),length>MaximumText,matcher.found);
   emittedASCII=items.size()!=previousSize;
   if(items.size()==limit) {cursor=end;break;}
  }
  uint32_t cp=0,previous=0;
  const auto unit=decode(bytes,cursor,stop,cp);
  const bool begins=cursor<start+2||decode(bytes,cursor-2,stop,previous)==0||(cp<127&&previous>=127);
  if(!emittedASCII&&cursor>=wideRunEnd[cursor&1]&&begins&&unit) {
   uint64_t end=cursor;size_t length=0,asciiUnits=0;std::string text;text.reserve(128);bool clipped=false;FilterMatcher matcher(filter);
   while(const auto consumed=decode(bytes,end,stop,cp)) {
    ++length;if(cp>=32&&cp<127)++asciiUnits;
    const size_t encoded=cp<0x80?1:cp<0x800?2:cp<0x10000?3:4;
    if(!matcher.found) {std::string character;appendUTF8(character,cp);for(const char value:character)matcher.push(value);}
    if(!clipped&&text.size()+encoded<=MaximumText)appendUTF8(text,cp);else clipped=true;
    end+=consumed;
   }
   wideRunEnd[cursor&1]=end;
   // ASCII evidence or a NUL terminator suppresses arbitrary binary word runs.
   const bool terminated=end<size&&size-end>=2&&word(bytes,end)==0;
   const bool continues=end>=stop-std::min<uint64_t>(stop-start,3)&&end<size&&decode(bytes,end,size,cp)>0;
   if(asciiUnits||terminated)add(cursor,end,length,std::move(text),"UTF-16LE",continues,clipped,matcher.found);
   if(items.size()==limit) {cursor=end;break;}
  }
  ++cursor;
 }
 auto result=finish(std::move(items),start,std::min(cursor,continuationCursor),size,limit,cursor-start,"strings");
 result["minimum"]=minimum;result["query"]=query;result["text_limit_bytes"]=MaximumText;
 return result;
}
}
