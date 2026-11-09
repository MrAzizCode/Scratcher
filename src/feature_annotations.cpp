#include "feature_annotations.hpp"
#include <stdexcept>

namespace scratcher {
namespace {
// Reject malformed text before it reaches the UI or JSON serialization.
bool validUTF8(const std::string& value) {
 for (size_t i = 0; i < value.size();) {
  unsigned char c = static_cast<unsigned char>(value[i++]);
  if (c < 0x80) { if (!c) return false; continue; }
  unsigned count; uint32_t code, minimum;
  if (c >= 0xc2 && c <= 0xdf) { count=1; code=c&0x1f; minimum=0x80; }
  else if (c >= 0xe0 && c <= 0xef) { count=2; code=c&0x0f; minimum=0x800; }
  else if (c >= 0xf0 && c <= 0xf4) { count=3; code=c&7; minimum=0x10000; }
  else return false;
  if (count > value.size()-i) return false;
  for (unsigned n=0; n<count; ++n) {
   unsigned char next=static_cast<unsigned char>(value[i++]);
   if ((next&0xc0)!=0x80) return false;
   code=(code<<6)|(next&0x3f);
  }
  if (code<minimum || code>0x10ffff || (code>=0xd800 && code<=0xdfff)) return false;
 }
 return true;
}
void validateText(const std::string& text, size_t limit, const char* kind, bool singleLine) {
 if (text.size()>limit) throw std::runtime_error(std::string(kind)+" exceeds "+std::to_string(limit)+" bytes");
 if (!validUTF8(text)) throw std::runtime_error(std::string(kind)+" must contain valid UTF-8 text without NUL characters");
 if (singleLine) for (unsigned char c:text) if (c<32 || c==127)
  throw std::runtime_error(std::string(kind)+" must be a single line without control characters");
}
std::string field(const Json& value, const char* name) {
 if (!value.contains(name)) return {};
 if (!value.at(name).is_string()) throw std::runtime_error(std::string("Annotation ")+name+" must be text");
 return value.at(name).get<std::string>();
}
}
Json AnnotationStore::row(Address at, const Entry& value) const {
 return {{"address",hex(at)},{"comment",value.comment},{"bookmark",value.bookmark},{"label",value.label}};
}
void AnnotationStore::eraseIfEmpty(Address at) {
 auto found=entries_.find(at);
 if (found!=entries_.end() && found->second.comment.empty() && found->second.bookmark.empty() && found->second.label.empty()) entries_.erase(found);
}
Json AnnotationStore::setComment(Address at, const std::string& text) {
 validateText(text,maxCommentBytes,"Comment",false);
 if (!text.empty() && !entries_.contains(at) && entries_.size()>=maxEntries) throw std::runtime_error("Too many annotations");
 if (!text.empty() || entries_.contains(at)) entries_[at].comment=text;
 eraseIfEmpty(at);
 return {{"address",hex(at)},{"comment",text},{"removed",text.empty()}};
}
Json AnnotationStore::setBookmark(Address at, const std::string& name) {
 validateText(name,maxNameBytes,"Bookmark name",true);
 if (!entries_.contains(at) && entries_.size()>=maxEntries) throw std::runtime_error("Too many annotations");
 const auto effective=name.empty()?std::string("Bookmark"):name;
 entries_[at].bookmark=effective;
 return {{"address",hex(at)},{"bookmark",effective}};
}
Json AnnotationStore::removeBookmark(Address at) {
 const auto found=entries_.find(at);
 const bool removed=found!=entries_.end() && !found->second.bookmark.empty();
 if (found!=entries_.end()) found->second.bookmark.clear();
 eraseIfEmpty(at);
 return {{"address",hex(at)},{"removed",removed}};
}
Json AnnotationStore::setLabel(Address at, const std::string& name) {
 validateText(name,maxNameBytes,"Label",true);
 if (!name.empty() && !entries_.contains(at) && entries_.size()>=maxEntries) throw std::runtime_error("Too many annotations");
 if (!name.empty() || entries_.contains(at)) entries_[at].label=name;
 eraseIfEmpty(at);
 return {{"address",hex(at)},{"label",name},{"removed",name.empty()}};
}
Json AnnotationStore::list(std::optional<Address> at) const {
 Json result=Json::array();
 if (at) { auto found=entries_.find(*at); if (found!=entries_.end()) result.push_back(row(found->first,found->second)); }
 else for (const auto& [location,value]:entries_) result.push_back(row(location,value));
 const auto count=result.size();
 return {{"annotations",std::move(result)},{"count",count}};
}
Json AnnotationStore::exportState() const {
 return {{"version",1},{"annotations",list().at("annotations")}};
}
void AnnotationStore::importState(const Json& state) {
 if (!state.is_object() || !state.contains("version") || !state.at("version").is_number_integer() || state.at("version")!=1)
  throw std::runtime_error("Unsupported annotation state version");
 if (!state.contains("annotations") || !state.at("annotations").is_array()) throw std::runtime_error("Annotation state must contain an annotations array");
 const auto& items=state.at("annotations");
 if (items.size()>maxEntries) throw std::runtime_error("Too many annotations");
 AnnotationStore next;
 for (const auto& item:items) {
  if (!item.is_object() || !item.contains("address")) throw std::runtime_error("Annotation must contain an address");
  const auto at=address(item.at("address"));
  if (next.entries_.contains(at)) throw std::runtime_error("Duplicate annotation address");
  Entry value{field(item,"comment"),field(item,"bookmark"),field(item,"label")};
  validateText(value.comment,maxCommentBytes,"Comment",false);
  validateText(value.bookmark,maxNameBytes,"Bookmark name",true);
  validateText(value.label,maxNameBytes,"Label",true);
  next.entries_.emplace(at,std::move(value));
 }
 for (const auto& item:items) next.eraseIfEmpty(address(item.at("address")));
 entries_.swap(next.entries_);
}
void AnnotationStore::clear() { entries_.clear(); }
}
