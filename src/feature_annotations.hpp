#pragma once
#include "core.hpp"
#include <optional>

namespace scratcher {
// Project-owned address annotations. Access under the same lock as the project.
class AnnotationStore {
 struct Entry { std::string comment, bookmark, label; };
 std::map<Address, Entry> entries_;
 Json row(Address at, const Entry& value) const;
 void eraseIfEmpty(Address at);
public:
 static constexpr size_t maxCommentBytes = 16384;
 static constexpr size_t maxNameBytes = 256;
 static constexpr size_t maxEntries = 100000;
 Json setComment(Address at, const std::string& text);
 Json setBookmark(Address at, const std::string& name);
 Json removeBookmark(Address at);
 Json setLabel(Address at, const std::string& name);
 Json list(std::optional<Address> at = std::nullopt) const;
 Json exportState() const;
 void importState(const Json& state);
 void clear();
};
}
