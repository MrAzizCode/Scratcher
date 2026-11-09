#pragma once
#include "core.hpp"
#include <map>

namespace scratcher {
// Staging never changes the mapped input. Export creates a separate file.
class PatchStore {
 struct Patch {
  Address va=0;
  uint64_t offset=0;
  std::vector<uint8_t> original,bytes;
 };
 std::map<Address,Patch> patches_;
 static Json describe(const Patch& patch);
public:
 Json stage(const Binary& binary,Address va,const std::string& hexBytes);
 Json list()const;
 Json remove(Address va);
 void clear();
 Json exportPatched(const Binary& binary,const std::filesystem::path& destination);
 Json exportState()const;
 void importState(const Binary& binary,const Json& state);
};
}
