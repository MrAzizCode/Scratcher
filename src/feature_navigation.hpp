#pragma once
#include "core.hpp"
#include <optional>

namespace scratcher {
class NavigationHistory {
    std::vector<Address> entries_;
    size_t cursor_=0;
public:
    void visit(Address value);
    std::optional<Address> back();
    std::optional<Address> forward();
    std::optional<Address> current()const;
    bool canBack()const;
    bool canForward()const;
    void clear();
};

// Resolve only statically known, mapped destinations. Memory references return
// the effective address, so following an import selects its pointer slot.
std::optional<Address> operandTarget(const Binary& binary,const Instruction& instruction);
Json describeAddress(const Binary& binary,Address value);
}
