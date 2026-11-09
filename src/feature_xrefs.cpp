#include "feature_xrefs.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <tuple>

namespace scratcher {
namespace {
std::string compactUpper(const std::string& value) {
    std::string out;
    for (unsigned char c : value)
        if (!std::isspace(c)) out.push_back(static_cast<char>(std::toupper(c)));
    return out;
}

std::optional<Address> literal(const std::string& value) {
    const auto text = compactUpper(value);
    if (text.empty()) return {};
    size_t start = 0;
    int radix = 10;
    if (text.size() > 2 && text[0] == '0' && text[1] == 'X') {
        start = 2;
        radix = 16;
    }
    if (start == text.size()) return {};
    Address result = 0;
    for (size_t i = start; i < text.size(); ++i) {
        const char c = text[i];
        const unsigned digit = c >= '0' && c <= '9' ? unsigned(c - '0') :
            c >= 'A' && c <= 'F' ? unsigned(c - 'A' + 10) : 255;
        if (digit >= unsigned(radix) || result > (UINT64_MAX - digit) / radix) return {};
        result = result * radix + digit;
    }
    return result;
}

// These are fixed effective addresses, not the pointer value stored there.
std::optional<Address> memoryAddress(const Instruction& instruction) {
    const auto text = compactUpper(instruction.operands);
    const auto begin = text.find('[');
    const auto end = text.find(']', begin);
    if (begin == std::string::npos || end == std::string::npos ||
        text.find('[', begin + 1) != std::string::npos) return {};
    // Segment-relative addresses require runtime state; even a literal offset
    // must not be presented as an address in the binary's flat mapping.
    if (text.find(':') != std::string::npos) return {};
    const auto expression = text.substr(begin + 1, end - begin - 1);
    if (auto absolute = literal(expression)) return absolute;
    const bool eip = expression.compare(0, 3, "EIP") == 0;
    if (!eip && expression.compare(0, 3, "RIP") != 0) return {};
    if (instruction.length <= 0 || Address(instruction.length) > UINT64_MAX - instruction.va) return {};
    Address pc = instruction.va + Address(instruction.length);
    if (eip) pc &= 0xffffffffULL;
    if (expression.size() == 3) return pc;
    if (expression.size() < 5 || (expression[3] != '+' && expression[3] != '-')) return {};
    const auto delta = literal(expression.substr(4));
    if (!delta) return {};
    if (eip) return (expression[3] == '+' ? pc + *delta : pc - *delta) & 0xffffffffULL;
    if (expression[3] == '+') {
        if (*delta > UINT64_MAX - pc) return {};
        return pc + *delta;
    }
    if (*delta > pc) return {};
    return pc - *delta;
}

bool isJump(const std::string& mnemonic) {
    return (!mnemonic.empty() && mnemonic[0] == 'J') || mnemonic == "LOOP" ||
        mnemonic == "LOOPE" || mnemonic == "LOOPNE" || mnemonic == "LOOPZ" || mnemonic == "LOOPNZ";
}

struct FunctionLookup {
    const Binary& binary;
    std::vector<const Function*> sorted;
    explicit FunctionLookup(const Binary& image) : binary(image) {
        for (const auto& function : binary.functions) sorted.push_back(&function);
        std::sort(sorted.begin(), sorted.end(), [](auto a, auto b) { return a->va < b->va; });
    }
    const Function* at(Address va) const {
        auto position = std::upper_bound(sorted.begin(), sorted.end(), va,
            [](Address value, const Function* function) { return value < function->va; });
        if (position == sorted.begin()) return nullptr;
        const auto* function = *std::prev(position);
        if (function->end > function->va) return va < function->end ? function : nullptr;
        // Missing boundaries are limited to the containing executable section.
        const auto* section = binary.section(va);
        return section && section->executable && binary.section(function->va) == section ? function : nullptr;
    }
};

struct ScanRange { Address start, end; };
std::vector<ScanRange> ranges(const Binary& binary) {
    std::vector<ScanRange> result;
    for (const auto& section : binary.sections) {
        const uint64_t size = std::min(section.fileSize, section.memorySize);
        if (!section.executable || !size || size > UINT64_MAX - section.va) continue;
        result.push_back({section.va, section.va + size});
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.start < b.start; });
    std::vector<ScanRange> merged;
    for (const auto& range : result) {
        if (!merged.empty() && range.start < merged.back().end)
            merged.back().end = std::max(merged.back().end, range.end);
        else merged.push_back(range);
    }
    return merged;
}
}

Json collectCrossReferences(Engine& engine, size_t instructionBudget) {
    if (instructionBudget > 1000000) throw std::runtime_error("Reference scan budget exceeds 1000000 instructions");
    const auto* binary = engine.binary();
    if (!binary) throw std::runtime_error("Open a binary first");
    if (engine.cancelled()) throw std::runtime_error("Operation cancelled");
    const auto start = std::chrono::steady_clock::now();
    const FunctionLookup functions(*binary);
    std::map<Address, const Import*> imports;
    for (const auto& item : binary->imports) imports[item.va] = &item;
    Json items = Json::array();
    std::set<std::tuple<Address, Address, std::string>> seen;
    size_t examined = 0, skippedRanges = 0;
    uint64_t scannedBytes = 0, executableBytes = 0;
    bool stopped = false;
    const auto scanRanges = ranges(*binary);
    for (const auto& range : scanRanges) executableBytes += range.end - range.start;

    auto add = [&](const Instruction& instruction, Address target, const std::string& kind) {
        if (!seen.emplace(instruction.va, target, kind).second) return;
        const auto* function = functions.at(instruction.va);
        Json row = {{"from", hex(instruction.va)}, {"to", hex(target)},
            {"source", hex(instruction.va)}, {"target", hex(target)}, {"kind", kind},
            {"mnemonic", instruction.mnemonic}, {"operands", instruction.operands},
            {"function_address", function ? Json(hex(function->va)) : Json(nullptr)},
            {"function_name", function ? function->name : ""},
            {"function_range_inferred", function && function->end <= function->va}};
        if (auto found = imports.find(target); found != imports.end()) {
            row["target_name"] = found->second->name;
            row["target_module"] = found->second->module;
        }
        items.push_back(std::move(row));
    };

    for (const auto& range : scanRanges) {
        Address cursor = range.start;
        while (cursor < range.end && examined < instructionBudget) {
            if (engine.cancelled()) throw std::runtime_error("Operation cancelled");
            // Batch decoding reduces translation setup and keeps the scan bounded.
            auto instructions = engine.disassemble(cursor, std::min<size_t>(256, instructionBudget - examined));
            if (instructions.empty()) { ++skippedRanges; stopped = true; break; }
            const Address previous = cursor;
            for (const auto& instruction : instructions) {
                if (engine.cancelled()) throw std::runtime_error("Operation cancelled");
                if (instruction.va < cursor) continue;
                if (instruction.va >= range.end || instruction.length <= 0 ||
                    Address(instruction.length) > range.end - instruction.va) break;
                cursor = instruction.va + Address(instruction.length);
                ++examined;
                scannedBytes += Address(instruction.length);
                const auto mnemonic = compactUpper(instruction.mnemonic);
                if (mnemonic == "DB") continue;
                const bool call = mnemonic == "CALL";
                const bool jump = isJump(mnemonic);
                if (call || jump) {
                    if (const auto target = literal(instruction.operands)) {
                        // A direct transfer may leave this image; retain its exact destination.
                        add(instruction, *target, call ? "call" : "jump");
                        continue;
                    }
                }
                if (const auto target = memoryAddress(instruction); target && binary->section(*target)) {
                    const bool imported = imports.find(*target) != imports.end();
                    add(instruction, *target, imported && call ? "import_call" : imported && jump ?
                        "import_jump" : mnemonic == "LEA" ? "data_address" : "data");
                }
                // A literal loaded into a register or pushed is reported only
                // when it names mapped memory. Arithmetic constants are excluded.
                if ((mnemonic == "MOV" || mnemonic == "MOVABS" || mnemonic == "PUSH") &&
                    instruction.operands.find('[') == std::string::npos) {
                    const auto comma = instruction.operands.find_last_of(',');
                    const auto operand = comma == std::string::npos ? instruction.operands : instruction.operands.substr(comma + 1);
                    if (const auto target = literal(operand); target && binary->section(*target))
                        add(instruction, *target, "data_address");
                }
            }
            if (cursor == previous) { stopped = true; ++skippedRanges; break; }
        }
    }
    const bool truncated = stopped || scannedBytes < executableBytes;
    return {{"items", std::move(items)}, {"instructions_examined", examined},
        {"instruction_budget", instructionBudget}, {"bytes_scanned", scannedBytes},
        {"executable_bytes", executableBytes}, {"truncated", truncated},
        {"budget_exhausted", truncated && examined >= instructionBudget},
        {"skipped_ranges", skippedRanges},
        {"elapsed_ms", std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count()}};
}

Json referencesAt(const Json& index, Address target, bool outgoing) {
    Json result = Json::array();
    const char* field = outgoing ? "from" : "to";
    for (const auto& item : index.at("items"))
        if (address(item.at(field)) == target) result.push_back(item);
    const auto count = result.size();
    return {{"address", hex(target)}, {"direction", outgoing ? "outgoing" : "incoming"},
        {"items", std::move(result)}, {"total", count}, {"truncated", index.value("truncated", false)}};
}

Json buildCallGraph(const Json& index, const Binary& binary) {
    std::map<Address, Json> nodes;
    for (const auto& function : binary.functions)
        nodes[function.va] = {{"address", hex(function.va)}, {"name", function.name}, {"kind", "function"}};
    std::map<Address, const Import*> imports;
    for (const auto& item : binary.imports) imports[item.va] = &item;
    std::map<std::pair<Address, Address>, Json> grouped;
    auto node = [&](Address va, bool imported, bool source) {
        if (nodes.find(va) != nodes.end()) return;
        const auto found = imports.find(va);
        if (imported && found != imports.end())
            nodes[va] = {{"address", hex(va)}, {"name", found->second->name}, {"module", found->second->module}, {"kind", "import"}};
        else nodes[va] = {{"address", hex(va)}, {"name", "sub_" + hex(va).substr(2)},
            {"kind", source ? "location" : binary.executable(va) ? "function" : "external"}};
    };
    for (const auto& item : index.at("items")) {
        const auto kind = item.at("kind").get<std::string>();
        if (kind != "call" && kind != "import_call") continue;
        const Address site = address(item.at("from"));
        const Address from = item.at("function_address").is_null() ? site : address(item.at("function_address"));
        const Address to = address(item.at("to"));
        node(from, false, true);
        node(to, kind == "import_call", false);
        auto [position, inserted] = grouped.try_emplace({from, to}, Json{{"from", hex(from)}, {"to", hex(to)}, {"sites", Json::array()}, {"count", 0}});
        (void)inserted;
        position->second["sites"].push_back(hex(site));
        position->second["count"] = position->second["sites"].size();
    }
    Json nodeList = Json::array(), edgeList = Json::array();
    for (const auto& entry : nodes) nodeList.push_back(entry.second);
    for (const auto& entry : grouped) edgeList.push_back(entry.second);
    return {{"nodes", std::move(nodeList)}, {"edges", std::move(edgeList)},
        {"truncated", index.value("truncated", false)}};
}
}
