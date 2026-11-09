#include "feature_xrefs.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace scratcher;
namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
bool contains(const Json& index, Address from, Address to, const std::string& kind) {
    for (const auto& row : index.at("items"))
        if (address(row.at("from")) == from && address(row.at("to")) == to && row.at("kind") == kind) return true;
    return false;
}
}
int main() {
    try {
        const auto dir = executableDir() / "test-fixtures";
        std::filesystem::create_directories(dir);
        const auto fixture = dir / "xrefs.bin";
        std::vector<uint8_t> bytes(96, 0x90);
        const uint8_t code[] = {
            0xe8, 0x0b, 0, 0, 0,                   // call 0x1010
            0x48, 0x8d, 0x05, 0x14, 0, 0, 0,       // lea rax,[0x1020]
            0xff, 0xd0,                             // call rax (unresolved)
            0xeb, 0,                                // jmp 0x1010
            0xc3,
            0xb8, 0x20, 0x10, 0, 0,                 // mov eax,0x1020
            0x48, 0x8b, 0x05, 0x03, 0, 0, 0        // mov rax,[0x1020]
        };
        std::memcpy(bytes.data(), code, sizeof(code));
        const uint8_t callAgain[] = {0xe8, 0xe3, 0xff, 0xff, 0xff};
        std::memcpy(bytes.data() + 0x28, callAgain, sizeof(callAgain));
        const uint8_t importCall[] = {0xff, 0x15, 0x0a, 0, 0, 0};
        std::memcpy(bytes.data() + 0x30, importCall, sizeof(importCall));
        {
            std::ofstream file(fixture, std::ios::binary);
            file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        }
        Engine engine;
        engine.open(fixture);
        auto& binary = const_cast<Binary&>(*engine.binary());
        // Supply an import slot exactly as a parsed image's import table would.
        binary.imports.push_back({0x1040, "example.dll", "fixture_import"});
        const auto index = collectCrossReferences(engine, 1000);
        check(!index.at("truncated"), "full scan is complete");
        check(contains(index, 0x1000, 0x1010, "call"), "direct call");
        check(contains(index, 0x100e, 0x1010, "jump"), "direct jump");
        check(contains(index, 0x1005, 0x1020, "data_address"), "PC-relative address");
        check(contains(index, 0x1011, 0x1020, "data_address"), "mapped literal address");
        check(contains(index, 0x1016, 0x1020, "data"), "PC-relative memory reference");
        check(referencesAt(index, 0x100c, true).at("total") == 0, "register call is not guessed");
        check(contains(index, 0x1030, 0x1040, "import_call"), "fixed import slot call");
        const auto refs = referencesAt(index, 0x1010);
        check(refs.at("total") == 3, "incoming reference count");
        const auto graph = buildCallGraph(index, binary);
        check(graph.at("edges").size() == 2, "calls grouped by caller and target");
        check(graph.at("edges")[0].at("count") == 2, "two call sites on one edge");
        bool importFound = false;
        for (const auto& node : graph.at("nodes"))
            if (node.at("address") == "0x1040") importFound = node.at("kind") == "import";
        check(importFound, "import node classification");
        const auto bounded = collectCrossReferences(engine, 1);
        check(bounded.at("instructions_examined") == 1, "instruction budget respected");
        check(bounded.at("truncated") && bounded.at("budget_exhausted"), "budget exhaustion disclosed");
        check(referencesAt(bounded, 0x1010).at("truncated"), "query retains scan completeness");
        check(collectCrossReferences(engine, 0).at("instructions_examined") == 0, "zero budget");
        bool rejected = false;
        try { collectCrossReferences(engine, 1000001); } catch (const std::exception&) { rejected = true; }
        check(rejected, "excessive budget rejected");
        std::cout << "PASS: cross references, fixed import calls, call graph, and scan budgets\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
