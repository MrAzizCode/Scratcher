#include "feature_project.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>

using namespace scratcher;
namespace {
int checks = 0;
void check(bool value, const char* description) {
    ++checks;
    if (!value) throw std::runtime_error(description);
}
template<class F> void rejects(F&& action, const char* description) {
    bool rejected = false;
    try { action(); } catch (const std::exception&) { rejected = true; }
    check(rejected, description);
}
void writeText(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) throw std::runtime_error("Cannot create test fixture");
}
}
int main() {
    try {
        auto dir = executableDir() / ("project-fixtures-" + std::to_string(GetCurrentProcessId()));
        std::filesystem::create_directories(dir);
        auto source = dir / "source.bin";
        auto replacement = dir / "replacement.bin";
        writeText(source, "abc");
        writeText(replacement, "abd");
        auto largeSource = dir / "streamed.bin";
        writeText(largeSource, std::string(2 * 1024 * 1024 + 17, 'a'));
        {
            Binary streamed(largeSource);
            check(binaryFingerprint(streamed)["sha256"] == "c2273a45bd6d19d2714b8279b1fd1123bb746e7f7f6331085fb6ecaa30164546", "multi-chunk SHA256 known answer");
            uint8_t tail[17]{};
            streamed.readFileBytes(2 * 1024 * 1024, tail, sizeof(tail));
            check(std::string(reinterpret_cast<char*>(tail), sizeof(tail)) == std::string(17, 'a'), "explicit-offset tail read");
            streamed.readFileBytes(streamed.size(), nullptr, 0);
            rejects([&] { streamed.readFileBytes(streamed.size(), tail, 1); }, "past-end streamed read rejected");
            rejects([&] { streamed.readFileBytes(0, nullptr, 1); }, "null streamed destination rejected");
        }
        {
            Binary binary(source), changed(replacement);
            auto fingerprint = binaryFingerprint(binary);
            check(fingerprint["size"] == 3, "fingerprint file length");
            check(fingerprint["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 known answer");
            validateBinaryFingerprint(binary, fingerprint);
            ++checks;
            rejects([&] { validateBinaryFingerprint(changed, fingerprint); }, "same-size replacement rejected");
            rejects([&] { validateBinaryFingerprint(binary, Json::object()); }, "missing fingerprint rejected");
            rejects([&] { validateBinaryFingerprint(binary, {{"size", -1}, {"sha256", fingerprint["sha256"]}}); }, "negative size rejected");
            rejects([&] { validateBinaryFingerprint(binary, {{"size", 3}, {"sha256", "bad"}}); }, "malformed hash rejected");
            auto uppercase = fingerprint;
            auto text = uppercase["sha256"].get<std::string>();
            for (char& c : text) if (c >= 'a' && c <= 'f') c = static_cast<char>(c - ('a' - 'A'));
            uppercase["sha256"] = text;
            validateBinaryFingerprint(binary, uppercase);
            ++checks;

            auto project = dir / std::filesystem::path(u8"مشروع-测试.scratcher");
            Json document = {{"version", 2}, {"fingerprint", fingerprint}, {"note", "ملاحظة ✓"}};
            writeProjectAtomic(project, document, source);
            check(readProjectFile(project) == document, "Unicode path and text round trip");
            document["note"] = "updated";
            writeProjectAtomic(project, document, source);
            check(readProjectFile(project) == document, "atomic replacement round trip");
            rejects([&] { writeProjectAtomic(source, document, source); }, "source binary save rejected");
            auto alias = dir / "alias.bin";
            std::filesystem::create_hard_link(source, alias);
            rejects([&] { writeProjectAtomic(alias, document, source); }, "hardlink binary save rejected");
            check(binaryFingerprint(binary) == fingerprint, "binary content preserved");

            HANDLE locked = CreateFileW(project.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            check(locked != INVALID_HANDLE_VALUE, "project locked for failure simulation");
            auto updated = document;
            updated["note"] = "must not replace locked file";
            rejects([&] { writeProjectAtomic(project, updated, source); }, "replace failure reported");
            CloseHandle(locked);
            check(readProjectFile(project) == document, "failed save preserves previous project");
            bool temporaryExists = false;
            for (const auto& entry : std::filesystem::directory_iterator(dir))
                if (entry.path().filename().wstring().starts_with(L".scratcher-")) temporaryExists = true;
            check(!temporaryExists, "failed save cleans temporary file");

            auto invalid = dir / "invalid.scratcher";
            writeText(invalid, "{");
            rejects([&] { readProjectFile(invalid); }, "invalid JSON rejected");
            writeText(invalid, "[]");
            rejects([&] { readProjectFile(invalid); }, "non-object project rejected");
            writeText(invalid, std::string(129, '[') + "0" + std::string(129, ']'));
            rejects([&] { readProjectFile(invalid); }, "excessive nesting rejected");
            auto oversized = dir / "oversized.scratcher";
            {
                std::ofstream out(oversized, std::ios::binary);
                out.seekp(64LL * 1024 * 1024);
                out.put(' ');
            }
            rejects([&] { readProjectFile(oversized); }, "oversized read rejected before parsing");
            rejects([&] { writeProjectAtomic(project, Json::array(), source); }, "non-object save rejected");
            check(readProjectFile(project) == document, "validation failure preserves previous project");
        }
        std::filesystem::remove_all(dir);
        std::cout << "PASS: " << checks << " project storage checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL after " << checks << " checks: " << error.what() << '\n';
        return 1;
    }
}
