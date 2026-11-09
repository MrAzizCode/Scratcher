#include <windows.h>
#include <bcrypt.h>
#include "feature_project.hpp"
#include <algorithm>
#include <array>
#include <vector>
#include "zlib.h"

namespace scratcher {
namespace {
constexpr uint64_t projectLimit = 64ULL * 1024 * 1024;
constexpr uint64_t expandedLimit = 256ULL * 1024 * 1024;
constexpr char compressedMagic[] = "SCRATCHERDB3\n";
constexpr ULONG ioChunk = 1024 * 1024;

class FileHandle {
public:
    HANDLE handle = INVALID_HANDLE_VALUE;
    explicit FileHandle(HANDLE value) : handle(value) {}
    ~FileHandle() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    bool close() {
        HANDLE value = handle;
        handle = INVALID_HANDLE_VALUE;
        return CloseHandle(value) != FALSE;
    }
};

void requireStatus(NTSTATUS status) {
    if (status < 0) throw std::runtime_error("Cannot calculate the file checksum");
}

struct HashHandles {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~HashHandles() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
};

std::string digestText(const uint8_t* bytes, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (size_t i = 0; i < size; ++i) {
        result[2 * i] = digits[bytes[i] >> 4];
        result[2 * i + 1] = digits[bytes[i] & 15];
    }
    return result;
}

void checkDepth(const std::string& text) {
    size_t depth = 0;
    bool quoted = false, escaped = false;
    for (char c : text) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '[' || c == '{') {
            if (++depth > 128) throw std::runtime_error("Project nesting exceeds the supported limit");
        } else if ((c == ']' || c == '}') && depth) --depth;
    }
}

void rejectBinaryDestination(const std::filesystem::path& destination,
                             const std::filesystem::path& sourceBinary) {
    if (sourceBinary.empty()) throw std::runtime_error("The binary path is missing");
    std::error_code error;
    auto source = std::filesystem::weakly_canonical(sourceBinary, error);
    if (error) throw std::runtime_error("Cannot resolve the binary path");
    auto target = std::filesystem::weakly_canonical(destination, error);
    if (error) throw std::runtime_error("Cannot resolve the project path");
    const auto& sourceText = source.native();
    const auto& targetText = target.native();
    if (CompareStringOrdinal(sourceText.c_str(), -1, targetText.c_str(), -1, TRUE) == CSTR_EQUAL)
        throw std::runtime_error("Choose a project path different from the binary");
    bool targetExists = std::filesystem::exists(destination, error);
    if (error) throw std::runtime_error("Cannot inspect the project path");
    if (targetExists) {
        bool sameFile = std::filesystem::equivalent(destination, sourceBinary, error);
        if (error) throw std::runtime_error("Cannot compare the project and binary paths");
        if (sameFile) throw std::runtime_error("Choose a project path different from the binary");
        if (!std::filesystem::is_regular_file(destination, error) || error)
            throw std::runtime_error("The project path must be a regular file");
    }
}

struct TemporaryFile {
    std::filesystem::path path;
    bool committed = false;
    ~TemporaryFile() {
        if (!committed && !path.empty()) DeleteFileW(path.c_str());
    }
};
}

Json binaryFingerprint(const Binary& binary) {
    std::vector<uint8_t> hashObject;
    HashHandles handles;
    requireStatus(BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
    DWORD objectSize = 0, returnedSize = 0;
    requireStatus(BCryptGetProperty(handles.algorithm, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returnedSize, 0));
    hashObject.resize(objectSize);
    requireStatus(BCryptCreateHash(handles.algorithm, &handles.hash, hashObject.data(), objectSize, nullptr, 0, 0));
    std::vector<uint8_t> input(ioChunk);
    for (uint64_t offset = 0; offset < binary.size();) {
        auto count = static_cast<ULONG>(std::min<uint64_t>(ioChunk, binary.size() - offset));
        binary.readFileBytes(offset, input.data(), count);
        requireStatus(BCryptHashData(handles.hash, input.data(), count, 0));
        offset += count;
    }
    std::array<uint8_t, 32> digest{};
    requireStatus(BCryptFinishHash(handles.hash, digest.data(), static_cast<ULONG>(digest.size()), 0));
    return {{"sha256", digestText(digest.data(), digest.size())}, {"size", binary.size()}};
}

void validateBinaryFingerprint(const Binary& binary, const Json& fingerprint) {
    if (!fingerprint.is_object() || !fingerprint.contains("size") ||
        !fingerprint.contains("sha256") || !fingerprint["sha256"].is_string())
        throw std::runtime_error("The project file checksum is missing or invalid");
    const auto& size = fingerprint["size"];
    if (!size.is_number_unsigned() && !(size.is_number_integer() && size.get<int64_t>() >= 0))
        throw std::runtime_error("The project file size is invalid");
    auto expected = fingerprint["sha256"].get<std::string>();
    if (expected.size() != 64 || !std::all_of(expected.begin(), expected.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        })) throw std::runtime_error("The project file checksum is invalid");
    if (size.get<uint64_t>() != binary.size())
        throw std::runtime_error("The binary has changed since this project was saved");
    for (char& c : expected) if (c >= 'A' && c <= 'F') c = static_cast<char>(c + ('a' - 'A'));
    if (binaryFingerprint(binary)["sha256"].get<std::string>() != expected)
        throw std::runtime_error("The binary has changed since this project was saved");
}

void writeProjectAtomic(const std::filesystem::path& destination, const Json& project,
                        const std::filesystem::path& sourceBinary) {
    if (destination.empty() || destination.filename().empty())
        throw std::runtime_error("Choose a project file path");
    if (!project.is_object()) throw std::runtime_error("A project must contain an object");
    rejectBinaryDestination(destination, sourceBinary);
    const bool compressed=project.value("scratcher_project",0)==3;
    std::string serialized = compressed?project.dump():project.dump(2);
    if (serialized.size() > (compressed?expandedLimit:projectLimit)) throw std::runtime_error("Project exceeds the supported size limit");
    checkDepth(serialized);
    if(compressed){uint64_t plainBytes=serialized.size();uLongf count=compressBound(static_cast<uLong>(plainBytes));std::string encoded(20+count,'\0');std::memcpy(encoded.data(),compressedMagic,12);for(size_t i=0;i<8;++i)encoded[12+i]=static_cast<char>(plainBytes>>(i*8));if(compress2(reinterpret_cast<Bytef*>(encoded.data()+20),&count,reinterpret_cast<const Bytef*>(serialized.data()),static_cast<uLong>(plainBytes),Z_BEST_SPEED)!=Z_OK)throw std::runtime_error("Cannot compress analysis database");encoded.resize(20+count);if(encoded.size()>projectLimit)throw std::runtime_error("Compressed project exceeds the 64 MiB file limit");serialized=std::move(encoded);}
    auto absolute = std::filesystem::absolute(destination);
    TemporaryFile temporary;
    HANDLE opened = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::array<uint8_t, 16> random{};
        if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw std::runtime_error("Cannot create a temporary project file");
        auto suffix = digestText(random.data(), random.size());
        temporary.path = absolute.parent_path() / (L".scratcher-" + std::wstring(suffix.begin(), suffix.end()) + L".tmp");
        opened = CreateFileW(temporary.path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        if (opened != INVALID_HANDLE_VALUE) break;
        auto code = GetLastError();
        // Only delete a file this save operation successfully created.
        temporary.path.clear();
        if (code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS)
            throw std::runtime_error("Cannot create the project file in the selected folder");
    }
    if (opened == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot create a temporary project file");
    FileHandle file(opened);
    for (size_t offset = 0; offset < serialized.size();) {
        DWORD count = static_cast<DWORD>(std::min<size_t>(ioChunk, serialized.size() - offset)), written = 0;
        if (!WriteFile(file.handle, serialized.data() + offset, count, &written, nullptr) || written == 0)
            throw std::runtime_error("Cannot write the project file");
        offset += written;
    }
    if (!FlushFileBuffers(file.handle)) throw std::runtime_error("Cannot finish writing the project file");
    if (!file.close()) throw std::runtime_error("Cannot close the project file");
    rejectBinaryDestination(absolute, sourceBinary);
    if (!MoveFileExW(temporary.path.c_str(), absolute.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("Cannot replace the project file; the previous project was preserved");
    temporary.committed = true;
}

Json readProjectFile(const std::filesystem::path& path) {
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open the project file");
    if (GetFileType(file.handle) != FILE_TYPE_DISK) throw std::runtime_error("The project path must be a regular file");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.handle, &length) || length.QuadPart <= 0)
        throw std::runtime_error("The project file is empty or unreadable");
    if (static_cast<uint64_t>(length.QuadPart) > projectLimit)
        throw std::runtime_error("Project exceeds the 64 MiB size limit");
    std::string serialized(static_cast<size_t>(length.QuadPart), '\0');
    for (size_t offset = 0; offset < serialized.size();) {
        DWORD count = static_cast<DWORD>(std::min<size_t>(ioChunk, serialized.size() - offset)), received = 0;
        if (!ReadFile(file.handle, serialized.data() + offset, count, &received, nullptr) || received == 0)
            throw std::runtime_error("Cannot read the complete project file");
        offset += received;
    }
    if(serialized.size()>=12&&std::memcmp(serialized.data(),compressedMagic,12)==0){if(serialized.size()<20)throw std::runtime_error("Truncated analysis database header");uint64_t plainBytes=0;for(size_t i=0;i<8;++i)plainBytes|=uint64_t(static_cast<unsigned char>(serialized[12+i]))<<(i*8);if(!plainBytes||plainBytes>expandedLimit)throw std::runtime_error("Analysis database exceeds the 256 MiB expanded limit");std::string expanded(static_cast<size_t>(plainBytes),'\0');uLongf count=static_cast<uLongf>(plainBytes);uLong sourceBytes=static_cast<uLong>(serialized.size()-20);if(uncompress2(reinterpret_cast<Bytef*>(expanded.data()),&count,reinterpret_cast<const Bytef*>(serialized.data()+20),&sourceBytes)!=Z_OK||count!=plainBytes||sourceBytes!=serialized.size()-20)throw std::runtime_error("Corrupt or truncated analysis database");serialized=std::move(expanded);}
    checkDepth(serialized);
    Json project;
    try { project = Json::parse(serialized); }
    catch (const Json::exception&) { throw std::runtime_error("The project file contains invalid JSON"); }
    if (!project.is_object()) throw std::runtime_error("The project file must contain an object");
    return project;
}
}
