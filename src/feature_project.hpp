#pragma once
#include "core.hpp"

namespace scratcher {
Json binaryFingerprint(const Binary& binary);
void validateBinaryFingerprint(const Binary& binary, const Json& fingerprint);
void writeProjectAtomic(const std::filesystem::path& destination, const Json& project,
                        const std::filesystem::path& sourceBinary);
Json readProjectFile(const std::filesystem::path& path);
}
