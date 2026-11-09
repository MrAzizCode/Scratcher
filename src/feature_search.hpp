#pragma once
#include "core.hpp"

namespace scratcher {
// Offsets are byte cursors into the file, including bytes outside mapped sections.
// Continue with next_offset until it is null. Each call scans at most 16 MiB;
// patterns are at most 256 bytes and result pages at most 500 rows.
Json searchBytePattern(const Binary& binary, const std::string& pattern,
                       size_t offset=0, size_t limit=500);
// ASCII and printable UTF-16LE (including surrogate pairs). Text is capped at
// 4096 UTF-8 bytes per result; length counts decoded characters, byte_length
// counts file bytes. A run crossing the scan window is returned as a fragment
// with continues=true and can be resumed using next_offset.
Json discoverStrings(const Binary& binary, size_t minimum=5, size_t offset=0,
                     size_t limit=500, const std::string& query="");
}
