#include <windows.h>
#include <dbghelp.h>
#include "core.hpp"
#include <algorithm>
#include <map>

namespace scratcher {
void Binary::parseMiniDump() {
 const auto header = read<MINIDUMP_HEADER>(0);
 if (header.NumberOfStreams > 4096 || !has(header.StreamDirectoryRva, uint64_t(header.NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY)))
  throw std::runtime_error("Invalid dump directory");
 std::map<ULONG, MINIDUMP_LOCATION_DESCRIPTOR> streams;
 for (ULONG index = 0; index < header.NumberOfStreams; ++index) {
  const auto directory = read<MINIDUMP_DIRECTORY>(header.StreamDirectoryRva + uint64_t(index) * sizeof(MINIDUMP_DIRECTORY));
  if (!has(directory.Location.Rva, directory.Location.DataSize)) throw std::runtime_error("Dump stream outside file");
  if(directory.StreamType==UnusedStream||directory.StreamType==ReservedStream0||directory.StreamType==ReservedStream1)continue;
  if (!streams.emplace(directory.StreamType, directory.Location).second) throw std::runtime_error("Duplicate dump stream");
 }
 const auto system = streams.find(SystemInfoStream);
 if (system == streams.end() || system->second.DataSize < sizeof(MINIDUMP_SYSTEM_INFO)) throw std::runtime_error("Dump lacks processor information");
 const auto cpu = read<MINIDUMP_SYSTEM_INFO>(system->second.Rva).ProcessorArchitecture;
 if (cpu != PROCESSOR_ARCHITECTURE_AMD64 && cpu != PROCESSOR_ARCHITECTURE_INTEL) throw std::runtime_error("This build supports x86/x64 dumps");
 bits = cpu == PROCESSOR_ARCHITECTURE_AMD64 ? 64 : 32; format = "Minidump";
 auto addRange = [&](Address va, uint64_t size, uint64_t offset) {
  if (!size) return;
  if (size > UINT64_MAX - va || !has(offset, size)) throw std::runtime_error("Dump memory outside file");
  sections.push_back({"memory_" + hex(va), va, size, offset, size, false, false});
 };
 if (auto found = streams.find(Memory64ListStream); found != streams.end()) {
  const auto& location = found->second;
  if (location.DataSize < 16) throw std::runtime_error("Truncated dump memory list");
  const auto count = read<uint64_t>(location.Rva);
  if (count > 1000000 || count > (location.DataSize - 16) / sizeof(MINIDUMP_MEMORY_DESCRIPTOR64)) throw std::runtime_error("Invalid dump memory count");
  auto offset = read<uint64_t>(uint64_t(location.Rva) + 8);
  for (uint64_t index = 0; index < count; ++index) {
   const auto range = read<MINIDUMP_MEMORY_DESCRIPTOR64>(uint64_t(location.Rva) + 16 + index * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64));
   addRange(range.StartOfMemoryRange, range.DataSize, offset);
   if (range.DataSize > UINT64_MAX - offset) throw std::runtime_error("Dump file offset overflow");
   offset += range.DataSize;
  }
 } else if (auto found = streams.find(MemoryListStream); found != streams.end()) {
  const auto& location = found->second;
  if (location.DataSize < 4) throw std::runtime_error("Truncated dump memory list");
  const auto count = read<uint32_t>(location.Rva);
  if (count > 1000000 || count > (location.DataSize - 4) / sizeof(MINIDUMP_MEMORY_DESCRIPTOR)) throw std::runtime_error("Invalid dump memory count");
  for (uint64_t index = 0; index < count; ++index) {
   const auto range = read<MINIDUMP_MEMORY_DESCRIPTOR>(uint64_t(location.Rva) + 4 + index * sizeof(MINIDUMP_MEMORY_DESCRIPTOR));
   addRange(range.StartOfMemoryRange, range.Memory.DataSize, range.Memory.Rva);
  }
 } else throw std::runtime_error("Dump contains no captured memory");
 if (sections.empty()) throw std::runtime_error("Dump contains no captured memory");
 std::sort(sections.begin(), sections.end(), [](const Section& a, const Section& b) { return a.va < b.va; });
 for (size_t index = 1; index < sections.size(); ++index)
  if (sections[index].va < sections[index - 1].va + sections[index - 1].memorySize) throw std::runtime_error("Overlapping dump memory ranges");
 base = sections.front().va; entry = base;
 if (auto found = streams.find(MemoryInfoListStream); found != streams.end()) {
  const auto& location = found->second;
  if (location.DataSize < sizeof(MINIDUMP_MEMORY_INFO_LIST)) throw std::runtime_error("Truncated dump memory information");
  const auto list = read<MINIDUMP_MEMORY_INFO_LIST>(location.Rva);
  if (list.SizeOfHeader < sizeof(list) || list.SizeOfHeader > location.DataSize || list.SizeOfEntry < sizeof(MINIDUMP_MEMORY_INFO) ||
      list.NumberOfEntries > 1000000 || list.NumberOfEntries > (location.DataSize - list.SizeOfHeader) / list.SizeOfEntry)
   throw std::runtime_error("Invalid dump memory information");
  // Split captured spans at protection boundaries; never treat arbitrary data as executable.
  std::vector<MINIDUMP_MEMORY_INFO> protections;
  for (uint64_t index = 0; index < list.NumberOfEntries; ++index) {
   auto info = read<MINIDUMP_MEMORY_INFO>(uint64_t(location.Rva) + list.SizeOfHeader + index * list.SizeOfEntry);
   if (info.RegionSize > UINT64_MAX - info.BaseAddress) throw std::runtime_error("Dump protection range overflow");
   if (info.State == MEM_COMMIT && info.RegionSize) protections.push_back(info);
  }
  std::sort(protections.begin(), protections.end(), [](const auto& a, const auto& b) { return a.BaseAddress < b.BaseAddress; });
  std::vector<Section> split;
  size_t index = 0;
  for (const auto& captured : sections) {
   Address cursor = captured.va, end = captured.va + captured.memorySize;
   while (cursor < end) {
    while (index < protections.size() && protections[index].BaseAddress + protections[index].RegionSize <= cursor) ++index;
    Address stop = end; DWORD protect = 0;
    if (index < protections.size()) {
     const auto& info = protections[index];
     if (cursor < info.BaseAddress) stop = std::min(end, info.BaseAddress);
     else { stop = std::min(end, info.BaseAddress + info.RegionSize); protect = info.Protect; }
    }
    split.push_back({"memory_" + hex(cursor), cursor, stop - cursor, captured.offset + cursor - captured.va, stop - cursor,
     (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0,
     (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0});
    cursor = stop;
   }
  }
  sections = std::move(split);
 }
 auto contextIP = [&](const MINIDUMP_LOCATION_DESCRIPTOR& location) -> Address {
  const auto offset = bits == 64 ? offsetof(CONTEXT, Rip) : offsetof(WOW64_CONTEXT, Eip);
  const auto width = bits == 64 ? 8 : 4;
  if (location.DataSize < offset + width || !has(location.Rva, location.DataSize)) return 0;
  return bits == 64 ? read<uint64_t>(uint64_t(location.Rva) + offset) : read<uint32_t>(uint64_t(location.Rva) + offset);
 };
 auto addIP = [&](Address ip, const std::string& name) {
  for (auto& section : sections) if (ip >= section.va && ip - section.va < section.memorySize) {
   // A captured instruction pointer establishes code when protection metadata is absent.
   if (!streams.count(MemoryInfoListStream)) section.executable = true;
   if (!section.executable) break;
   functions.push_back({ip, 0, name, "captured instruction pointer"});
   if (entry == base) entry = ip;
   break;
  }
 };
 if (auto found = streams.find(ExceptionStream); found != streams.end() && found->second.DataSize >= sizeof(MINIDUMP_EXCEPTION_STREAM)) {
  auto exception = read<MINIDUMP_EXCEPTION_STREAM>(found->second.Rva); addIP(contextIP(exception.ThreadContext), "exception_ip");
 }
 if (auto found = streams.find(ThreadListStream); found != streams.end()) {
  auto location = found->second;
  if (location.DataSize < 4) throw std::runtime_error("Truncated dump thread list");
  auto count = read<uint32_t>(location.Rva);
  if (count > (location.DataSize - 4) / sizeof(MINIDUMP_THREAD)) throw std::runtime_error("Invalid dump thread count");
  for (uint64_t index = 0; index < count; ++index) {
   auto thread = read<MINIDUMP_THREAD>(uint64_t(location.Rva) + 4 + index * sizeof(MINIDUMP_THREAD));
   addIP(contextIP(thread.ThreadContext), "thread_" + std::to_string(thread.ThreadId) + "_ip");
  }
 }
}
}
