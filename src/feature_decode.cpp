#include "feature_decode.hpp"
#include "feature_advanced_architectures.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <chrono>
#include <unordered_set>
#include <future>
#include <thread>
#include <cctype>

namespace scratcher {
namespace {
ZydisDecoder decoderFor(int bits) {
 ZydisDecoder decoder{};
 ZydisDecoderInit(&decoder, bits == 64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
  bits == 64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
 return decoder;
}
const uint8_t* input(const Binary& binary, const Section& section, Address va, uint8_t* scratch, size_t& length) {
 const auto delta = va - section.va;
 length = static_cast<size_t>(std::min<uint64_t>(15, section.memorySize - delta));
 if (delta < section.fileSize && section.fileSize - delta >= length && binary.has(section.offset + delta, length))
  return binary.bytes() + section.offset + delta;
 binary.load(va, scratch, length);
 return scratch;
}
}

std::vector<Instruction> decodeListing(const Binary& binary, Address va, size_t count, const std::function<bool()>& cancelled) {
 if(!binary.language.starts_with("x86:"))return decodeArchitectureListing(binary,va,count,cancelled);
 auto decoder = decoderFor(binary.bits);
 ZydisFormatter formatter{};
 ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_UPPERCASE_MNEMONIC, ZYAN_TRUE);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_UPPERCASE_PREFIXES, ZYAN_TRUE);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_UPPERCASE_REGISTERS, ZYAN_TRUE);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYDIS_PADDING_DISABLED);
 ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_PRINT_BRANCH_SIZE, ZYAN_FALSE);
 std::vector<Instruction> rows;
 rows.reserve(count);
 const char* digits = "0123456789abcdef";
 for (size_t index = 0; index < count; ++index) {
  if ((index & 255) == 0 && cancelled()) throw std::runtime_error("Operation cancelled");
  const auto* section = binary.section(va);
  if (!section || !binary.analysisCode(va)) break;
  uint8_t scratch[15]; size_t available = 0;
  const auto* bytes = input(binary, *section, va, scratch, available);
  ZydisDecodedInstruction decoded;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  Instruction row; row.va = va; row.length = 1; row.mnemonic = "db";
  if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes, available, &decoded, operands))) {
   row.length = decoded.length;
   row.mnemonic=ZydisMnemonicGetString(decoded.mnemonic);for(auto&character:row.mnemonic)character=static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
   char formatted[512]{};
   if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &decoded, operands,
      decoded.operand_count_visible, formatted, sizeof(formatted), va, nullptr))) {
    std::string text(formatted);
    auto mnemonicPosition=text.find(row.mnemonic);
    if(mnemonicPosition!=std::string::npos){if(mnemonicPosition)row.prefixes=text.substr(0,mnemonicPosition-1);auto operandPosition=mnemonicPosition+row.mnemonic.size();if(operandPosition<text.size())row.operands=text.substr(operandPosition+1);}
   }
  }
  row.bytes.resize(row.length * 3 - 1);
  for (int i = 0; i < row.length; ++i) {
   row.bytes[i * 3] = digits[bytes[i] >> 4]; row.bytes[i * 3 + 1] = digits[bytes[i] & 15];
   if (i + 1 < row.length) row.bytes[i * 3 + 2] = ' ';
  }
  rows.push_back(std::move(row));
  if (Address(rows.back().length) > UINT64_MAX - va) break;
  va += rows.back().length;
 }
 return rows;
}

Json scanDirectCalls(const Binary& binary, size_t budget, std::vector<Function>& discovered, const std::function<bool()>& cancelled, bool fullScan) {
 if(!binary.language.starts_with("x86:"))return scanArchitectureCalls(binary,budget,discovered,cancelled,fullScan);
 const auto start = std::chrono::steady_clock::now();
 std::unordered_set<Address> known;
 if(fullScan){known.reserve(binary.functions.size() + 4096);for (const auto& function : binary.functions) known.insert(function.va);}
 struct Part { const Section* section; uint64_t begin, end; };
 struct Result { size_t examined=0,invalid=0;uint64_t scanned=0;std::vector<Address> targets; };
 std::vector<Part> parts;
 uint64_t total = 0;
 for (const auto& section : binary.sections) {
  if (!section.executable) continue;
  const auto size = std::min(section.fileSize, section.memorySize);
  total += size;
  uint64_t begin=0;
  if(fullScan) {
   // Split only at indexed function starts, preserving instruction boundaries.
   auto function=std::lower_bound(binary.functions.begin(),binary.functions.end(),section.va,[](const Function&f,Address va){return f.va<va;});
   for(;function!=binary.functions.end()&&function->va-section.va<size;++function) {
    if(function->end<=function->va || (function->source!="unwind metadata"&&function->source!="ELF symbol"))continue;
    auto offset=function->va-section.va;
    if(offset-begin>=2*1024*1024) {parts.push_back({&section,begin,offset});begin=offset;}
   }
  }
  if(begin<size)parts.push_back({&section,begin,size});
 }
 auto scan=[&](const Part&part,size_t allowance) {
  Result result;auto decoder=decoderFor(binary.bits);
  uint64_t offset=part.begin;
  while(offset<part.end&&result.examined<allowance) {
   if ((result.examined & 1023) == 0 && cancelled()) throw std::runtime_error("Operation cancelled");
   const auto available = static_cast<size_t>(std::min<uint64_t>(15, part.end - offset));
   const auto* bytes = binary.bytes() + part.section->offset + offset;
   ZydisDecodedInstruction instruction;
   ZydisDecoderContext context;
   size_t length = 1;
   if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &context, bytes, available, &instruction))) {
    length = instruction.length;
    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.operand_count_visible) {
     ZydisDecodedOperand operand;
     if (ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &context, &instruction, &operand, 1)) &&
         operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
      ZyanU64 target = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, part.section->va + offset, &target)) &&
          binary.executable(target) && (!fullScan||!known.contains(target)))result.targets.push_back(target);
     }
    }
   } else ++result.invalid;
   offset += length; result.scanned += length; ++result.examined;
  }
  return result;
 };
 std::vector<Result> results(parts.size());
 const auto workers=fullScan?std::min<size_t>(parts.size(),std::min<size_t>(8,std::max(1u,std::thread::hardware_concurrency()))):size_t(1);
 size_t examined=0,invalid=0;uint64_t scanned=0;
 if(workers>1) {
  std::atomic_size_t next=0;std::vector<std::future<void>> tasks;
  for(size_t worker=0;worker<workers;++worker)tasks.push_back(std::async(std::launch::async,[&]{for(;;){auto index=next.fetch_add(1);if(index>=parts.size())break;results[index]=scan(parts[index],SIZE_MAX);}}));
  std::exception_ptr failure;
  for(auto&task:tasks)try{task.get();}catch(...){if(!failure)failure=std::current_exception();}
  if(failure)std::rethrow_exception(failure);
 }else {
  size_t remaining=budget;
  for(size_t index=0;index<parts.size()&&remaining;++index){results[index]=scan(parts[index],remaining);remaining-=results[index].examined;}
 }
 std::vector<Address> targets;
 for(auto&result:results){examined+=result.examined;invalid+=result.invalid;scanned+=result.scanned;targets.insert(targets.end(),result.targets.begin(),result.targets.end());}
 std::sort(targets.begin(),targets.end());targets.erase(std::unique(targets.begin(),targets.end()),targets.end());
 discovered.reserve(targets.size());
 for(auto target:targets){if(!fullScan){auto found=std::lower_bound(binary.functions.begin(),binary.functions.end(),target,[](const Function&f,Address va){return f.va<va;});if(found!=binary.functions.end()&&found->va==target)continue;}discovered.push_back({target,0,"sub_"+hex(target).substr(2),"direct call target"});}
 const bool complete = scanned == total;
 uint64_t excluded=0,candidateBytes=0;
 for(const auto& section:binary.sections){const auto size=std::min(section.fileSize,section.memorySize);if(!section.executable)excluded+=size;}
 for(const auto& section:binary.sections)if(!section.executable){const auto extent=std::min(section.fileSize,section.memorySize);if(extent>UINT64_MAX-section.va)continue;for(const auto& range:binary.analysisRanges){auto begin=std::max(range.first,section.va),end=std::min(range.second,section.va+extent);if(end>begin)candidateBytes+=end-begin;}}
 Json warnings=Json::array();
 if(candidateBytes)warnings.push_back("Loader-metadata code candidates outside declared executable sections are excluded from this linear scan; run analyze_code_paths to traverse their indexed seeds.");
 if(!binary.executable(binary.entry))warnings.push_back("The entry point lacks a declared executable permission; this scan does not cover its code candidate region.");
 return {{"instructions_examined", examined}, {"instructions_decoded", examined - invalid},
  {"invalid_bytes", invalid}, {"functions_added", discovered.size()}, {"scanned_bytes", scanned},
  {"executable_bytes", total}, {"coverage_percent", total ? 100.0 * scanned / total : 100.0},
  {"complete", complete}, {"budget_exhausted", !complete && examined >= budget}, {"cached", false},
  {"parallel_workers",workers},{"scan_partitions",parts.size()},{"full_scan",fullScan},
  {"excluded_file_backed_bytes",excluded},{"excluded_metadata_code_candidate_bytes",candidateBytes},
  {"semantic_analysis_complete",false},{"coverage_is_scope_only",true},{"warnings",warnings},
  {"scope", "linear direct-call discovery in file-backed executable sections"},
  {"elapsed_ms", std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count()}};
}
}

