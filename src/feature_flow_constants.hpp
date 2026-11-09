#pragma once
#include "core.hpp"
#include <Zydis/Zydis.h>
#include <array>
#include <functional>
#include <optional>

namespace scratcher {
struct FlowConstant {
 uint64_t value=0;
 std::optional<Address> readonlySlot;
};
// The caller must validate complete pointer bytes, read-only storage, imports,
// immutable file backing and any capture allowlist before returning a value.
using FlowPointerReader=std::function<std::optional<uint64_t>(Address,size_t)>;
// Straight-line facts only. Callers reset at every trace entry and conditional
// split; facts never propagate through a join, call, or guessed instruction.
class FlowConstants {
public:
 explicit FlowConstants(int bits);
 void reset();
 // Operand need for observe() only. Transfer operands must still be decoded
 // separately before querying the incoming state. In particular CALL returns
 // false here because observe() clears all facts without reading operands.
 bool needsOperands(const ZydisDecodedInstruction& instruction) const {
  if(instruction.meta.category==ZYDIS_CATEGORY_CALL)return false;
  if(liveMask_)return instruction.operand_count!=0;
  if(instruction.operand_count_visible<2)return false;
  // ADD/SUB require a known destination and cannot establish facts from an
  // empty state. Keep potential MOV/LEA/XOR-self producers conservative.
  return instruction.mnemonic==ZYDIS_MNEMONIC_MOV||instruction.mnemonic==ZYDIS_MNEMONIC_LEA||instruction.mnemonic==ZYDIS_MNEMONIC_XOR;
 }
 uint16_t liveMask() const noexcept {return liveMask_;}
 std::optional<FlowConstant> registerValue(ZydisRegister) const;
 std::optional<Address> effectiveAddress(const ZydisDecodedInstruction&,const ZydisDecodedOperand&,Address pc) const;
 std::optional<FlowConstant> operandValue(const ZydisDecodedInstruction&,const ZydisDecodedOperand&,Address pc,const FlowPointerReader&) const;
 // Resolve transfers using the input state before observing the instruction.
 // Every explicit/implicit GPR write kills its entire alias before the modeled
 // whitelist restores a width-correct value. Calls clear all register facts.
 // A null operands pointer is supported when needsOperands() is false. A null
 // pointer when operands are required discards facts defensively; it never
 // preserves stale constants across an instruction whose writes are unknown.
 void observe(const ZydisDecodedInstruction&,const ZydisDecodedOperand*,Address pc,const FlowPointerReader&);
private:
 int bits_;
 ZydisMachineMode mode_;
 std::array<std::optional<FlowConstant>,16> registers_{};
 uint16_t liveMask_=0;
 int index(ZydisRegister) const;
};
}
