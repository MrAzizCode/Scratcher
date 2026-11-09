#include "feature_flow_constants.hpp"
#include <stdexcept>

namespace scratcher {
FlowConstants::FlowConstants(int bits):bits_(bits),mode_(bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32){if(bits!=32&&bits!=64)throw std::invalid_argument("Flow constants require x86/x64");}
void FlowConstants::reset(){liveMask_=0;}
int FlowConstants::index(ZydisRegister reg) const {
 switch(ZydisRegisterGetLargestEnclosing(mode_,reg)){
 case ZYDIS_REGISTER_RAX:case ZYDIS_REGISTER_EAX:return 0;
 case ZYDIS_REGISTER_RCX:case ZYDIS_REGISTER_ECX:return 1;
 case ZYDIS_REGISTER_RDX:case ZYDIS_REGISTER_EDX:return 2;
 case ZYDIS_REGISTER_RBX:case ZYDIS_REGISTER_EBX:return 3;
 case ZYDIS_REGISTER_RSP:case ZYDIS_REGISTER_ESP:return 4;
 case ZYDIS_REGISTER_RBP:case ZYDIS_REGISTER_EBP:return 5;
 case ZYDIS_REGISTER_RSI:case ZYDIS_REGISTER_ESI:return 6;
 case ZYDIS_REGISTER_RDI:case ZYDIS_REGISTER_EDI:return 7;
 case ZYDIS_REGISTER_R8:return 8;case ZYDIS_REGISTER_R9:return 9;
 case ZYDIS_REGISTER_R10:return 10;case ZYDIS_REGISTER_R11:return 11;
 case ZYDIS_REGISTER_R12:return 12;case ZYDIS_REGISTER_R13:return 13;
 case ZYDIS_REGISTER_R14:return 14;case ZYDIS_REGISTER_R15:return 15;
 default:return -1;
 }
}
std::optional<FlowConstant> FlowConstants::registerValue(ZydisRegister reg) const {auto i=index(reg);auto width=ZydisRegisterGetWidth(mode_,reg);if(i<0||width<32||!(liveMask_&(uint16_t(1)<<i))||!registers_[i])return {};auto value=*registers_[i];if(width==32)value.value&=0xffffffffULL;return value;}
std::optional<Address> FlowConstants::effectiveAddress(const ZydisDecodedInstruction& instruction,const ZydisDecodedOperand& operand,Address pc) const {
 if(operand.type!=ZYDIS_OPERAND_TYPE_MEMORY||operand.mem.segment==ZYDIS_REGISTER_FS||operand.mem.segment==ZYDIS_REGISTER_GS)return {};
 ZydisRegisterContext context{};
 for(auto reg:{operand.mem.base,operand.mem.index})if(reg!=ZYDIS_REGISTER_NONE&&reg!=ZYDIS_REGISTER_RIP&&reg!=ZYDIS_REGISTER_EIP){auto value=registerValue(reg);if(!value)return {};context.values[reg]=value->value;}
 ZyanU64 result=0;if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&instruction,&operand,pc,&context,&result)))return {};return result;
}
std::optional<FlowConstant> FlowConstants::operandValue(const ZydisDecodedInstruction& instruction,const ZydisDecodedOperand& operand,Address pc,const FlowPointerReader& read) const {
 if(operand.type==ZYDIS_OPERAND_TYPE_REGISTER)return registerValue(operand.reg.value);
 if(operand.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){if(operand.imm.is_relative){ZyanU64 target=0;if(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction,&operand,pc,&target)))return FlowConstant{target,{}};return {};}return FlowConstant{operand.imm.is_signed?static_cast<uint64_t>(operand.imm.value.s):operand.imm.value.u,{}};}
 if(operand.type==ZYDIS_OPERAND_TYPE_MEMORY&&(operand.size==32||operand.size==64)){auto slot=effectiveAddress(instruction,operand,pc);if(slot&&read){auto value=read(*slot,operand.size/8);if(value)return FlowConstant{*value,*slot};}}
 return {};
}
void FlowConstants::observe(const ZydisDecodedInstruction& instruction,const ZydisDecodedOperand* operands,Address pc,const FlowPointerReader& read){
 if(instruction.meta.category==ZYDIS_CATEGORY_CALL){reset();return;}
 if(!needsOperands(instruction))return;
 if(!operands){reset();return;}
 // Compute the supported result from the input state before killing aliases.
 std::optional<FlowConstant> value;int destination=-1;unsigned width=0;
 if(instruction.operand_count_visible>=2&&operands[0].type==ZYDIS_OPERAND_TYPE_REGISTER){const auto& dst=operands[0];const auto& src=operands[1];destination=index(dst.reg.value);width=dst.size;
  if(width>=32&&destination>=0){auto mnemonic=instruction.mnemonic;
   if(mnemonic==ZYDIS_MNEMONIC_MOV)value=operandValue(instruction,src,pc,read);
   else if(mnemonic==ZYDIS_MNEMONIC_LEA){auto address=effectiveAddress(instruction,src,pc);if(address)value=FlowConstant{*address,{}};}
   else if(mnemonic==ZYDIS_MNEMONIC_XOR&&src.type==ZYDIS_OPERAND_TYPE_REGISTER&&dst.reg.value==src.reg.value)value=FlowConstant{0,{}};
   else if(mnemonic==ZYDIS_MNEMONIC_ADD||mnemonic==ZYDIS_MNEMONIC_SUB){auto a=operandValue(instruction,dst,pc,read),b=operandValue(instruction,src,pc,read);if(a&&b){value=*a;value->value=mnemonic==ZYDIS_MNEMONIC_ADD?a->value+b->value:a->value-b->value;if(!value->readonlySlot)value->readonlySlot=b->readonlySlot;}}
  }
 }
 for(unsigned n=0;n<instruction.operand_count;++n){const auto& operand=operands[n];if(operand.type==ZYDIS_OPERAND_TYPE_REGISTER&&(operand.actions&ZYDIS_OPERAND_ACTION_MASK_WRITE)){auto i=index(operand.reg.value);if(i>=0)liveMask_&=~(uint16_t(1)<<i);}}
 if(value&&destination>=0&&(width==32||width==64)){if(width==32||bits_==32)value->value&=0xffffffffULL;registers_[destination]=value;liveMask_|=uint16_t(1)<<destination;}
}
}
