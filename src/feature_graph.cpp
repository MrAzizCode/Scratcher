#include "feature_graph.hpp"
#include "feature_advanced_manual.hpp"
#include "feature_advanced_architectures.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "action.hh"
#include "feature_advanced_pseudocode.hpp"
#include "feature_flow_constants.hpp"
#include <algorithm>
#include <cctype>
#include <deque>
#include <limits>
#include <optional>
#include <set>

namespace scratcher {
namespace {
enum class Flow { Linear, Call, Conditional, Jump, Return, Stop, Invalid };
std::string upper(std::string value) {
    for (auto& c : value) c=static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return value;
}
std::string trim(std::string value) {
    auto first=value.find_first_not_of(" \t\r\n");
    if(first==std::string::npos) return {};
    return value.substr(first,value.find_last_not_of(" \t\r\n")-first+1);
}
// Accept only a complete immediate operand. In particular, do not turn an
// indirect memory operand's displacement into a branch destination.
std::optional<Address> directTarget(std::string operand) {
    operand=trim(operand);
    for (const auto* prefix : {"SHORT ", "NEAR ", "FAR "}) {
        if (upper(operand).rfind(prefix,0)==0) operand=trim(operand.substr(std::strlen(prefix)));
    }
    if (operand.empty() || operand.find_first_of("[]()*,:+-")!=std::string::npos) return {};
    int base=10;
    if (operand.size()>2 && operand[0]=='0' && (operand[1]=='x'||operand[1]=='X')) {
        operand=operand.substr(2); base=16;
    } else if (operand.back()=='h'||operand.back()=='H') {
        operand.pop_back(); base=16;
    }
    if(operand.empty()) return {};
    if(!std::all_of(operand.begin(),operand.end(),[&](unsigned char c){return base==16?std::isxdigit(c)!=0:std::isdigit(c)!=0;})) return {};
    try {size_t used=0;auto result=std::stoull(operand,&used,base);if(used==operand.size())return result;} catch(const std::exception&) {}
    return {};
}
Flow classify(const std::string& input,const std::string& operands) {
    auto m=upper(trim(input));
    if(m=="DB"||m=="INVALID"||m=="UNDEFINED")return Flow::Invalid;
    if(m=="CALL"||m=="CALLF"||m=="BL"||m=="BLX"||m=="BLR"||m=="JAL"||m=="JALR")return Flow::Call;
    if(m=="JR"&&(upper(trim(operands))=="RA"||upper(trim(operands))=="$RA"))return Flow::Return;
    if(m=="BX"&&upper(trim(operands))=="LR")return Flow::Return;
    if(m=="B"||m=="BR"||m=="J"||m=="JR")return Flow::Jump;
    if(m.starts_with("B.")||m=="CBZ"||m=="CBNZ"||m=="TBZ"||m=="TBNZ"||m=="BEQ"||m=="BNE"||m=="BEQZ"||m=="BNEZ"||m=="BLT"||m=="BGE"||m=="BLTU"||m=="BGEU"||m=="BGTZ"||m=="BLEZ"||m=="BLTZ"||m=="BGEZ")return Flow::Conditional;
    if(m=="JMP"||m=="JMPF")return Flow::Jump;
    if((m.size()>1&&m[0]=='J')||m=="LOOP"||m=="LOOPE"||m=="LOOPNE"||m=="LOOPZ"||m=="LOOPNZ")return Flow::Conditional;
    if(m=="RET"||m=="RETF"||m=="RETN"||m=="IRET"||m=="IRETD"||m=="IRETQ")return Flow::Return;
    if(m=="HLT"||m=="UD2"||m=="INT3"||m=="INT"||m=="INTO")return Flow::Stop;
    return Flow::Linear;
}
struct Successor { Address target; std::string label; std::string source; };
struct Row { Instruction instruction; Flow flow=Flow::Linear; std::optional<Address> target; std::vector<Successor> successors; std::string exit;
    bool constantTransfer=false,pathLocal=true,lateJoin=false;Address constantTraceStart=0;std::optional<Address> readonlySlot;std::string targetSource; };
Json instructionJson(const Instruction& instruction) {
    return {{"address",hex(instruction.va)},{"length",instruction.length},{"bytes",instruction.bytes},{"mnemonic",instruction.mnemonic},{"operands",instruction.operands},{"prefixes",instruction.prefixes}};
}
}

Json buildControlFlowGraph(Engine& session,Address requested,size_t instructionBudget) {
    const auto* binary=session.binary();
    if(!binary)throw std::runtime_error("Open a binary first");
    if(!instructionBudget||instructionBudget>100000)throw std::runtime_error("Graph instruction budget must be between 1 and 100000");
    if(!binary->analysisCode(requested))throw std::runtime_error("Graph address is not executable");
    Address entry=requested;
    const Function* function=nullptr;
    for(const auto& candidate:binary->functions) {
        if(candidate.va==requested || (candidate.end>candidate.va && requested>=candidate.va && requested<candidate.end)) {
            if(!function || candidate.va>function->va || (candidate.va==function->va&&candidate.end>function->end)) function=&candidate;
        }
    }
    if(function)entry=function->va;
    const auto* section=binary->section(entry);
    if(!section||!binary->analysisCode(entry))throw std::runtime_error("Function address is not executable");
    const auto available=std::min(section->memorySize,section->fileSize);
    if(available>std::numeric_limits<Address>::max()-section->va)throw std::runtime_error("Graph address range overflow");
    Address end=section->va+available;
    bool metadataBound=function&&function->end>entry;
    if(metadataBound)end=std::min(end,function->end);
    else for(const auto& candidate:binary->functions)if(candidate.va>entry)end=std::min(end,candidate.va);
    if(entry>=end)throw std::runtime_error("Graph address has no instruction bytes");
    auto inside=[&](Address va){return va>=entry&&va<end&&binary->analysisCode(va)&&manualClassification(session,va).value_or("undefined")!="data";};
    const bool x86=binary->language.starts_with("x86:")&&(binary->bits==32||binary->bits==64);
    auto candidateTarget=[&](Address va){const auto* s=binary->section(va);return s&&binary->analysisCode(va)&&va-s->va<std::min(s->memorySize,s->fileSize)&&manualClassification(session,va).value_or("undefined")!="data";};
    size_t pointerBytesRead=0;
    const size_t pointerReadBudget=std::min<size_t>(65536,instructionBudget*8);
    FlowPointerReader readPointer=[&](Address at,size_t width)->std::optional<uint64_t>{
        if(!width||width>8||at>std::numeric_limits<Address>::max()-width||width>pointerReadBudget-pointerBytesRead)return {};
        // IAT values are mutable loader state even when the containing section
        // lacks a writable flag. Do not reinterpret them as immutable targets.
        for(const auto& imp:binary->imports){const auto slotWidth=static_cast<Address>(binary->bits/8);if(imp.va>std::numeric_limits<Address>::max()-slotWidth)return {};if(at<imp.va+slotWidth&&imp.va<at+width)return {};}
        const auto* storage=binary->section(at);
        if(!storage||storage->writable)return {};
        const auto delta=at-storage->va,extent=std::min(storage->fileSize,storage->memorySize);
        if(delta>extent||width>extent-delta||storage->offset>std::numeric_limits<Address>::max()-delta)return {};
        const auto offset=storage->offset+delta;
        if(!binary->has(offset,width))return {};
        pointerBytesRead+=width;uint64_t value=0;std::memcpy(&value,binary->bytes()+offset,width);return value;
    };
    // Resolve only the requested function and only when its reachable listing
    // encounters an indirect jump. Loader candidates and recovered table entries
    // remain evidence rather than an assertion of full semantic analysis.
    std::map<Address,std::vector<Address>> recoveredSwitches;
    Json switchEvidence=Json::array(),recoveryIssues=Json::array();
    bool recoveryInspected=false,recoveryAttempted=false;
    size_t effectiveNativeInstructions=0,effectiveNativeTableEntries=0;
    auto recoverSwitches=[&] {
        if(recoveryInspected)return;
        recoveryInspected=true;
        if(session.cancelled())throw std::runtime_error("Operation cancelled");
        try {
            auto* architecture=session.nativeArchitecture();
            auto at=ghidra::Address(architecture->getDefaultCodeSpace(),entry);
            auto* scope=architecture->symboltab->getGlobalScope();
            auto* nativeFunction=scope->queryFunction(at);
            if(!nativeFunction||!nativeFunction->isProcStarted()) {
                struct Limits {
                    ghidra::Architecture* architecture; ghidra::uint4 instructions,tables;
                    ~Limits(){architecture->max_instructions=instructions;architecture->max_jumptable_size=tables;}
                } limits{architecture,architecture->max_instructions,architecture->max_jumptable_size};
                recoveryAttempted=true;
                if(!nativeFunction)nativeFunction=scope->addFunction(at,"sub_"+hex(entry).substr(2))->getFunction();
                applyPseudocodeOptions(session,entry);
                // Persisted pseudocode settings may raise these limits. Apply
                // graph bounds after all saved options, immediately before action.
                architecture->max_instructions=std::min({architecture->max_instructions,static_cast<ghidra::uint4>(instructionBudget),ghidra::uint4(4096)});
                architecture->max_jumptable_size=std::min({architecture->max_jumptable_size,static_cast<ghidra::uint4>(instructionBudget),ghidra::uint4(4096)});
                effectiveNativeInstructions=architecture->max_instructions;
                effectiveNativeTableEntries=architecture->max_jumptable_size;
                auto* action=architecture->allacts.getCurrent();
                action->reset(*nativeFunction);
                try{action->perform(*nativeFunction);}
                catch(...){architecture->clearAnalysis(nativeFunction);throw;}

            }
            if(session.cancelled())throw std::runtime_error("Operation cancelled");
            if(!nativeFunction||!nativeFunction->isProcStarted())return;
            size_t totalEntries=0;
            for(int i=0;i<nativeFunction->numJumpTables();++i) {
                if(session.cancelled())throw std::runtime_error("Operation cancelled");
                auto* table=nativeFunction->getJumpTable(i);
                auto switchAt=table->getOpAddress();
                if(switchAt.getSpace()!=architecture->getDefaultCodeSpace())continue;
                auto branch=switchAt.getOffset();
                if(!inside(branch)||!table->isRecovered()||table->isOverride())continue;
                auto entries=table->numEntries();
                Json evidence={{"address",hex(branch)},{"source","decompiler_recovered_switch"},{"entries",entries},{"partial",table->isPartial()},{"targets",Json::array()}};
                if(entries<1||table->isPartial()||static_cast<size_t>(entries)>instructionBudget-totalEntries) {
                    evidence["accepted"]=false;evidence["reason"]=table->isPartial()?"partial_table":"entry_budget";
                    switchEvidence.push_back(std::move(evidence));continue;
                }
                totalEntries+=static_cast<size_t>(entries);
                std::set<Address> targets,foldedDefaults;
                bool valid=true;
                for(int j=0;j<entries;++j) {
                    if(session.cancelled())throw std::runtime_error("Operation cancelled");
                    auto target=table->getAddressByIndex(j);
                    auto destination=target.getOffset();
                    const auto* targetSection=binary->section(destination);
                    bool mapped=targetSection&&destination>=targetSection->va&&destination-targetSection->va<std::min(targetSection->memorySize,targetSection->fileSize);
                    if(target.getSpace()!=architecture->getDefaultCodeSpace()||!mapped||!binary->analysisCode(destination)||manualClassification(session,destination).value_or("undefined")=="data") {valid=false;break;}
                    // Normalization folds the already decoded guard's default
                    // branch into a synthetic unlabelled switch destination.
                    // Keep that edge at its machine conditional, rather than
                    // inventing another edge from the indirect JMP itself.
                    if(table->hasFoldedDefault()&&table->isLabelled()&&nativeFunction->isProcComplete()&&table->getLabelByIndex(j)==ghidra::JumpValues::NO_LABEL)
                        foldedDefaults.insert(destination);
                    else targets.insert(destination);
                }
                evidence["folded_guard_default_targets"]=Json::array();
                for(auto target:foldedDefaults)evidence["folded_guard_default_targets"].push_back(hex(target));
                evidence["accepted"]=valid&&!targets.empty();
                if(valid&&!targets.empty()) {
                    auto& recovered=recoveredSwitches[branch];recovered.assign(targets.begin(),targets.end());
                    for(auto target:targets)evidence["targets"].push_back(hex(target));
                } else evidence["reason"]="invalid_target";
                switchEvidence.push_back(std::move(evidence));
            }
        } catch(const ghidra::LowlevelError&) {
            recoveryIssues.push_back({{"reason","switch_recovery_failed"}});
        } catch(const std::exception&) {
            if(session.cancelled())throw;
            recoveryIssues.push_back({{"reason","switch_recovery_failed"}});
        }
    };
    std::map<Address,Row> rows;
    std::map<Address,std::string> failed;
    std::set<Address> leaders{entry},queued{entry};
    std::deque<Address> pending{entry};
    bool exhausted=false;
    auto enqueue=[&](Address target){
        if(!inside(target))return;
        leaders.insert(target);
        if(queued.insert(target).second)pending.push_back(target);
    };
    auto overlaps=[&](Address va){auto it=rows.upper_bound(va);if(it==rows.begin())return false;--it;return va>it->first&&va-it->first<static_cast<Address>(it->second.instruction.length);};
    while(!pending.empty()&&!exhausted) {
        if(session.cancelled())throw std::runtime_error("Operation cancelled");
        Address va=pending.front();pending.pop_front();
        FlowConstants facts(x86?binary->bits:64);Address factTraceStart=va;
        while(inside(va)&&!rows.count(va)&&!failed.count(va)) {
            auto indexed=std::lower_bound(binary->functions.begin(),binary->functions.end(),va,[](const Function& f,Address at){return f.va<at;});
            if(va!=factTraceStart&&(leaders.count(va)||(indexed!=binary->functions.end()&&indexed->va==va))){facts.reset();factTraceStart=va;}
            if(session.cancelled())throw std::runtime_error("Operation cancelled");
            if(rows.size()>=instructionBudget){exhausted=true;break;}
            if(overlaps(va)){failed[va]="overlapping_target";break;}
            std::vector<Instruction> decoded;
            try{decoded=session.disassemble(va,1);}catch(const std::exception&){failed[va]="decode_error";break;}
            if(decoded.empty()||decoded.front().va!=va||decoded.front().length<=0){failed[va]="decode_error";break;}
            auto instruction=std::move(decoded.front());
            if(static_cast<Address>(instruction.length)>end-va){failed[va]="range_end";break;}
            auto next=va+static_cast<Address>(instruction.length);
            bool classifiedData=false;for(auto byte=va;byte<next;++byte)if(manualClassification(session,byte).value_or("undefined")=="data"){classifiedData=true;break;}
            if(classifiedData){failed[va]="manual_data";break;}
            auto existing=rows.upper_bound(va);
            if(existing!=rows.end()&&existing->first<next){failed[va]="overlapping_instruction";break;}
            Row row;row.instruction=std::move(instruction);row.flow=classify(row.instruction.mnemonic,row.instruction.operands);
            if(row.flow==Flow::Call||row.flow==Flow::Jump||row.flow==Flow::Conditional){auto operand=row.instruction.operands;if(binaryArchitecture(*binary)!="x86"&&binaryArchitecture(*binary)!="x64"){auto comma=operand.find_last_of(',');if(comma!=std::string::npos)operand=operand.substr(comma+1);operand=trim(operand);if(operand.starts_with("#"))operand.erase(0,1);}row.target=directTarget(operand);}
            if(x86){
                ZydisDecoder decoder{};ZydisDecoderInit(&decoder,binary->bits==64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32,binary->bits==64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32);
                ZydisDecodedInstruction native{};ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
                auto offset=section->offset+(va-section->va);auto length=static_cast<size_t>(std::min<Address>(15,end-va));
                if(binary->has(offset,length)&&ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,binary->bytes()+offset,length,&native,operands))&&native.length==row.instruction.length){
                    // Inspect the incoming facts before the transfer kills them.
                    if(!row.target&&(row.flow==Flow::Call||row.flow==Flow::Jump)&&native.operand_count_visible){
                        auto value=facts.operandValue(native,operands[0],va,readPointer);
                        if(value&&candidateTarget(value->value)){
                            row.target=value->value;row.constantTransfer=true;row.constantTraceStart=factTraceStart;row.readonlySlot=value->readonlySlot;
                            row.pathLocal=operands[0].type!=ZYDIS_OPERAND_TYPE_MEMORY||operands[0].mem.index!=ZYDIS_REGISTER_NONE||(operands[0].mem.base!=ZYDIS_REGISTER_NONE&&operands[0].mem.base!=ZYDIS_REGISTER_RIP&&operands[0].mem.base!=ZYDIS_REGISTER_EIP);
                            row.targetSource=!row.pathLocal?"fixed_readonly_memory_pointer":value->readonlySlot?"straight_line_readonly_pointer_candidate":"straight_line_register_constant_candidate";
                        }
                    }
                    facts.observe(native,operands,va,readPointer);
                }else facts.reset();
            }
            auto add=[&](Address target,const char* label){row.successors.push_back({target,label,{}});};
            if(row.flow==Flow::Conditional) {
                if(row.target){add(*row.target,"true");enqueue(*row.target);}else row.exit="indirect_branch";
                add(next,"false");enqueue(next);
            } else if(row.flow==Flow::Jump) {
                auto manualTargets=manualSwitchTargets(session,va);
                if(row.constantTransfer&&!manualTargets.empty()){
                    row.target.reset();row.constantTransfer=false;row.targetSource.clear();row.readonlySlot.reset();
                    for(auto target:manualTargets){row.successors.push_back({target,"switch","manual_switch"});enqueue(target);}
                }else if(row.target){row.successors.push_back({*row.target,"jump",row.targetSource});enqueue(*row.target);}else {
                    auto targets=manualSwitchTargets(session,va);
                    std::string source="manual_switch";
                    if(targets.empty()) {
                        recoverSwitches();
                        auto recovered=recoveredSwitches.find(va);
                        if(recovered!=recoveredSwitches.end())targets=recovered->second;
                        source="decompiler_recovered_switch";
                    }
                    if(targets.empty())row.exit="indirect_jump";
                    else for(auto target:targets){row.successors.push_back({target,"switch",source});enqueue(target);}
                }
            } else if(row.flow==Flow::Return)row.exit="return";
            else if(row.flow==Flow::Stop)row.exit="stop";
            else if(row.flow==Flow::Invalid)row.exit="invalid_instruction";
            else add(next,"fallthrough");
            const auto flow=row.flow;
            rows.emplace(va,std::move(row));
            if(flow!=Flow::Linear){facts.reset();factTraceStart=next;}
            if(flow!=Flow::Linear&&flow!=Flow::Call)break;
            va=next;
        }
    }
    // A leader discovered after a trace may bypass its defining instructions.
    // Keep only path-local candidate evidence, with an explicit residual edge;
    // never promote the first visited path's fact into an all-path result.
    for(auto& [va,row]:rows)if(row.constantTransfer&&row.pathLocal){
        auto leader=leaders.upper_bound(row.constantTraceStart);
        row.lateJoin=leader!=leaders.end()&&*leader<=va;
        row.exit=row.flow==Flow::Call?"indirect_call_residual_unknown":"indirect_jump_residual_unknown";
    }
    // Each reachable branch destination is a leader even if it was discovered
    // after its containing trace; this splits loops and joins into real blocks.
    Json nodes=Json::array(),edges=Json::array(),calls=Json::array(),issues=Json::array();
    std::map<Address,Address> owner;
    std::map<Address,std::vector<Address>> blocks;
    for(const auto& [va,row]:rows) {
        if(owner.count(va))continue;
        Address current=va;
        auto& block=blocks[va];
        while(true) {
            auto it=rows.find(current);
            if(it==rows.end()||owner.count(current))break;
            block.push_back(current);owner[current]=va;
            const auto& item=it->second;
            if(item.flow!=Flow::Linear&&item.flow!=Flow::Call)break;
            if(item.successors.empty())break;
            auto next=item.successors.front().target;
            if(leaders.count(next))break;
            current=next;
        }
    }
    for(const auto& [start,block]:blocks) {
        Json instructions=Json::array(),blockCalls=Json::array();
        for(auto va:block) {
            const auto& row=rows.at(va);instructions.push_back(instructionJson(row.instruction));
            if(row.flow==Flow::Call) {
                Json call={{"address",hex(va)},{"target",row.target?Json(hex(*row.target)):Json(nullptr)},{"indirect",!row.target.has_value()||row.constantTransfer},{"operands",row.instruction.operands}};
                if(row.constantTransfer){call["source_provenance"]=row.targetSource;call["path_local"]=row.pathLocal;call["all_paths_proven"]=!row.pathLocal;call["residual_unknown"]=row.pathLocal;call["later_incoming_join"]=row.lateJoin;if(row.readonlySlot)call["readonly_pointer_slot"]=hex(*row.readonlySlot);}
                blockCalls.push_back(call);calls.push_back(call);
            }
        }
        const auto& last=rows.at(block.back());
        std::string exit=last.exit;
        for(const auto& successor:last.successors) {
            bool internal=owner.count(successor.target)!=0;
            Json edge={{"source",hex(start)},{"target",hex(internal?owner.at(successor.target):successor.target)},{"label",successor.label},{"external",!inside(successor.target)},{"unresolved",!internal}};
            if(!successor.source.empty())edge["source_provenance"]=successor.source;
            if(last.constantTransfer){edge["path_local"]=last.pathLocal;edge["all_paths_proven"]=!last.pathLocal;edge["residual_unknown"]=last.pathLocal;edge["later_incoming_join"]=last.lateJoin;if(last.readonlySlot)edge["readonly_pointer_slot"]=hex(*last.readonlySlot);}
            if(!internal) {
                auto failure=failed.find(successor.target);
                edge["reason"]=!inside(successor.target)?"function_boundary":failure!=failed.end()?failure->second:exhausted?"instruction_budget":"unresolved_target";
                if(exit.empty())exit=edge["reason"].get<std::string>();
            }
            edges.push_back(std::move(edge));
        }
        nodes.push_back({{"id",hex(start)},{"address",hex(start)},{"end",hex(last.instruction.va+last.instruction.length)},{"instruction_count",block.size()},{"instructions",instructions},{"calls",blockCalls},{"exit",exit}});
    }
    for(const auto& [va,reason]:failed)issues.push_back({{"address",hex(va)},{"reason",reason}});
    bool unresolved=false;
    for(const auto& [va,row]:rows)if((row.constantTransfer&&row.pathLocal)||row.exit=="indirect_jump"||row.exit=="indirect_branch"||row.exit=="invalid_instruction")unresolved=true;
    return {{"entry",hex(entry)},{"requested_address",hex(requested)},{"name",function?function->name:"sub_"+hex(entry).substr(2)},
        {"range",{{"start",hex(entry)},{"end",hex(end)},{"source",metadataBound?"function_metadata":"section_and_function_index"}}},
        {"nodes",nodes},{"edges",edges},{"calls",calls},{"issues",issues},{"instruction_count",rows.size()},
        {"instruction_budget",instructionBudget},{"truncated",exhausted},{"complete",!exhausted&&failed.empty()&&!unresolved},
        {"semantic_analysis_complete",false},{"switch_tables",switchEvidence},
        {"constant_transfer_policy","Straight-line candidates only; reset at trace entries, known leaders, splits and calls. Residual unknown paths remain; no dominance or all-path proof."},
        {"readonly_pointer_bytes_read",pointerBytesRead},{"readonly_pointer_read_budget",pointerReadBudget},
        {"switch_recovery",{{"inspected",recoveryInspected},{"requested_function_analysis_attempted",recoveryAttempted},{"instruction_limit",std::min(instructionBudget,size_t(4096))},{"effective_native_instruction_limit",effectiveNativeInstructions},{"effective_native_table_limit",effectiveNativeTableEntries},{"issues",recoveryIssues}}}};
}
}
