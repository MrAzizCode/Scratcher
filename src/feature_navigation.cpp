#include "feature_navigation.hpp"
#include <algorithm>
#include <cctype>
#include <limits>

namespace scratcher {
void NavigationHistory::visit(Address value){
    if(current()==value)return;
    if(!entries_.empty())entries_.resize(cursor_+1);
    entries_.push_back(value);
    if(entries_.size()>512)entries_.erase(entries_.begin());
    cursor_=entries_.size()-1;
}
std::optional<Address> NavigationHistory::back(){if(!canBack())return {};--cursor_;return current();}
std::optional<Address> NavigationHistory::forward(){if(!canForward())return {};++cursor_;return current();}
std::optional<Address> NavigationHistory::current()const {return entries_.empty()?std::nullopt:std::optional<Address>(entries_[cursor_]);}
bool NavigationHistory::canBack()const {return !entries_.empty()&&cursor_>0;}
bool NavigationHistory::canForward()const {return !entries_.empty()&&cursor_+1<entries_.size();}
void NavigationHistory::clear(){entries_.clear();cursor_=0;}

namespace {
std::string trim(std::string text){auto first=text.find_first_not_of(" \t\r\n");return first==std::string::npos?std::string():text.substr(first,text.find_last_not_of(" \t\r\n")-first+1);}
std::string upper(std::string text){for(auto& c:text)c=static_cast<char>(std::toupper(static_cast<unsigned char>(c)));return text;}
std::optional<Address> literal(std::string text){
    text=upper(trim(text));
    for(const auto* prefix:{"SHORT ","NEAR ","FAR ","OFFSET "})if(text.rfind(prefix,0)==0)text=trim(text.substr(std::strlen(prefix)));
    unsigned radix=10;size_t start=0;
    if(text.size()>2&&text.rfind("0X",0)==0){radix=16;start=2;}
    else if(!text.empty()&&text.back()=='H'){radix=16;text.pop_back();}
    if(start>=text.size())return {};
    Address value=0;
    for(size_t i=start;i<text.size();++i){unsigned char c=text[i];unsigned digit=c>='0'&&c<='9'?c-'0':c>='A'&&c<='F'?c-'A'+10:255;
        if(digit>=radix||value>(UINT64_MAX-digit)/radix)return {};value=value*radix+digit;}
    return value;
}
std::optional<Address> memoryTarget(const Instruction& instruction,const std::string& text){
    auto begin=text.find('['),end=text.find(']',begin);
    if(begin==std::string::npos||end==std::string::npos||text.find('[',begin+1)!=std::string::npos||text.find(']',end+1)!=std::string::npos||text.find(':')!=std::string::npos)return {};
    auto expression=upper(text.substr(begin+1,end-begin-1));
    expression.erase(std::remove_if(expression.begin(),expression.end(),[](unsigned char c){return std::isspace(c)!=0;}),expression.end());
    if(auto value=literal(expression))return value;
    const bool eip=expression.rfind("EIP",0)==0;
    if(!eip&&expression.rfind("RIP",0)!=0)return {};
    if(instruction.length<=0||Address(instruction.length)>UINT64_MAX-instruction.va)return {};
    Address pc=instruction.va+Address(instruction.length);
    if(eip)pc&=0xffffffffULL;
    if(expression.size()==3)return pc;
    if(expression.size()<5||(expression[3]!='+'&&expression[3]!='-'))return {};
    auto displacement=literal(expression.substr(4));if(!displacement)return {};
    if(eip)return (expression[3]=='+'?pc+*displacement:pc-*displacement)&0xffffffffULL;
    if(expression[3]=='+'){if(*displacement>UINT64_MAX-pc)return {};return pc+*displacement;}
    if(*displacement>pc)return {};return pc-*displacement;
}
}

std::optional<Address> operandTarget(const Binary& binary,const Instruction& instruction){
    if(instruction.operands.find('[')!=std::string::npos){auto value=memoryTarget(instruction,instruction.operands);return value&&binary.section(*value)?value:std::nullopt;}
    // Only complete immediate operands qualify; register displacements, segment
    // offsets and arithmetic expressions cannot be followed without live state.
    std::optional<Address> result;
    size_t start=0;
    do {auto end=instruction.operands.find(',',start);auto text=instruction.operands.substr(start,end==std::string::npos?end:end-start);
        if(auto value=literal(text);value&&binary.section(*value)){if(result&&*result!=*value)return {};result=value;}
        if(end==std::string::npos)break;start=end+1;
    }while(start<instruction.operands.size());
    return result;
}

Json describeAddress(const Binary& binary,Address value){
    Json result={{"address",hex(value)},{"mapped",false},{"executable",false},{"section",nullptr},{"function",nullptr},{"import",nullptr},{"name",""},{"names",Json::array()},{"offset",0},{"file_offset",nullptr}};
    const auto* section=binary.section(value);if(!section)return result;
    auto delta=value-section->va;
    result["mapped"]=true;result["executable"]=section->executable;result["offset"]=delta;
    result["section"]={{"name",section->name},{"address",hex(section->va)},{"offset",delta},{"executable",section->executable},{"writable",section->writable}};
    if(delta<section->fileSize&&section->offset<=UINT64_MAX-delta&&binary.has(section->offset+delta,1))result["file_offset"]=section->offset+delta;
    const Function* function=nullptr;
    for(const auto& candidate:binary.functions){
        if(candidate.va>value||binary.section(candidate.va)!=section)continue;
        if(candidate.end>candidate.va&&value>=candidate.end)continue;
        if(!section->executable&&candidate.va!=value)continue;
        if(!function||candidate.va>function->va)function=&candidate;
    }
    // An unknown boundary ends at the next function, even if that next function
    // has an explicit end that excludes the selected address.
    if(function&&function->end<=function->va)for(const auto& next:binary.functions)if(next.va>function->va&&next.va<=value&&binary.section(next.va)==section){function=nullptr;break;}
    if(function){auto offset=value-function->va;result["function"]={{"name",function->name},{"address",hex(function->va)},{"end",function->end?Json(hex(function->end)):Json(nullptr)},{"offset",offset}};result["name"]=function->name;result["names"].push_back(function->name);result["offset"]=offset;}
    for(const auto& import:binary.imports){auto width=Address(binary.bits/8);if(value<import.va||value-import.va>=width)continue;
        result["import"]={{"name",import.name},{"module",import.module},{"address",hex(import.va)},{"offset",value-import.va}};
        result["name"]=import.name;result["offset"]=value-import.va;result["names"].push_back(import.name);if(!import.module.empty())result["names"].push_back(import.module+"!"+import.name);break;
    }
    if(result["name"]=="")result["name"]=section->name;
    return result;
}
}
