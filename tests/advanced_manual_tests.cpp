#include "feature_advanced_manual.hpp"
#include <fstream>
#include <iostream>
#include <functional>
#include <cstring>

using namespace scratcher;
namespace {
int checks=0;
void check(bool condition,const char* label){++checks;if(!condition)throw std::runtime_error(label);}
void reject(const std::function<void()>& operation,const char* label){bool rejected=false;try{operation();}catch(const std::exception&){rejected=true;}check(rejected,label);}
Json call(Engine& engine,const char* name,Json args=Json::object()){auto result=callManualTool(engine,name,args);if(!result)throw std::runtime_error("Missing manual tool dispatch");return *result;}
}
int main(){try{
 auto root=executableDir()/"advanced-manual-fixtures";std::filesystem::create_directories(root);auto path=root/"manual.bin";
 std::vector<uint8_t> bytes(256,0x90);bytes[0]=0xb8;bytes[1]=0x41;bytes[2]=bytes[3]=bytes[4]=0;bytes[5]=0xc3;bytes[8]=0xff;bytes[9]=0xe0;
 uint64_t first=0x1000,second=0x1005;std::memcpy(bytes.data()+128,&first,8);std::memcpy(bytes.data()+136,&second,8);
 int32_t relativeFirst=-0x90,relativeSecond=-0x8b;std::memcpy(bytes.data()+144,&relativeFirst,4);std::memcpy(bytes.data()+148,&relativeSecond,4);
 uint64_t invalid=0x5000;std::memcpy(bytes.data()+160,&invalid,8);
 {std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
 Engine engine;check(manualTools().size()==14,"manual tool count");reject([&]{call(engine,"get_manual_analysis");},"manual tools require an input");check(!callManualTool(engine,"foreign_tool",Json::object()),"foreign tool is not handled");engine.open(path);
 auto bounded=call(engine,"set_function_bounds",{{"address","0x1000"},{"end","0x1010"}});check(bounded["end"]=="0x1010","explicit bounds applied");
 call(engine,"create_function",{{"address","0x1010"},{"end","0x1020"},{"name","next_function"}});check(engine.binary()->functions.size()==2,"manual function created");
 reject([&]{call(engine,"create_function",{{"address","0x1006"},{"end","0x1011"},{"name","overlap"}});},"overlapping function rejected");
 reject([&]{call(engine,"set_function_bounds",{{"address","0x1000"},{"end","0x1011"}});},"enlarging across next function rejected");
 reject([&]{call(engine,"split_function",{{"address","0x1000"},{"split_address","0x1002"},{"name","inside_instruction"}});},"split inside instruction rejected");
 auto split=call(engine,"split_function",{{"address","0x1000"},{"split_address","0x1005"},{"name","tail"}});check(split["first"]["end"]=="0x1005"&&split["second"]["end"]=="0x1010","split preserved exact ranges");check(engine.binary()->functions.size()==3,"split indexed both functions");
 auto merged=call(engine,"merge_functions",{{"address","0x1000"},{"second_address","0x1005"}});check(merged["end"]=="0x1010"&&engine.binary()->functions.size()==2,"merge restores original span");check(manuallyDeletedFunction(engine,0x1005),"merge prevents rediscovery of removed start");
 call(engine,"delete_function",{{"address","0x1010"}});check(manuallyDeletedFunction(engine,0x1010),"delete remembers removed start");call(engine,"create_function",{{"address","0x1010"},{"end","0x1020"},{"name","recreated"}});check(!manuallyDeletedFunction(engine,0x1010),"explicit recreation clears deletion");
 call(engine,"define_data",{{"address","0x1020"},{"end","0x1040"},{"data_type","dword"}});check(manualClassification(engine,0x1024)=="data","data classification recorded");
 call(engine,"define_code",{{"address","0x1028"},{"end","0x1030"}});check(manualClassification(engine,0x1029)=="code"&&manualClassification(engine,0x1030)=="data","overriding range preserves surrounding data");
 auto cleared=call(engine,"clear_definition",{{"address","0x102c"},{"end","0x1034"}});check(cleared["definitions_touched"]==2,"clear updates each overlapping definition");check(!manualClassification(engine,0x1030)&&manualClassification(engine,0x1034)=="data","half-open clear keeps outside metadata");
 reject([&]{call(engine,"create_function",{{"address","0x1034"},{"end","0x1038"},{"name","in_data"}});},"function starts cannot be data");
 reject([&]{call(engine,"define_data",{{"address","0x1040"},{"end","0x1043"},{"data_type","dword"}});},"data length validates element width");
 reject([&]{call(engine,"define_code",{{"address","0x10ff"},{"end","0x1101"}});},"definitions reject crossing mapping end");
 auto listing=engine.disassemble(0x1000,1);auto original=listing[0].operands;
 auto character=call(engine,"set_operand_presentation",{{"address","0x1000"},{"index",1},{"presentation","character"}});check(character["display"]=="'A'","character rendering uses actual immediate");check(manualDisplayedOperands(engine,listing[0]).find("'A'")!=std::string::npos,"display helper applies override");check(listing[0].operands==original,"semantic operands stay intact");
 call(engine,"set_operand_presentation",{{"address","0x1000"},{"index",1},{"presentation","decimal"}});check(manualDisplayedOperands(engine,listing[0])=="EAX, 65","decimal rendering uses actual immediate");
 call(engine,"set_operand_presentation",{{"address","0x1000"},{"index",1},{"presentation","binary"}});check(manualDisplayedOperands(engine,listing[0])=="EAX, 0b1000001","binary rendering");
 reject([&]{call(engine,"set_operand_presentation",{{"address","0x1000"},{"index",0},{"presentation","decimal"}});},"numeric override rejects register operands");
 reject([&]{call(engine,"set_operand_presentation",{{"address","0x1000"},{"index",9},{"presentation","text"},{"text","invalid"}});},"override checks visible operand count");
 auto removed=call(engine,"clear_operand_presentation",{{"address","0x1000"},{"index",1}});check(removed["removed"]==true&&manualDisplayedOperands(engine,listing[0])==original,"clear restores original display");
 check(call(engine,"clear_operand_presentation",{{"address","0x1000"},{"index",1}})["removed"]==false,"missing display override removal reports false");
 auto table=call(engine,"define_switch_table",{{"address","0x1008"},{"table","0x1080"},{"entry_size",8},{"count",2}});check(table["targets"]==Json::array({"0x1000","0x1005"}),"absolute table reads captured targets");check(manualSwitchTargets(engine,0x1008)==std::vector<Address>({0x1000,0x1005}),"switch helper returns actual targets");
 table=call(engine,"define_switch_table",{{"address","0x1008"},{"table","0x1090"},{"entry_size",4},{"count",2},{"relative_base","0x1090"}});check(table["targets"]==Json::array({"0x1000","0x1005"}),"signed negative relative table resolves correctly");
 auto before=engine.advancedState();reject([&]{call(engine,"define_switch_table",{{"address","0x1008"},{"table","0x10a0"},{"entry_size",8},{"count",1}});},"unmapped switch target rejected");check(before==engine.advancedState(),"failed switch replacement preserves old definition");
 reject([&]{call(engine,"define_switch_table",{{"address","0x1000"},{"table","0x1080"},{"entry_size",8},{"count",2}});},"switch requires actual jump instruction");
 reject([&]{call(engine,"define_switch_table",{{"address","0x1008"},{"table","0x1080"},{"entry_size",3},{"count",1}});},"unsupported switch width rejected");
 auto page=call(engine,"get_manual_analysis",{{"offset",0},{"limit",1}});check(page["ranges"].size()==1&&page["totals"]["ranges"]==3,"manual metadata pagination reports total");
 validateManualState(*engine.binary(),engine.advancedState()["manual"]);auto corrupt=engine.advancedState()["manual"];corrupt["switches"][0]["targets"][0]="0x5000";reject([&]{validateManualState(*engine.binary(),corrupt);},"restored metadata rejects invalid switch targets");
 auto segment=call(engine,"edit_segment",{{"address","0x1000"},{"name","analysis_code"},{"writable",true}});check(segment["name"]=="analysis_code"&&engine.binary()->sections[0].writable,"segment metadata edit applied");check(segment["mapping_changed"]==false&&engine.binary()->sections[0].va==0x1000,"segment edit preserves mappings");
 reject([&]{call(engine,"edit_segment",{{"address","0x1000"},{"executable",false}});},"execute permission removal rejects existing functions");
 std::atomic_bool cancelled=true;engine.setCancellation(&cancelled);before=engine.advancedState();auto functionCount=engine.binary()->functions.size();reject([&]{call(engine,"create_function",{{"address","0x1040"},{"end","0x1050"},{"name","cancelled"}});},"cancelled manual edit rejected");check(engine.binary()->functions.size()==functionCount&&before==engine.advancedState(),"cancelled edit preserves state");engine.setCancellation(nullptr);
 check(call(engine,"remove_switch_table",{{"address","0x1008"}})["removed"]==true&&manualSwitchTargets(engine,0x1008).empty(),"switch removal clears resolution");
 std::cout<<"PASS: "<<checks<<" manual analysis checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}}
