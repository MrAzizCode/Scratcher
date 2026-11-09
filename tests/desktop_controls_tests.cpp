#include "feature_desktop.hpp"
#include <iostream>
#include <thread>
using namespace scratcher;
int main(){try{
 DesktopMailbox mailbox;auto future=mailbox.post({{"name","get_selection"}});auto commands=mailbox.drain();if(commands.size()!=1)throw std::runtime_error("Command not queued");mailbox.resolve(commands[0],{{"address","0x1000"}});mailbox.resolve(commands[0],{});if(future.get()["address"]!="0x1000")throw std::runtime_error("Reply lost");
 auto abandoned=mailbox.post({});auto inFlight=mailbox.drain();auto queued=mailbox.post({});mailbox.close();for(auto*f:{&abandoned,&queued}){bool rejected=false;try{f->get();}catch(...){rejected=true;}if(!rejected)throw std::runtime_error("Shutdown did not unblock request");}mailbox.resolve(inFlight[0],{});
 bool closed=false;try{mailbox.post({});}catch(...){closed=true;}if(!closed)throw std::runtime_error("Closed mailbox accepted work");
 for(auto*view:{"Overview","Graph","Pseudocode","Hex","Search","Automation"})if(desktopView(view)!=view)throw std::runtime_error("View mismatch");
 for(auto bad:{Json(3),Json("Invented")}){bool failed=false;try{desktopView(bad);}catch(...){failed=true;}if(!failed)throw std::runtime_error("Invalid view accepted");}
 validateDesktopArguments("navigate_to",{{"address","0x1000"},{"view","Graph"}});validateDesktopArguments("set_function_filter",{{"query","main"}});
 std::string unicode;for(int i=0;i<127;i++)unicode+="\xD9\x85";validateDesktopArguments("set_function_filter",{{"query",unicode}});
 for(auto bad:{Json{{"query",std::string(128,'a')}},Json{{"query",3}}}){bool failed=false;try{validateDesktopArguments("set_function_filter",bad);}catch(...){failed=true;}if(!failed)throw std::runtime_error("Invalid filter accepted");}
 DesktopMailbox threaded;std::future<Json> reply;std::thread client([&]{reply=threaded.post({{"name","get_selection"}});});client.join();auto batch=threaded.drain();threaded.resolve(batch[0],{{"selected",true}});if(!reply.get()["selected"])throw std::runtime_error("Threaded reply mismatch");
 DesktopMailbox bounded;std::vector<std::future<Json>> outstanding;for(int i=0;i<256;i++)outstanding.push_back(bounded.post({}));bool full=false;try{bounded.post({});}catch(...){full=true;}if(!full)throw std::runtime_error("Mailbox exceeded command limit");bounded.close();
 std::cout<<"Desktop controls passed\n";return 0;
 }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
