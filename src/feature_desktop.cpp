#include "feature_desktop.hpp"
#include <algorithm>
namespace scratcher {
std::future<Json> DesktopMailbox::post(Json request){
 auto command=std::make_shared<Command>();command->request=std::move(request);auto future=command->reply.get_future();
 std::lock_guard lock(mutex_);if(closed_)throw std::runtime_error("Desktop is closing");if(pending_.size()>=256)throw std::runtime_error("Desktop command queue is full");queued_.push_back(command);pending_.insert(command);return future;
}
std::vector<DesktopMailbox::Pending> DesktopMailbox::drain(){std::lock_guard lock(mutex_);std::vector<Pending> result(queued_.begin(),queued_.end());queued_.clear();return result;}
void DesktopMailbox::resolve(const Pending& command,Json result){std::lock_guard lock(mutex_);if(command->completed)return;command->completed=true;command->reply.set_value(std::move(result));pending_.erase(command);}
void DesktopMailbox::reject(const Pending& command,const std::string& message){std::lock_guard lock(mutex_);if(command->completed)return;command->completed=true;command->reply.set_exception(std::make_exception_ptr(std::runtime_error(message)));pending_.erase(command);}
void DesktopMailbox::close(){std::lock_guard lock(mutex_);closed_=true;for(auto&command:pending_){command->completed=true;command->reply.set_exception(std::make_exception_ptr(std::runtime_error("Desktop is closing")));}pending_.clear();queued_.clear();}
std::string desktopView(const Json& value){
 if(!value.is_string())throw std::runtime_error("view must be a string");auto name=value.get<std::string>();
 static const std::vector<std::string> views={"Overview","Pseudocode","Disassembly","Hex","Strings","Imports","Graph","References","Calls","Search","Bookmarks","Types","Patches","Automation","Workbench","Acceleration"};
 if(std::find(views.begin(),views.end(),name)==views.end())throw std::runtime_error("Unknown workspace view");return name;
}
void validateDesktopArguments(const std::string&name,const Json&args){
 if(!args.is_object())throw std::runtime_error("arguments must be an object");
 if(args.contains("view"))desktopView(args["view"]);
 if(name=="set_active_view"&&!args.contains("view"))throw std::runtime_error("view is required");
 if(name=="navigate_to"){if(!args.contains("address"))throw std::runtime_error("address is required");address(args["address"]);}
 if(name=="set_function_filter"){
  if(!args.contains("query")||!args["query"].is_string())throw std::runtime_error("query must be a string");auto&query=args["query"].get_ref<const std::string&>();if(query.size()>508)throw std::runtime_error("query exceeds 127 characters");size_t characters=0;
  for(size_t i=0;i<query.size();++characters){auto lead=(unsigned char)query[i];size_t length=0;uint32_t code=0;if(lead>0&&lead<128){length=1;code=lead;}else if(lead>=0xc2&&lead<=0xdf){length=2;code=lead&31;}else if(lead>=0xe0&&lead<=0xef){length=3;code=lead&15;}else if(lead>=0xf0&&lead<=0xf4){length=4;code=lead&7;}else throw std::runtime_error("query must contain valid UTF-8");if(i+length>query.size())throw std::runtime_error("query must contain valid UTF-8");for(size_t j=1;j<length;j++){auto next=(unsigned char)query[i+j];if((next&0xc0)!=0x80)throw std::runtime_error("query must contain valid UTF-8");code=(code<<6)|(next&63);}if((length==3&&code<0x800)||(length==4&&code<0x10000)||code>0x10ffff||(code>=0xd800&&code<=0xdfff))throw std::runtime_error("query must contain valid UTF-8");i+=length;}
  if(characters>127)throw std::runtime_error("query exceeds 127 characters");
 }
 if(args.contains("include_views")&&!args["include_views"].is_boolean())throw std::runtime_error("include_views must be boolean");
 if(args.contains("include_result")&&!args["include_result"].is_boolean())throw std::runtime_error("include_result must be boolean");
 if(name=="list_jobs"||name=="await_job"||name=="get_activity_log")for(const auto&key:{"offset","limit","timeout_ms"})if(args.contains(key)){if(!args[key].is_number_integer()||args[key].get<long double>()<0)throw std::runtime_error(std::string(key)+" must be a nonnegative integer");auto value=args[key].get<long double>();if(value>(std::string(key)=="offset"?1000000:std::string(key)=="limit"?512:30000))throw std::runtime_error(std::string(key)+" exceeds its limit");}
 if(name=="submit_job"){if(!args.contains("tool")||!args["tool"].is_string())throw std::runtime_error("tool must be a string");if(args.contains("arguments")&&!args["arguments"].is_object())throw std::runtime_error("arguments must be an object");}
}
}
