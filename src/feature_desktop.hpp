#pragma once
#include "core.hpp"
#include <future>
#include <deque>
#include <set>
namespace scratcher {
// The transport submits commands; only the desktop thread drains and applies them.
class DesktopMailbox {
public:
 struct Command { Json request; std::promise<Json> reply; bool completed=false; };
 using Pending=std::shared_ptr<Command>;
 std::future<Json> post(Json request);
 std::vector<Pending> drain();
 void resolve(const Pending&,Json result);
 void reject(const Pending&,const std::string& message);
 void close();
private:
 std::mutex mutex_;
 std::deque<Pending> queued_;
 std::set<Pending> pending_;
 bool closed_=false;
};
std::string desktopView(const Json& value);
void validateDesktopArguments(const std::string& name,const Json& args);
}
