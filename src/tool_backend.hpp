#pragma once
#include "core.hpp"
#include <optional>
namespace scratcher {
class ToolBackendError:public std::runtime_error {
 int code_;
public:
 ToolBackendError(int code,const std::string& message):std::runtime_error(message),code_(code){}
 int code()const noexcept { return code_; }
};
class ToolBackend {
public:
 virtual ~ToolBackend()=default;
 virtual Json toolDefinitions()const=0;
 virtual std::optional<Json> invoke(const std::string& name,const Json& arguments)=0;
 virtual Json resourcesList()const { return {{"resources",Json::array()}}; }
 virtual Json resourceRead(const std::string&) { throw ToolBackendError(-32002,"Resource not found"); }
 virtual Json promptsList()const { return {{"prompts",Json::array()}}; }
 virtual Json promptGet(const std::string&,const Json&) { throw std::runtime_error("Unknown prompt"); }
};
}
