#pragma once
#include "core.hpp"
#include <functional>

namespace scratcher {
using BridgeHandler=std::function<Json(const Json&)>;
// Local, authenticated transport. The handler runs on a worker and must unblock
// outstanding requests during desktop shutdown before stop() joins workers.
class BridgeServer {
    struct State;
    std::unique_ptr<State> state_;
public:
    BridgeServer(const std::filesystem::path& endpointDirectory,BridgeHandler handler);
    ~BridgeServer();
    BridgeServer(const BridgeServer&)=delete;
    BridgeServer& operator=(const BridgeServer&)=delete;
    void stop();
    Json endpoint()const;
};
Json discoverDesktopSessions(const std::filesystem::path& directory);
Json callDesktopSession(const Json& endpoint,const Json& request,uint32_t timeoutMs=120000);
}
