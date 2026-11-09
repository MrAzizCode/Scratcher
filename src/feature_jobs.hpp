#pragma once
#include "core.hpp"
#include <condition_variable>
#include <deque>
#include <functional>
#include <optional>
#include <thread>

namespace scratcher {

struct JobCompletion {
 uint64_t id = 0;
 std::string name;
 Json args;
 Json result;
 std::string error;
 bool cancelled = false;
};

// A single worker owns all calls to the supplied operation. Construct this before
// submitting work, and destroy it before any objects captured by the operation.
// Cancellation is cooperative: the operation must check its token during long
// work. The token remains valid until that operation returns.
class JobQueue {
public:
 using Operation = std::function<Json(const std::string&, const Json&, std::atomic_bool&)>;
 using Started = std::function<void(uint64_t)>;
 explicit JobQueue(Operation operation, Started started = {});
 ~JobQueue();
 JobQueue(const JobQueue&) = delete;
 JobQueue& operator=(const JobQueue&) = delete;

 // Replaceable requests may supersede other replaceable requests. Normal jobs
 // retain their ordering and are never cancelled by superseding requests.
 uint64_t submit(std::string name, Json args = Json::object(), bool supersede = false);
 void cancel();
 bool cancel(uint64_t id);
 std::optional<JobCompletion> poll();
 // Blocks until a completion, timeout, or complete shutdown. Unlike poll this
 // lets a tracking service wait without repeatedly inspecting the queue.
 std::optional<JobCompletion> waitCompletion(uint32_t timeoutMs = UINT32_MAX);
 bool busy() const;
 size_t pending() const;
 // Stops accepting work, cancels queued/active work, and joins the worker.
 // Repeated calls are safe. Calling this from an operation requests shutdown;
 // destruction and final joining must take place outside the operation.
 void shutdown();

private:
 struct Job {
  uint64_t id;
  std::string name;
  Json args;
  bool replaceable;
  std::shared_ptr<std::atomic_bool> cancellation;
 };
 Operation operation_;
 Started started_;
 mutable std::mutex mutex_;
 std::mutex joinMutex_;
 std::condition_variable ready_;
 std::condition_variable completed_;
 std::deque<Job> jobs_;
 std::deque<JobCompletion> completions_;
 std::shared_ptr<std::atomic_bool> activeCancellation_;
 bool activeReplaceable_ = false;
 uint64_t activeId_ = 0;
 bool stopping_ = false;
 uint64_t nextId_ = 1;
 std::thread worker_;
 std::thread::id workerId_;

 void run();
 void discardPending(bool replaceableOnly);
};

}
