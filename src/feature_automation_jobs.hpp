#pragma once
#include "feature_jobs.hpp"
#include <chrono>
#include <map>

namespace scratcher {

// The tracking service consumes worker completions immediately; UI delivery is
// independent, so querying a job never depends on a frame being rendered.
class AutomationJobs {
public:
 explicit AutomationJobs(JobQueue::Operation operation);
 ~AutomationJobs();
 AutomationJobs(const AutomationJobs&) = delete;
 AutomationJobs& operator=(const AutomationJobs&) = delete;
 uint64_t submit(std::string name, Json args = Json::object(), bool supersede = false);
 std::optional<JobCompletion> poll();
 bool busy() const;
 size_t pending() const;
 Json get(uint64_t id, bool includeResult = true);
 Json list(size_t offset = 0, size_t limit = 100) const;
 Json cancel(uint64_t id);
 Json await(uint64_t id, uint32_t timeoutMs = 0, bool includeResult = true);
 void cancel();
 void shutdown();

private:
 struct Record {
  uint64_t id = 0;
  std::string name, status = "queued", error;
  Json args, result;
  bool cancellationRequested = false, resultTruncated = false;
  int64_t created = 0, started = 0, completed = 0;
  double duration = 0;
  size_t retainedBytes = 0;
  std::chrono::steady_clock::time_point startClock;
 };
 mutable std::mutex mutex_;
 std::mutex joinMutex_;
 std::condition_variable changed_;
 std::map<uint64_t, std::shared_ptr<Record>> records_;
 std::deque<uint64_t> retained_;
 std::deque<JobCompletion> deliveries_;
 size_t retainedBytes_ = 0, deliveryBytes_ = 0;
 std::deque<size_t> deliverySizes_;
 bool stopping_ = false, monitorDone_ = false;
 std::thread::id workerId_;
 JobQueue queue_;
 std::thread monitor_;

 void started(uint64_t id);
 void monitor();
 static Json describe(const Record& record, bool includeResult);
 static bool terminal(const Record& record);
 std::shared_ptr<Record> find(uint64_t id) const;
};
}
