#include "feature_automation_jobs.hpp"
#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace scratcher {
namespace {
constexpr size_t maximumOutput = 8 * 1024 * 1024;
constexpr size_t maximumArguments = 1024 * 1024;
constexpr size_t retention = 512;
constexpr size_t retainedByteLimit = 32 * 1024 * 1024;
constexpr size_t deliveryByteLimit = 32 * 1024 * 1024;
int64_t timestamp() {
 return std::chrono::duration_cast<std::chrono::milliseconds>(
  std::chrono::system_clock::now().time_since_epoch()).count();
}
}

AutomationJobs::AutomationJobs(JobQueue::Operation operation)
 : queue_(std::move(operation), [this](uint64_t id) { started(id); }) {
 monitor_ = std::thread([this] { monitor(); });
}
AutomationJobs::~AutomationJobs() { shutdown(); }

uint64_t AutomationJobs::submit(std::string name, Json args, bool supersede) {
 if (name.empty() || name.size() > 1024) throw std::invalid_argument("Invalid task name");
 (void)Json(name).dump(); // Reject invalid UTF-8 before entering the queue.
 if (args.dump().size() > maximumArguments) throw std::invalid_argument("Task arguments exceed 1 MiB");
 std::lock_guard lock(mutex_);
 if (stopping_) throw std::runtime_error("Task queue is closed");
 if (queue_.pending() >= 512) throw std::runtime_error("Task queue has reached its 512 pending task limit");
 auto record = std::make_shared<Record>();
 record->name = name;
 record->args = args;
 record->created = timestamp();
 record->id = queue_.submit(std::move(name), std::move(args), supersede);
 records_.emplace(record->id, record);
 return record->id;
}

void AutomationJobs::started(uint64_t id) {
 std::lock_guard lock(mutex_);
 workerId_ = std::this_thread::get_id();
 auto record = find(id);
 record->status = "running";
 record->started = timestamp();
 record->startClock = std::chrono::steady_clock::now();
 changed_.notify_all();
}

bool AutomationJobs::terminal(const Record& record) {
 return record.status == "completed" || record.status == "failed" || record.status == "cancelled";
}
std::shared_ptr<AutomationJobs::Record> AutomationJobs::find(uint64_t id) const {
 auto it = records_.find(id);
 if (it == records_.end()) throw std::out_of_range("Task not found or no longer retained");
 return it->second;
}

Json AutomationJobs::describe(const Record& record, bool includeResult) {
 Json out = {{"job_id", std::to_string(record.id)}, {"tool", record.name},
  {"arguments", record.args}, {"status", record.status},
  {"cancellation_requested", record.cancellationRequested}, {"created_at_ms", record.created}};
 if (record.started) out["started_at_ms"] = record.started;
 if (terminal(record)) {
  out["completed_at_ms"] = record.completed;
  out["duration_ms"] = record.duration;
  if (!record.error.empty()) out["error"] = record.error;
  if (includeResult) out["result"] = record.result;
  if (record.resultTruncated) out["result_truncated"] = true;
 } else if (record.started) {
  out["duration_ms"] = std::chrono::duration<double, std::milli>(
   std::chrono::steady_clock::now() - record.startClock).count();
 }
 return out;
}

void AutomationJobs::monitor() {
 while (auto completion = queue_.waitCompletion()) {
  // Restrict retained payloads before acquiring the tracking lock.
  Json retainedResult = completion->result;
  bool truncated = false;
  try {
   if (retainedResult.dump().size() > maximumOutput - maximumArguments - 65536) {
    retainedResult = {{"truncated", true}, {"reason", "Result exceeds the retained output limit"}};
    truncated = true;
   }
  } catch (const std::exception&) {
   retainedResult = {{"truncated", true}, {"reason", "Result cannot be serialized"}};
   truncated = true;
  }
  std::lock_guard lock(mutex_);
  auto record = find(completion->id);
  record->completed = timestamp();
  if (record->started) record->duration = std::chrono::duration<double, std::milli>(
   std::chrono::steady_clock::now() - record->startClock).count();
  record->status = completion->cancelled ? "cancelled" : completion->error.empty() ? "completed" : "failed";
  record->cancellationRequested = record->cancellationRequested || completion->cancelled;
  record->error = Json::parse(Json(completion->error.substr(0, 32768)).dump(
   -1, ' ', false, Json::error_handler_t::replace)).get<std::string>();
  completion->error = record->error;
  record->result = std::move(retainedResult);
  record->resultTruncated = truncated;
  record->retainedBytes = record->args.dump().size() + record->result.dump().size() + record->error.size() + record->name.size() + 1024;
  retainedBytes_ += record->retainedBytes;
  retained_.push_back(record->id);
  while (retained_.size() > retention || retainedBytes_ > retainedByteLimit) {
   retainedBytes_ -= records_.at(retained_.front())->retainedBytes;
   records_.erase(retained_.front());
   retained_.pop_front();
  }
  // poll is a bounded delivery history. Long-disconnected UIs retrieve current
  // state independently, while MCP-only consumers need not drain UI payloads.
  if (truncated) completion->result = record->result;
  const auto deliverySize = record->retainedBytes;
  deliveryBytes_ += deliverySize;
  deliverySizes_.push_back(deliverySize);
  deliveries_.push_back(std::move(*completion));
  while (deliveries_.size() > retention || deliveryBytes_ > deliveryByteLimit) {
   deliveryBytes_ -= deliverySizes_.front();
   deliverySizes_.pop_front();
   deliveries_.pop_front();
  }
  changed_.notify_all();
 }
 std::lock_guard lock(mutex_);
 monitorDone_ = true;
 changed_.notify_all();
}

std::optional<JobCompletion> AutomationJobs::poll() {
 std::lock_guard lock(mutex_);
 if (deliveries_.empty()) return std::nullopt;
 auto completion = std::move(deliveries_.front());
 deliveries_.pop_front();
 deliveryBytes_ -= deliverySizes_.front();
 deliverySizes_.pop_front();
 return completion;
}
bool AutomationJobs::busy() const { return queue_.busy(); }
size_t AutomationJobs::pending() const { return queue_.pending(); }

Json AutomationJobs::get(uint64_t id, bool includeResult) {
 std::lock_guard lock(mutex_);
 return describe(*find(id), includeResult);
}

Json AutomationJobs::list(size_t offset, size_t limit) const {
 if (!limit || limit > 512) throw std::invalid_argument("Task list limit must be between 1 and 512");
 std::lock_guard lock(mutex_);
 Json items = Json::array();
 size_t index = 0, encodedBytes = 1024;
 for (const auto& pair : records_) {
  if (index++ < offset) continue;
  auto item = describe(*pair.second, false);
  auto bytes = item.dump().size();
  if (items.size() == limit || encodedBytes + bytes > maximumOutput - 1024) break;
  encodedBytes += bytes;
  items.push_back(std::move(item));
 }
 const auto next = offset + items.size();
 return {{"items", std::move(items)}, {"offset", offset}, {"limit", limit},
  {"total", records_.size()}, {"has_more", next < records_.size()},
  {"next_offset", next < records_.size() ? Json(next) : Json(nullptr)}};
}

Json AutomationJobs::cancel(uint64_t id) {
 std::shared_ptr<Record> record;
 {
  std::lock_guard lock(mutex_);
  record = find(id);
  if (terminal(*record)) {
   auto response = describe(*record, true);
   response["cancellation_accepted"] = false;
   return response;
  }
  record->cancellationRequested = true;
 }
 const bool accepted = queue_.cancel(id);
 std::lock_guard lock(mutex_);
 auto response = describe(*record, true);
 response["cancellation_accepted"] = accepted;
 return response;
}

Json AutomationJobs::await(uint64_t id, uint32_t timeoutMs, bool includeResult) {
 if (timeoutMs > 30000) throw std::invalid_argument("Task wait timeout exceeds 30000 ms");
 std::unique_lock lock(mutex_);
 auto record = find(id);
 changed_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] {
  return terminal(*record) || monitorDone_;
 });
 auto result = describe(*record, includeResult);
 result["timed_out"] = !terminal(*record);
 return result;
}

void AutomationJobs::cancel() {
 {
  std::lock_guard lock(mutex_);
  for (auto& pair : records_)
   if (!terminal(*pair.second)) pair.second->cancellationRequested = true;
 }
 queue_.cancel();
}

void AutomationJobs::shutdown() {
 bool fromWorker;
 {
  std::lock_guard lock(mutex_);
  stopping_ = true;
  fromWorker = workerId_ == std::this_thread::get_id();
  for (auto& pair : records_)
   if (!terminal(*pair.second)) pair.second->cancellationRequested = true;
 }
 queue_.shutdown();
 if (fromWorker) return;
 std::lock_guard joinLock(joinMutex_);
 if (monitor_.joinable()) monitor_.join();
}
}
