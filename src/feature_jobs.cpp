#include "feature_jobs.hpp"
#include <stdexcept>
#include <chrono>

namespace scratcher {

JobQueue::JobQueue(Operation operation, Started started)
 : operation_(std::move(operation)), started_(std::move(started)) {
 if (!operation_) throw std::invalid_argument("A task handler is required");
 worker_ = std::thread([this] { run(); });
 workerId_ = worker_.get_id();
}

JobQueue::~JobQueue() { shutdown(); }

uint64_t JobQueue::submit(std::string name, Json args, bool supersede) {
 std::lock_guard lock(mutex_);
 if (stopping_) throw std::runtime_error("Task queue is closed");
 if (nextId_ == 0) throw std::runtime_error("Task identifier limit reached");
 if (supersede) {
  discardPending(true);
  if (activeCancellation_ && activeReplaceable_)
   activeCancellation_->store(true, std::memory_order_relaxed);
 }
 const auto id = nextId_++;
 jobs_.push_back({id, std::move(name), std::move(args), supersede,
                  std::make_shared<std::atomic_bool>(false)});
 ready_.notify_one();
 return id;
}

// Requires mutex_. Discarded requests also get a completion, so clients can
// account for every submitted id without waiting for work that will never run.
void JobQueue::discardPending(bool replaceableOnly) {
 for (auto it = jobs_.begin(); it != jobs_.end();) {
  if (replaceableOnly && !it->replaceable) { ++it; continue; }
  it->cancellation->store(true, std::memory_order_relaxed);
  completions_.push_back({it->id, std::move(it->name), std::move(it->args),
                          nullptr, {}, true});
  it = jobs_.erase(it);
 }
 completed_.notify_all();
}

void JobQueue::cancel() {
 std::lock_guard lock(mutex_);
 discardPending(false);
 if (activeCancellation_) activeCancellation_->store(true, std::memory_order_relaxed);
}

bool JobQueue::cancel(uint64_t id) {
 std::lock_guard lock(mutex_);
 if (activeId_ == id && activeCancellation_) {
  activeCancellation_->store(true, std::memory_order_relaxed);
  return true;
 }
 for (auto it = jobs_.begin(); it != jobs_.end(); ++it) {
  if (it->id != id) continue;
  it->cancellation->store(true, std::memory_order_relaxed);
  completions_.push_back({it->id, std::move(it->name), std::move(it->args), nullptr, {}, true});
  jobs_.erase(it);
  completed_.notify_all();
  return true;
 }
 return false;
}

std::optional<JobCompletion> JobQueue::poll() {
 std::lock_guard lock(mutex_);
 if (completions_.empty()) return std::nullopt;
 auto completion = std::move(completions_.front());
 completions_.pop_front();
 return completion;
}

std::optional<JobCompletion> JobQueue::waitCompletion(uint32_t timeoutMs) {
 std::unique_lock lock(mutex_);
 const auto available = [this] {
  return !completions_.empty() || (stopping_ && !activeCancellation_ && jobs_.empty());
 };
 if (timeoutMs == UINT32_MAX) completed_.wait(lock, available);
 else if (!completed_.wait_for(lock, std::chrono::milliseconds(timeoutMs), available)) return std::nullopt;
 if (completions_.empty()) return std::nullopt;
 auto result = std::move(completions_.front());
 completions_.pop_front();
 return result;
}

bool JobQueue::busy() const {
 std::lock_guard lock(mutex_);
 return activeCancellation_ || !jobs_.empty();
}

size_t JobQueue::pending() const {
 std::lock_guard lock(mutex_);
 return jobs_.size();
}

void JobQueue::shutdown() {
 {
  std::lock_guard lock(mutex_);
  stopping_ = true;
  discardPending(false);
  if (activeCancellation_) activeCancellation_->store(true, std::memory_order_relaxed);
 }
 ready_.notify_all();
 completed_.notify_all();
 if (std::this_thread::get_id() == workerId_) return;
 std::lock_guard joinLock(joinMutex_);
 if (worker_.joinable()) worker_.join();
}

void JobQueue::run() {
 for (;;) {
  std::optional<Job> current;
  {
   std::unique_lock lock(mutex_);
   ready_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
   if (stopping_) return;
   current.emplace(std::move(jobs_.front()));
   jobs_.pop_front();
   activeCancellation_ = current->cancellation;
   activeReplaceable_ = current->replaceable;
   activeId_ = current->id;
  }
  JobCompletion completion{current->id, current->name, current->args, nullptr, {}, false};
  try {
   if (started_) started_(current->id);
   completion.result = operation_(current->name, current->args, *current->cancellation);
  } catch (const std::exception& error) {
   completion.error = error.what();
  } catch (...) {
   completion.error = "Task failed unexpectedly";
  }
  {
   std::lock_guard lock(mutex_);
   completion.cancelled = current->cancellation->load(std::memory_order_relaxed);
   completions_.push_back(std::move(completion));
   activeCancellation_.reset();
   activeReplaceable_ = false;
   activeId_ = 0;
   completed_.notify_all();
  }
 }
}

}
