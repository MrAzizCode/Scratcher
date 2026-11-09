#include "feature_automation_jobs.hpp"
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace scratcher;
using namespace std::chrono_literals;
namespace {
std::atomic_uint checks{0};
void check(bool value, const char* label) {
 ++checks;
 if (!value) throw std::runtime_error(label);
}
template<class Fn> void rejected(Fn fn, const char* label) {
 bool threw = false;
 try { fn(); } catch (const std::exception&) { threw = true; }
 check(threw, label);
}

void trackingAndTargetedCancellation() {
 std::promise<void> entered, release;
 auto gate = release.get_future().share();
 std::atomic_bool cancellationObserved{false};
 AutomationJobs jobs([&](const std::string& name, const Json&, std::atomic_bool& token) -> Json {
  if (name == "active") {
   entered.set_value();
   gate.wait();
   cancellationObserved = token.load();
  }
  return {{"committed", name}};
 });
 auto active = jobs.submit("active");
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "active starts");
 auto queued = jobs.submit("queued");
 auto unaffected = jobs.submit("unaffected");
 check(jobs.get(active).at("status") == "running", "running status visible without poll");
 check(jobs.get(queued).at("status") == "queued", "queued status visible");
 const auto started = std::chrono::steady_clock::now();
 auto timeout = jobs.await(active, 20);
 check(timeout.at("timed_out") && timeout.at("status") == "running", "bounded await times out");
 check(std::chrono::steady_clock::now() - started < 1s, "await honors timeout");
 jobs.cancel(queued);
 check(jobs.await(queued, 5000).at("status") == "cancelled", "targeted pending cancellation completes");
 auto cancelling = jobs.cancel(active);
 check(cancelling.at("status") == "running" && cancelling.at("cancellation_requested"),
       "active cancellation remains running until operation exits");
 release.set_value();
 auto cancelled = jobs.await(active, 5000);
 check(cancelled.at("status") == "cancelled" && cancelled.at("result").at("committed") == "active",
       "cancelled active retains committed result");
 check(cancellationObserved, "operation token sees targeted cancellation");
 check(jobs.await(unaffected, 5000).at("status") == "completed", "unrelated task survives cancellation");
 check(jobs.get(active).at("job_id") == std::to_string(active), "JSON IDs are decimal strings");
 check(jobs.get(active).contains("started_at_ms") && jobs.get(active).contains("completed_at_ms"),
       "timestamps retained");
 check(!jobs.get(active, false).contains("result"), "result omission works");
 check(jobs.cancel(unaffected).at("status") == "completed", "cancel of completed job is truthful");
 jobs.shutdown();
 size_t delivered = 0;
 while (jobs.poll()) ++delivered;
 check(delivered == 3 && !jobs.poll(), "UI receives each retained completion once despite reads");
 rejected([&] { jobs.get(99999); }, "unknown IDs rejected");
 rejected([&] { jobs.submit("late"); }, "closed service rejects submissions");
}

void supersedeAndErrors() {
 std::promise<void> entered, release;
 auto gate = release.get_future().share();
 AutomationJobs jobs([&](const std::string& name, const Json&, std::atomic_bool&) -> Json {
  if (name == "first") { entered.set_value(); gate.wait(); }
  if (name == "fail") throw std::runtime_error("Expected failure");
  if (name == "unknown") throw 3;
  if (name == "encoding") throw std::runtime_error("Bad encoding \xff");
  return name;
 });
 auto first = jobs.submit("first", {}, true);
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "replaceable starts");
 auto mutation = jobs.submit("mutation");
 auto old = jobs.submit("old", {}, true);
 auto latest = jobs.submit("latest", {}, true);
 check(jobs.await(old, 5000).at("status") == "cancelled", "superseded queued task accounted for");
 release.set_value();
 check(jobs.await(first, 5000).at("status") == "cancelled", "superseded active accounted for");
 check(jobs.await(mutation, 5000).at("status") == "completed", "supersede preserves mutation");
 check(jobs.await(latest, 5000).at("status") == "completed", "latest replaceable completes");
 auto failure = jobs.submit("fail");
 auto unknown = jobs.submit("unknown");
 auto recovered = jobs.submit("recover");
 check(jobs.await(failure, 5000).at("error") == "Expected failure", "exception retained");
 check(jobs.get(failure).at("status") == "failed", "failure status");
 check(jobs.await(unknown, 5000).at("error") == "Task failed unexpectedly", "unknown exception retained");
 check(jobs.await(recovered, 5000).at("status") == "completed", "worker recovers");
 auto encoding = jobs.submit("encoding");
 check(!jobs.await(encoding, 5000).dump().empty(), "exception messages normalized to valid UTF-8");
 rejected([&] { jobs.submit(std::string("\xff")); }, "invalid UTF-8 task names rejected");
 rejected([&] { jobs.await(recovered, 30001); }, "oversized waits rejected");
 jobs.shutdown();
}

void retentionAndBounds() {
 AutomationJobs jobs([](const std::string&, const Json& args, std::atomic_bool&) -> Json { return args; });
 std::vector<uint64_t> ids;
 for (unsigned index = 0; index < 600; ++index) {
  auto id = jobs.submit("read", {{"value", index}});
  ids.push_back(id);
  check(jobs.await(id, 5000).at("status") == "completed", "retention task completes");
 }
 auto page = jobs.list(0, 500);
 check(page.at("total") == 512 && page.at("items").size() == 500 && page.at("has_more"), "retention bounded to 512");
 check(jobs.list(500, 100).at("items").size() == 12, "metadata list pagination");
 rejected([&] { jobs.get(ids.front()); }, "evicted task reports unavailable");
 rejected([&] { jobs.list(0, 0); }, "zero list limit rejected");
 rejected([&] { jobs.submit("big", std::string(1024 * 1024 + 1, 'a')); }, "oversized arguments rejected");
 jobs.shutdown();
 size_t delivered = 0;
 while (jobs.poll()) ++delivered;
 check(delivered == 512, "unconsumed UI completions bounded");

 AutomationJobs large([](const std::string&, const Json&, std::atomic_bool&) -> Json {
  return std::string(9 * 1024 * 1024, 'a');
 });
 auto big = large.submit("large");
 auto summary = large.await(big, 5000);
 check(summary.at("status") == "completed" && summary.at("result_truncated"), "oversized result summarized truthfully");
 check(summary.dump().size() < 8 * 1024 * 1024, "get output bounded");
 large.shutdown();

 std::promise<void> entered, release;
 auto gate = release.get_future().share();
 AutomationJobs protectedActive([&](const std::string&, const Json&, std::atomic_bool&) -> Json {
  entered.set_value(); gate.wait(); return "committed";
 });
 auto active = protectedActive.submit("active");
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "retention active starts");
 for (unsigned index = 0; index < 550; ++index) {
  auto queued = protectedActive.submit("pending");
  protectedActive.cancel(queued);
  if (protectedActive.await(queued, 5000).at("status") != "cancelled")
   throw std::runtime_error("retention cancellation incomplete");
 }
 check(protectedActive.get(active).at("status") == "running", "retention never evicts active job");
 check(protectedActive.list().at("total") == 513, "active jobs retained outside completed cap");
 protectedActive.cancel();
 release.set_value();
 check(protectedActive.await(active, 5000).at("status") == "cancelled", "cancel-all compatibility accounts for active job");
 protectedActive.shutdown();
}

void concurrentRetrievalAndShutdown() {
 AutomationJobs jobs([](const std::string&, const Json& args, std::atomic_bool& token) -> Json {
  if (token) return {{"cancelled", true}};
  return args;
 });
 std::vector<std::future<void>> clients;
 for (int client = 0; client < 4; ++client) {
  clients.push_back(std::async(std::launch::async, [&, client] {
   for (int index = 0; index < 60; ++index) {
    auto id = jobs.submit("read", {{"client", client}, {"index", index}});
    auto done = jobs.await(id, 5000);
    check(done.at("status") == "completed", "concurrent awaiting completes");
    jobs.get(id, false);
    jobs.list(0, 25);
   }
  }));
 }
 for (auto& client : clients) client.get();
 auto first = std::async(std::launch::async, [&] { jobs.shutdown(); });
 auto second = std::async(std::launch::async, [&] { jobs.shutdown(); });
 check(first.wait_for(5s) == std::future_status::ready && second.wait_for(5s) == std::future_status::ready,
       "concurrent shutdown completes");
 first.get(); second.get();
 check(!jobs.busy(), "shutdown idle");

 std::promise<void> entered, release;
 auto gate = release.get_future().share();
 AutomationJobs active([&](const std::string&, const Json&, std::atomic_bool& token) -> Json {
  entered.set_value(); gate.wait(); return {{"cancelled", token.load()}};
 });
 auto id = active.submit("blocked");
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "shutdown task starts");
 auto waiter = std::async(std::launch::async, [&] { return active.await(id, 5000); });
 auto stopper = std::async(std::launch::async, [&] { active.shutdown(); });
 const auto deadline = std::chrono::steady_clock::now() + 5s;
 while (!active.get(id).at("cancellation_requested").get<bool>()) {
  if (std::chrono::steady_clock::now() > deadline) throw std::runtime_error("shutdown cancellation timeout");
  std::this_thread::yield();
 }
 release.set_value();
 stopper.get();
 check(waiter.get().at("status") == "cancelled", "shutdown wakes concurrent awaiting");
}
}

int main() {
 try {
  trackingAndTargetedCancellation(); supersedeAndErrors(); retentionAndBounds(); concurrentRetrievalAndShutdown();
  std::cout << "PASS: " << checks.load() << " automation job checks\n";
  return 0;
 } catch (const std::exception& error) {
  std::cerr << "FAIL: " << error.what() << '\n';
  return 1;
 }
}
