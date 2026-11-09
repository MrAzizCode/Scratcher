#include "feature_jobs.hpp"
#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace scratcher;
using namespace std::chrono_literals;

static unsigned checks = 0;
static void check(bool value, const char* label) {
 ++checks;
 if (!value) throw std::runtime_error(label);
}
template<class Predicate> static void eventually(Predicate predicate, const char* label) {
 const auto deadline = std::chrono::steady_clock::now() + 5s;
 while (!predicate()) {
  if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error(label);
  std::this_thread::sleep_for(1ms);
 }
}
static std::vector<JobCompletion> collect(JobQueue& queue, size_t count) {
 std::vector<JobCompletion> results;
 eventually([&] {
  while (auto completion = queue.poll()) results.push_back(std::move(*completion));
  return results.size() == count;
 }, "completion timeout");
 return results;
}
static const JobCompletion& find(const std::vector<JobCompletion>& results, uint64_t id) {
 const auto it = std::find_if(results.begin(), results.end(),
                            [id](const auto& result) { return result.id == id; });
 if (it == results.end()) throw std::runtime_error("missing completion");
 return *it;
}

static void serialAndFailures() {
 std::atomic_int active{0}, maximum{0};
 std::vector<int> order;
 JobQueue queue([&](const std::string& name, const Json& args, std::atomic_bool&) -> Json {
  const auto concurrent = ++active;
  maximum.store(std::max(maximum.load(), concurrent));
  order.push_back(args.at("value").get<int>());
  --active;
  if (name == "fail") throw std::runtime_error("Requested failure");
  if (name == "unknown") throw 42;
  return {{"value", args.at("value")}};
 });
 std::vector<uint64_t> ids;
 for (int index = 0; index < 250; ++index)
  ids.push_back(queue.submit("read", {{"value", index}}));
 const auto failure = queue.submit("fail", {{"value", 250}});
 const auto unknown = queue.submit("unknown", {{"value", 251}});
 const auto recovery = queue.submit("read", {{"value", 252}});
 auto results = collect(queue, 253);
 queue.shutdown();
 check(maximum == 1, "operations overlap");
 check(order.size() == 253, "operation count");
 for (size_t index = 0; index < order.size(); ++index)
  check(order[index] == static_cast<int>(index), "serial ordering");
 for (size_t index = 0; index < ids.size(); ++index) {
  const auto& result = find(results, ids[index]);
  check(result.args.at("value") == index && result.result.at("value") == index,
        "arguments and result retained");
 }
 check(find(results, failure).error == "Requested failure", "exception completion");
 check(find(results, unknown).error == "Task failed unexpectedly", "unknown exception completion");
 check(find(results, recovery).error.empty(), "worker recovers after failure");
 check(!queue.busy() && queue.pending() == 0, "idle after completion");
 check(!queue.poll(), "completion consumed once");
 queue.shutdown();
 bool rejected = false;
 try { queue.submit("late"); } catch (const std::runtime_error&) { rejected = true; }
 check(rejected, "submission after shutdown rejected");
}

static void supersedeAndMutations() {
 std::promise<void> entered, release;
 auto releaseFuture = release.get_future().share();
 std::atomic_bool observedCancellation{false};
 std::vector<std::string> executed;
 JobQueue queue([&](const std::string& name, const Json&, std::atomic_bool& token) -> Json {
  executed.push_back(name);
  if (name == "first") {
   entered.set_value();
   releaseFuture.wait();
   observedCancellation = token.load();
  }
  return name;
 });
 const auto first = queue.submit("first", {}, true);
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "first request starts");
 const auto mutation = queue.submit("rename");
 const auto older = queue.submit("older", {}, true);
 const auto latest = queue.submit("latest", {}, true);
 check(queue.pending() == 2, "only replaceable pending work removed");
 release.set_value();
 const auto results = collect(queue, 4);
 queue.shutdown();
 check(observedCancellation, "active navigation cancellation signalled");
 check(find(results, first).cancelled, "active navigation result marked cancelled");
 check(find(results, older).cancelled && find(results, older).result.is_null(),
       "superseded pending result marked cancelled");
 check(!find(results, mutation).cancelled && !find(results, latest).cancelled,
       "mutation and latest request preserved");
 check(executed == std::vector<std::string>({"first", "rename", "latest"}),
       "mutation ordering preserved");

 std::promise<void> mutationEntered, mutationRelease;
 auto mutationReleaseFuture = mutationRelease.get_future().share();
 std::atomic_bool mutationCancelled{true};
 JobQueue mutations([&](const std::string& name, const Json&, std::atomic_bool& token) -> Json {
  if (name == "write") {
   mutationEntered.set_value();
   mutationReleaseFuture.wait();
   mutationCancelled = token.load();
  }
  return {};
 });
 const auto writing = mutations.submit("write");
 check(mutationEntered.get_future().wait_for(5s) == std::future_status::ready, "mutation starts");
 mutations.submit("navigation", {}, true);
 mutationRelease.set_value();
 const auto mutationResults = collect(mutations, 2);
 mutations.shutdown();
 check(!mutationCancelled && !find(mutationResults, writing).cancelled,
       "superseding does not cancel active mutation");
}

static void concurrentSubmitters() {
 std::atomic_int active{0};
 std::atomic_bool overlap{false};
 JobQueue queue([&](const std::string&, const Json& args, std::atomic_bool&) -> Json {
  if (++active != 1) overlap = true;
  std::this_thread::yield();
  --active;
  return args;
 });
 std::vector<std::future<std::vector<uint64_t>>> producers;
 for (int producer = 0; producer < 4; ++producer) {
  producers.push_back(std::async(std::launch::async, [&, producer] {
   std::vector<uint64_t> ids;
   for (int item = 0; item < 100; ++item)
    ids.push_back(queue.submit("read", {{"producer", producer}, {"item", item}}));
   return ids;
  }));
 }
 std::vector<uint64_t> ids;
 for (auto& producer : producers) {
  auto submitted = producer.get();
  ids.insert(ids.end(), submitted.begin(), submitted.end());
 }
 const auto results = collect(queue, ids.size());
 queue.shutdown();
 std::sort(ids.begin(), ids.end());
 check(std::adjacent_find(ids.begin(), ids.end()) == ids.end(), "concurrent ids are unique");
 check(!overlap, "concurrent submissions use a single worker");
 for (size_t index = 0; index < results.size(); ++index) {
  check(results[index].id == ids[index], "concurrent submission ordering retained");
  check(results[index].args == results[index].result, "concurrent result retains request");
 }
}

static void cancelAndLifetime() {
 std::promise<void> entered;
 std::atomic_bool stopped{false};
 JobQueue queue([&](const std::string&, const Json&, std::atomic_bool& token) -> Json {
  entered.set_value();
  while (!token.load()) std::this_thread::sleep_for(1ms);
  stopped = true;
  return "finished";
 });
 const auto active = queue.submit("long");
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "cancellable request starts");
 const auto pending = queue.submit("pending");
 queue.cancel();
 const auto results = collect(queue, 2);
 queue.shutdown();
 check(stopped && find(results, active).cancelled && find(results, pending).cancelled,
       "explicit cancellation marks all work");

 std::promise<void> destructorEntered;
 std::atomic_bool destructorExited{false};
 {
  JobQueue lifetime([&](const std::string&, const Json&, std::atomic_bool& token) -> Json {
   destructorEntered.set_value();
   while (!token.load()) std::this_thread::sleep_for(1ms);
   destructorExited = true;
   return {};
  });
  lifetime.submit("long");
  check(destructorEntered.get_future().wait_for(5s) == std::future_status::ready,
        "destructor request starts");
  lifetime.submit("queued");
 }
 check(destructorExited, "destructor joins active work before captured state expires");

 bool rejected = false;
 try { JobQueue empty(JobQueue::Operation{}); }
 catch (const std::invalid_argument&) { rejected = true; }
 check(rejected, "missing handler rejected");

 std::promise<void> shutdownEntered;
 std::atomic_bool shutdownExited{false};
 JobQueue sharedShutdown([&](const std::string&, const Json&, std::atomic_bool& token) -> Json {
  shutdownEntered.set_value();
  while (!token.load()) std::this_thread::sleep_for(1ms);
  shutdownExited = true;
  return {};
 });
 sharedShutdown.submit("long");
 check(shutdownEntered.get_future().wait_for(5s) == std::future_status::ready,
       "concurrent shutdown request starts");
 auto firstShutdown = std::async(std::launch::async, [&] { sharedShutdown.shutdown(); });
 auto secondShutdown = std::async(std::launch::async, [&] { sharedShutdown.shutdown(); });
 check(firstShutdown.wait_for(5s) == std::future_status::ready &&
       secondShutdown.wait_for(5s) == std::future_status::ready,
       "concurrent shutdown joins safely");
 firstShutdown.get();
 secondShutdown.get();
 check(shutdownExited && !sharedShutdown.busy(), "concurrent shutdown completes work");
}

static void targetedCancelAndCompletionWait() {
 std::promise<void> entered, release;
 auto gate = release.get_future().share();
 JobQueue queue([&](const std::string& name, const Json&, std::atomic_bool&) -> Json {
  if (name == "active") { entered.set_value(); gate.wait(); }
  return name;
 });
 const auto active = queue.submit("active");
 check(entered.get_future().wait_for(5s) == std::future_status::ready, "wait test starts");
 const auto cancelled = queue.submit("cancelled");
 const auto retained = queue.submit("retained");
 check(!queue.waitCompletion(5), "completion wait timeout");
 check(queue.cancel(cancelled) && !queue.cancel(99999), "targeted cancellation identifies pending ID");
 auto result = queue.waitCompletion(5000);
 check(result && result->id == cancelled && result->cancelled, "completion wait receives pending cancellation");
 check(queue.pending() == 1, "targeted cancellation leaves unrelated pending work");
 release.set_value();
 result = queue.waitCompletion(5000);
 check(result && result->id == active && !result->cancelled, "targeted pending cancellation leaves active work");
 result = queue.waitCompletion(5000);
 check(result && result->id == retained && !result->cancelled, "completion wait receives retained task");
 queue.shutdown();
 check(!queue.waitCompletion(), "completion wait wakes at shutdown");
}

int main() {
 try {
  serialAndFailures();
  supersedeAndMutations();
  concurrentSubmitters();
  cancelAndLifetime();
  targetedCancelAndCompletionWait();
  std::cout << "PASS: " << checks << " background queue checks\n";
  return 0;
 } catch (const std::exception& error) {
  std::cerr << "FAIL: " << error.what() << '\n';
  return 1;
 }
}
