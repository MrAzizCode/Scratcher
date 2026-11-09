#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace scratcher::accel {
using Fingerprint = std::array<uint64_t,4>;
struct Neighbor { uint32_t index=0; uint16_t distance=0; bool operator==(const Neighbor&) const = default; };
enum class Mode { Cpu, Cuda, Auto };
struct Timings {
 double setup_ms=0, corpus_upload_ms=0, query_upload_ms=0, kernel_ms=0, download_ms=0;
 double cpu_ms=0, calibration_ms=0, end_to_end_ms=0;
};
struct SearchResult {
 std::vector<std::vector<Neighbor>> neighbors;
 std::string backend="cpu", fallback_reason;
 Timings timings;
 uint32_t cpu_workers=1;
 uint64_t device_bytes=0;
 // Driver-reported per-thread local-memory allocation and register counts for
 // inspecting real compiled kernels; meaningful when backend is CUDA.
 uint32_t distance_kernel_local_bytes=0, merge_kernel_local_bytes=0;
 uint32_t distance_kernel_registers=0, merge_kernel_registers=0;
 bool cache_hit=false, calibration_performed=false, calibration_equal=false;
 // Auto selects for subsequent searches against this retained corpus. The
 // first batch shape pays cold setup plus one GPU warmup, then compares exact
 // CPU output with a second, warm CUDA search on the same queries/top-k.
 // CUDA must take <=90% of CPU elapsed time. Baselines persist with the cached
 // choice; calibration_ms is work incurred by this request only.
 std::string selection_policy;
 double auto_cpu_baseline_ms=0, auto_cuda_warm_baseline_ms=0;
 double auto_minimum_gain_percent=10;
};
struct GpuInfo {
 bool compiled=false, available=false;
 std::string name, reason;
 uint64_t total_bytes=0, free_bytes=0;
 uint32_t compute_major=0, compute_minor=0;
};
// Probe never requires a GPU and reports loader/driver failures as a reason.
GpuInfo probeGpu();
class Matcher {
public:
 // Top-k supports 1..32 (the product may expose a smaller public limit).
 // Corpus is immutable; validation precedes device allocation. The memory cap
 // includes corpus, query, partial top-k and result device buffers.
 explicit Matcher(std::vector<Fingerprint> corpus, uint32_t workers=4,
                  uint64_t gpu_memory_cap=256ULL*1024*1024);
 ~Matcher();
 Matcher(Matcher&&) noexcept;
 Matcher& operator=(Matcher&&) noexcept;
 Matcher(const Matcher&)=delete;
 Matcher& operator=(const Matcher&)=delete;
 SearchResult search(const std::vector<Fingerprint>& queries, uint32_t k=1, Mode mode=Mode::Auto);
 size_t size() const noexcept;
private:
 struct Impl;
 std::unique_ptr<Impl> impl_;
};
}
