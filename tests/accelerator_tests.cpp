#include "accel/matcher.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace scratcher::accel;
namespace {
size_t checks=0;
void check(bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);}
template<class F>void rejects(F action,const char* text){bool threw=false;try{action();}catch(const std::exception&){threw=true;}check(threw,text);}
uint16_t scalarDistance(const Fingerprint& a,const Fingerprint& b){uint16_t count=0;for(unsigned word=0;word<4;++word)for(unsigned bit=0;bit<64;++bit)count+=((a[word]>>bit)&1)!=((b[word]>>bit)&1);return count;}
std::vector<std::vector<Neighbor>> reference(const std::vector<Fingerprint>& corpus,const std::vector<Fingerprint>& queries,uint32_t k){std::vector<std::vector<Neighbor>> result;for(const auto& query:queries){std::vector<Neighbor> row;for(size_t n=0;n<corpus.size();++n)row.push_back({static_cast<uint32_t>(n),scalarDistance(corpus[n],query)});std::sort(row.begin(),row.end(),[](const auto& a,const auto& b){return a.distance<b.distance||(a.distance==b.distance&&a.index<b.index);});row.resize(std::min<size_t>(k,row.size()));result.push_back(std::move(row));}return result;}
uint64_t randomWord(uint64_t& state){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
}
int main(){try{
 const Fingerprint zero{},ones{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX};
 std::vector<Fingerprint> known={zero,ones,{1,0,0,0},{2,0,0,0},zero,{3,0,0,0}};
 Matcher exact(known,1);auto result=exact.search({zero},6,Mode::Cpu);
 check(result.neighbors[0]==std::vector<Neighbor>({{0,0},{4,0},{2,1},{3,1},{5,2},{1,256}}),"known bit counts and ties order by lower corpus index");
 check(result.backend=="cpu"&&result.fallback_reason.empty()&&result.device_bytes==0,"CPU mode reports actual backend without device allocations");
 check(result.cpu_workers==1&&result.timings.cpu_ms>=0&&result.timings.end_to_end_ms>=result.timings.cpu_ms,"CPU timings include complete search work");
 check(exact.search({ones},32,Mode::Cpu).neighbors[0].size()==known.size(),"k larger than corpus returns only existing candidates");
 check(exact.search({},1,Mode::Cuda).neighbors.empty(),"empty query batch requires no accelerator");
 Matcher empty({},2);auto noCandidates=empty.search({zero,ones},1,Mode::Cuda);check(noCandidates.neighbors.size()==2&&noCandidates.neighbors[0].empty()&&noCandidates.backend=="cpu","empty corpus returns empty neighbor lists without GPU work");
 rejects([&]{exact.search({zero},0,Mode::Cpu);},"zero k is invalid");rejects([&]{exact.search({zero},33,Mode::Cpu);},"k above 32 is invalid");
 rejects([&]{exact.search(std::vector<Fingerprint>(1025),1,Mode::Cpu);},"query bound rejects before work");
 rejects([&]{Matcher bad(known,0);},"zero workers is invalid");rejects([&]{Matcher bad(known,33);},"worker ceiling is enforced");
 rejects([&]{Matcher bad(known,1,256ULL*1024*1024+1);},"GPU memory cap cannot exceed 256 MiB");
 rejects([&]{Matcher bad(std::vector<Fingerprint>(1000001),1);},"corpus bound rejects before worker or device allocation");
 Matcher pairBound(std::vector<Fingerprint>(131073),1);rejects([&]{pairBound.search(std::vector<Fingerprint>(1024),1,Mode::Cpu);},"comparison-pair ceiling applies equally to CPU and CUDA modes");
 rejects([&]{exact.search({zero},1,static_cast<Mode>(99));},"unknown mode is rejected");

 uint64_t state=0x628b1d765ac390efULL;std::vector<Fingerprint> corpus(8193);for(auto& value:corpus)for(auto& word:value)word=randomWord(state);corpus[0]=corpus[4096]=corpus[8192]=zero;
 std::vector<Fingerprint> queries(19);for(auto& value:queries)for(auto& word:value)word=randomWord(state);queries[0]=zero;queries[1]=ones;queries[2]=corpus[8191];
 Matcher serial(corpus,1),parallel(corpus,16);auto expected=reference(corpus,queries,32);auto serialResult=serial.search(queries,32,Mode::Cpu);auto parallelResult=parallel.search(queries,32,Mode::Cpu);
 check(serialResult.neighbors==expected,"optimized CPU top-k agrees with independent scalar all-candidate sort");
 check(parallelResult.neighbors==expected&&parallelResult.cpu_workers==16,"persistent parallel workers preserve exact results and ties");
 check(expected[0][0]==Neighbor{0,0}&&expected[0][1]==Neighbor{4096,0}&&expected[0][2]==Neighbor{8192,0},"equal best matches across tile boundaries keep lower indices");
 auto smallerQueries=std::vector<Fingerprint>{corpus[53]};check(parallel.search(smallerQueries,17,Mode::Cpu).neighbors==reference(corpus,smallerQueries,17),"persistent pool handles changed batch and internal exclusion top-17 depth");
 check(parallel.search(queries,32,Mode::Cpu).neighbors==expected,"persistent pool remains reusable after different batch shapes");
 Matcher moved(std::move(serial));check(moved.search({zero},1,Mode::Cpu).neighbors[0][0]==Neighbor{0,0},"moving matcher preserves corpus and pool ownership");rejects([&]{serial.search({zero},1,Mode::Cpu);},"moved-from matcher rejects search safely");

 Matcher lowMemory(corpus,4,1);auto fallback=lowMemory.search(queries,32,Mode::Cuda);
 check(fallback.backend=="cpu"&&!fallback.fallback_reason.empty()&&fallback.device_bytes==0,"insufficient device budget falls back honestly without allocation");
 check(fallback.neighbors==expected&&lowMemory.search(queries,32,Mode::Cpu).neighbors==expected,"failed CUDA allocation eligibility preserves sequential CPU usability");
 auto autoFallback=lowMemory.search(queries,32,Mode::Auto);check(autoFallback.backend=="cpu"&&autoFallback.neighbors==expected&&!autoFallback.calibration_equal&&autoFallback.auto_cuda_warm_baseline_ms==0,"Auto device-budget failure returns actual CPU output without inventing a warm measurement");
 auto gpuInfo=probeGpu();check(gpuInfo.available||!gpuInfo.reason.empty(),"GPU probe explains absence without throwing");
 Matcher accelerated(corpus,16);auto cuda=accelerated.search(queries,32,Mode::Cuda);
 check(cuda.neighbors==expected,"CUDA or explicit fallback matches scalar ground truth across multiple tiles and tail candidates");
 if(gpuInfo.available){
  check(cuda.backend=="cuda",("available GPU must execute real kernel: "+cuda.fallback_reason).c_str());
  check(cuda.device_bytes>0&&cuda.device_bytes<=256ULL*1024*1024&&cuda.timings.kernel_ms>0,"real kernel reports bounded live device buffers and GPU event timing");
  check(cuda.distance_kernel_registers>0&&cuda.merge_kernel_registers>0,"real compiled CUDA functions expose driver register-allocation diagnostics");
  std::cout<<"CUDA distance local bytes/thread="<<cuda.distance_kernel_local_bytes<<" registers="<<cuda.distance_kernel_registers<<"; merge local bytes/thread="<<cuda.merge_kernel_local_bytes<<" registers="<<cuda.merge_kernel_registers<<'\n';
  auto repeated=accelerated.search(smallerQueries,17,Mode::Cuda);check(repeated.backend=="cuda"&&repeated.cache_hit&&repeated.timings.corpus_upload_ms==0&&repeated.neighbors==reference(corpus,smallerQueries,17),"warm CUDA search reuses immutable uploaded corpus and handles changed shape");
  auto calibration=accelerated.search(queries,32,Mode::Auto);check(calibration.calibration_performed&&calibration.calibration_equal&&calibration.timings.calibration_ms>0,"Auto measures corresponding CPU and CUDA work and verifies equality");
  check(calibration.neighbors==expected&&(calibration.backend=="cuda"||!calibration.fallback_reason.empty()),"Auto reports measured backend choice and exact neighbors");
  check(calibration.selection_policy=="retained_corpus_warm_cuda"&&calibration.auto_cpu_baseline_ms>0&&calibration.auto_cuda_warm_baseline_ms>0,"Auto exposes both measured baselines and retained-corpus policy");
  check((calibration.backend=="cuda")== (calibration.auto_cuda_warm_baseline_ms<=calibration.auto_cpu_baseline_ms*0.90),"Auto chooses CUDA exactly when measured warm work meets its conservative gain margin");
  check(calibration.timings.calibration_ms>=calibration.auto_cpu_baseline_ms+calibration.auto_cuda_warm_baseline_ms&&calibration.timings.end_to_end_ms>=calibration.timings.calibration_ms,"calibration and request timing include all timed calibration computations");
  auto calibrated=accelerated.search(queries,32,Mode::Auto);check(!calibrated.calibration_performed&&calibrated.neighbors==expected,"Auto can reuse measured policy for same corpus and batch shape");
  check(calibrated.backend==calibration.backend&&calibrated.calibration_equal&&calibrated.timings.calibration_ms==0&&calibrated.auto_cpu_baseline_ms==calibration.auto_cpu_baseline_ms&&calibrated.auto_cuda_warm_baseline_ms==calibration.auto_cuda_warm_baseline_ms,"cached selection preserves measured policy and baselines without charging fresh calibration");
  // A fresh Auto request must separate its cold compiler/upload costs from its
  // selection baseline; never decide from the first cold GPU pass.
  Matcher coldAuto(corpus,16);auto cold= coldAuto.search(queries,8,Mode::Auto);auto expectedEight=expected;for(auto& row:expectedEight)row.resize(8);
  check(cold.neighbors==expectedEight&&cold.calibration_performed&&cold.calibration_equal&&!cold.cache_hit,"cold Auto calibrates and validates the same exact query/top-k workload");
  check(cold.timings.setup_ms>0&&cold.timings.corpus_upload_ms>0&&cold.auto_cuda_warm_baseline_ms>0,"cold setup and corpus upload remain visible while selection has a separate warm baseline");
  check((cold.backend=="cuda")== (cold.auto_cuda_warm_baseline_ms<=cold.auto_cpu_baseline_ms*0.90)&&cold.timings.calibration_ms>=cold.timings.setup_ms+cold.timings.corpus_upload_ms+cold.auto_cpu_baseline_ms+cold.auto_cuda_warm_baseline_ms,"cold Auto decision excludes initialization from warm baseline while total calibration includes it");
  auto coldCached=coldAuto.search(queries,8,Mode::Auto);check(coldCached.neighbors==expectedEight&&coldCached.backend==cold.backend&&!coldCached.calibration_performed&&coldCached.timings.setup_ms==0&&coldCached.timings.corpus_upload_ms==0,"following Auto request uses retained choice with no repeated cold setup");
  // Exact threshold ties on both sides of a 4096-candidate tile boundary,
  // including the single-entry final tile and extreme Hamming distances.
  std::vector<Fingerprint> boundaryCorpus(8193,ones);for(size_t n=0;n<40;++n)boundaryCorpus[n][0]^=1;boundaryCorpus[4095]=boundaryCorpus[4096]=boundaryCorpus[8192]=zero;
  std::vector<Fingerprint> boundaryQueries={zero,ones};auto boundaryExpected=reference(boundaryCorpus,boundaryQueries,32);Matcher boundaryMatcher(boundaryCorpus,16);
  check(boundaryExpected[0][0]==Neighbor{4095,0}&&boundaryExpected[0][1]==Neighbor{4096,0}&&boundaryExpected[0][2]==Neighbor{8192,0}&&boundaryExpected[0][3]==Neighbor{0,255},"boundary ground truth includes zero and 255-bit distances with stable tie order");
  for(uint32_t depth:{1u,8u,17u,32u}){auto expectedDepth=boundaryExpected;for(auto& row:expectedDepth)row.resize(depth);auto actual=boundaryMatcher.search(boundaryQueries,depth,Mode::Cuda);check(actual.backend=="cuda"&&actual.neighbors==expectedDepth,"real GPU top-k is exact at depths 1, 8, 17 and 32 across tile boundaries and sentinel tail");}
 }else{check(cuda.backend=="cpu"&&!cuda.fallback_reason.empty(),"missing CUDA driver produces explicit CPU fallback");auto absentAuto=accelerated.search(queries,8,Mode::Auto);auto absentExpected=expected;for(auto& row:absentExpected)row.resize(8);check(absentAuto.backend=="cpu"&&absentAuto.neighbors==absentExpected&&!absentAuto.calibration_equal&&absentAuto.auto_cuda_warm_baseline_ms==0&&!absentAuto.fallback_reason.empty(),"Auto without CUDA reports actual CPU computation and no fabricated GPU baseline");}
#ifdef _WIN32
 // A relative compiler path must never cause DLL lookup in the process CWD.
 wchar_t oldPath[32768];auto previous=GetEnvironmentVariableW(L"SCRATCHER_CUDA_PATH",oldPath,32768);check(previous<32768,"test can preserve configured compiler path");SetEnvironmentVariableW(L"SCRATCHER_CUDA_PATH",L"relative-untrusted-directory");
 Matcher invalidPath(known,1);auto safeFallback=invalidPath.search({zero},3,Mode::Cuda);if(previous)SetEnvironmentVariableW(L"SCRATCHER_CUDA_PATH",oldPath);else SetEnvironmentVariableW(L"SCRATCHER_CUDA_PATH",nullptr);
 check(safeFallback.backend=="cpu"&&safeFallback.neighbors==reference(known,{zero},3)&&!safeFallback.fallback_reason.empty(),"unsafe compiler path falls back to correct CPU search");
 check(invalidPath.search({zero},3,Mode::Cpu).neighbors==safeFallback.neighbors,"compiler load failure leaves CPU pool reusable");
#endif
 std::cout<<"PASS: "<<checks<<" accelerator checks; CUDA compiled="<<gpuInfo.compiled<<" available="<<gpuInfo.available<<" backend="<<cuda.backend<<"\n";return 0;
 }catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" accelerator checks: "<<error.what()<<'\n';return 1;}}
