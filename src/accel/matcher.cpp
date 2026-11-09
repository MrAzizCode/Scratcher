#include "matcher.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <cstring>
#include <condition_variable>
#include <functional>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#ifdef _MSC_VER
#include <intrin.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <filesystem>
#endif
#if defined(SCRATCHER_ENABLE_CUDA) && SCRATCHER_ENABLE_CUDA
#include <cuda.h>
#include <nvrtc.h>
#endif

namespace scratcher::accel {
namespace {
using Clock=std::chrono::steady_clock;
double elapsed(Clock::time_point start){return std::chrono::duration<double,std::milli>(Clock::now()-start).count();}
constexpr uint64_t maxPairs=128ULL*1024*1024, maxDeviceBytes=256ULL*1024*1024;
constexpr uint32_t maxCorpus=1000000,maxQueries=1024,maxK=32,tileSize=4096;
uint32_t distance(const Fingerprint& a,const Fingerprint& b){
 uint32_t result=0;
 for(unsigned n=0;n<4;++n){
#if defined(_MSC_VER) && defined(_M_X64)
  result+=static_cast<uint32_t>(__popcnt64(a[n]^b[n]));
#else
  result+=static_cast<uint32_t>(std::popcount(a[n]^b[n]));
#endif
 }return result;
}
uint64_t packed(uint32_t index,uint32_t distance){return (uint64_t(distance)<<32)|index;}
void insert(uint64_t* top,uint32_t k,uint64_t value){if(value>=top[k-1])return;uint32_t position=k-1;while(position&&value<top[position-1]){top[position]=top[position-1];--position;}top[position]=value;}
std::vector<std::vector<Neighbor>> unpack(const std::vector<uint64_t>& values,size_t queries,uint32_t k){std::vector<std::vector<Neighbor>> result(queries);for(size_t q=0;q<queries;++q){result[q].reserve(k);for(uint32_t n=0;n<k;++n){auto value=values[q*k+n];result[q].push_back({static_cast<uint32_t>(value),static_cast<uint16_t>(value>>32)});}}return result;}
class WorkerPool {
 std::mutex mutex;std::condition_variable ready,finished;std::vector<std::thread> threads;
 std::function<void(uint32_t)> job;uint64_t generation=0;uint32_t remaining=0;bool stopping=false;std::exception_ptr error;
 void worker(uint32_t index){uint64_t seen=0;for(;;){std::unique_lock lock(mutex);ready.wait(lock,[&]{return stopping||generation!=seen;});if(stopping)return;seen=generation;auto current=job;lock.unlock();try{current(index);}catch(...){std::lock_guard failure(mutex);if(!error)error=std::current_exception();}lock.lock();if(!--remaining)finished.notify_one();}}
 void stop()noexcept{{std::lock_guard lock(mutex);stopping=true;}ready.notify_all();for(auto& thread:threads)if(thread.joinable())thread.join();}
public:
 explicit WorkerPool(uint32_t count){try{for(uint32_t n=1;n<count;++n)threads.emplace_back([this,n]{worker(n);});}catch(...){stop();throw;}}
 ~WorkerPool(){stop();}
 void run(std::function<void(uint32_t)> work){{std::lock_guard lock(mutex);job=std::move(work);remaining=static_cast<uint32_t>(threads.size());error=nullptr;++generation;}ready.notify_all();try{job(0);}catch(...){std::lock_guard lock(mutex);if(!error)error=std::current_exception();}std::unique_lock lock(mutex);finished.wait(lock,[&]{return remaining==0;});job={};if(error)std::rethrow_exception(error);}
};
std::vector<std::vector<Neighbor>> cpuSearch(const std::vector<Fingerprint>& corpus,const std::vector<Fingerprint>& queries,uint32_t k,uint32_t workers,WorkerPool& pool){
 if(corpus.empty()||queries.empty())return std::vector<std::vector<Neighbor>>(queries.size());
 // Partition candidate ranges, keeping contiguous cache-friendly scans. A small
 // query batch still uses the requested worker pool; no per-comparison threads.
 workers=std::min<uint32_t>(workers,static_cast<uint32_t>(corpus.size()));
 std::vector<std::vector<uint64_t>> partial(workers,std::vector<uint64_t>(queries.size()*k,UINT64_MAX));
 auto work=[&](uint32_t worker){if(worker>=workers)return;size_t begin=corpus.size()*worker/workers,end=corpus.size()*(worker+1)/workers;for(size_t q=0;q<queries.size();++q){auto* top=partial[worker].data()+q*k;for(size_t c=begin;c<end;++c)insert(top,k,packed(static_cast<uint32_t>(c),distance(queries[q],corpus[c])));}};
 pool.run(work);
 std::vector<uint64_t> result(queries.size()*k,UINT64_MAX);for(size_t q=0;q<queries.size();++q)for(uint32_t w=0;w<workers;++w)for(uint32_t n=0;n<k;++n)insert(result.data()+q*k,k,partial[w][q*k+n]);return unpack(result,queries.size(),k);
}

#if defined(SCRATCHER_ENABLE_CUDA) && SCRATCHER_ENABLE_CUDA && defined(_WIN32)
struct Library {HMODULE value=nullptr;~Library(){if(value)FreeLibrary(value);}Library()=default;Library(const Library&)=delete;};
template<class T>T symbol(HMODULE library,const char* name){auto address=GetProcAddress(library,name);if(!address)throw std::runtime_error(std::string("CUDA runtime missing symbol ")+name);return reinterpret_cast<T>(address);}
struct Api {
 // Members are destroyed in reverse order: NVRTC may retain references to its
 // dynamically loaded builtins until its own library is unloaded.
 Library driver,builtins,nvrtc;
#define DRIVER_MEMBER(name) decltype(&name) name##_=nullptr
 DRIVER_MEMBER(cuInit);DRIVER_MEMBER(cuDeviceGet);DRIVER_MEMBER(cuDeviceGetName);DRIVER_MEMBER(cuDeviceGetAttribute);DRIVER_MEMBER(cuDeviceTotalMem);DRIVER_MEMBER(cuCtxCreate);DRIVER_MEMBER(cuCtxDestroy);DRIVER_MEMBER(cuCtxPushCurrent);DRIVER_MEMBER(cuCtxPopCurrent);DRIVER_MEMBER(cuMemGetInfo);DRIVER_MEMBER(cuMemAlloc);DRIVER_MEMBER(cuMemFree);DRIVER_MEMBER(cuMemAllocHost);DRIVER_MEMBER(cuMemFreeHost);DRIVER_MEMBER(cuMemcpyHtoD);DRIVER_MEMBER(cuMemcpyHtoDAsync);DRIVER_MEMBER(cuMemcpyDtoHAsync);DRIVER_MEMBER(cuModuleLoadDataEx);DRIVER_MEMBER(cuModuleUnload);DRIVER_MEMBER(cuModuleGetFunction);DRIVER_MEMBER(cuFuncGetAttribute);DRIVER_MEMBER(cuLaunchKernel);DRIVER_MEMBER(cuStreamCreate);DRIVER_MEMBER(cuStreamDestroy);DRIVER_MEMBER(cuStreamSynchronize);DRIVER_MEMBER(cuEventCreate);DRIVER_MEMBER(cuEventDestroy);DRIVER_MEMBER(cuEventRecord);DRIVER_MEMBER(cuEventElapsedTime);
#undef DRIVER_MEMBER
#define NVRTC_MEMBER(name) decltype(&name) name##_=nullptr
 NVRTC_MEMBER(nvrtcCreateProgram);NVRTC_MEMBER(nvrtcCompileProgram);NVRTC_MEMBER(nvrtcGetPTXSize);NVRTC_MEMBER(nvrtcGetPTX);NVRTC_MEMBER(nvrtcGetProgramLogSize);NVRTC_MEMBER(nvrtcGetProgramLog);NVRTC_MEMBER(nvrtcDestroyProgram);
#undef NVRTC_MEMBER
 Api(){
  driver.value=LoadLibraryExW(L"nvcuda.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!driver.value)throw std::runtime_error("NVIDIA CUDA driver is unavailable");
#define LOAD_DRIVER(name,exportName) name##_=symbol<decltype(name##_)>(driver.value,exportName)
  LOAD_DRIVER(cuInit,"cuInit");LOAD_DRIVER(cuDeviceGet,"cuDeviceGet");LOAD_DRIVER(cuDeviceGetName,"cuDeviceGetName");LOAD_DRIVER(cuDeviceGetAttribute,"cuDeviceGetAttribute");LOAD_DRIVER(cuDeviceTotalMem,"cuDeviceTotalMem_v2");LOAD_DRIVER(cuCtxCreate,"cuCtxCreate_v2");LOAD_DRIVER(cuCtxDestroy,"cuCtxDestroy_v2");LOAD_DRIVER(cuCtxPushCurrent,"cuCtxPushCurrent_v2");LOAD_DRIVER(cuCtxPopCurrent,"cuCtxPopCurrent_v2");LOAD_DRIVER(cuMemGetInfo,"cuMemGetInfo_v2");LOAD_DRIVER(cuMemAlloc,"cuMemAlloc_v2");LOAD_DRIVER(cuMemFree,"cuMemFree_v2");LOAD_DRIVER(cuMemAllocHost,"cuMemAllocHost_v2");LOAD_DRIVER(cuMemFreeHost,"cuMemFreeHost");LOAD_DRIVER(cuMemcpyHtoD,"cuMemcpyHtoD_v2");LOAD_DRIVER(cuMemcpyHtoDAsync,"cuMemcpyHtoDAsync_v2");LOAD_DRIVER(cuMemcpyDtoHAsync,"cuMemcpyDtoHAsync_v2");LOAD_DRIVER(cuModuleLoadDataEx,"cuModuleLoadDataEx");LOAD_DRIVER(cuModuleUnload,"cuModuleUnload");LOAD_DRIVER(cuModuleGetFunction,"cuModuleGetFunction");LOAD_DRIVER(cuFuncGetAttribute,"cuFuncGetAttribute");LOAD_DRIVER(cuLaunchKernel,"cuLaunchKernel");LOAD_DRIVER(cuStreamCreate,"cuStreamCreate");LOAD_DRIVER(cuStreamDestroy,"cuStreamDestroy_v2");LOAD_DRIVER(cuStreamSynchronize,"cuStreamSynchronize");LOAD_DRIVER(cuEventCreate,"cuEventCreate");LOAD_DRIVER(cuEventDestroy,"cuEventDestroy_v2");LOAD_DRIVER(cuEventRecord,"cuEventRecord");LOAD_DRIVER(cuEventElapsedTime,"cuEventElapsedTime");
#undef LOAD_DRIVER
 }
 void loadCompiler(){if(nvrtc.value)return;std::filesystem::path folder;wchar_t setting[32768];auto count=GetEnvironmentVariableW(L"SCRATCHER_CUDA_PATH",setting,32768);if(count){if(count>=32768)throw std::runtime_error("SCRATCHER_CUDA_PATH is too long");folder=std::filesystem::path(setting);if(!folder.is_absolute())throw std::runtime_error("SCRATCHER_CUDA_PATH must be an absolute directory");}else{wchar_t exe[32768];auto length=GetModuleFileNameW(nullptr,exe,32768);if(!length||length>=32768)throw std::runtime_error("Cannot locate executable CUDA directory");folder=std::filesystem::path(exe).parent_path()/L"cuda";}
  // NVRTC opens builtins later by basename; the dependency search flags of its
  // own initial load do not apply to that later LoadLibrary call. Preload the
  // matching builtins from the same trusted absolute folder and retain its
  // handle, avoiding changes to PATH, CWD or process-wide DLL directories.
  builtins.value=LoadLibraryExW((folder/L"nvrtc-builtins64_124.dll").c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!builtins.value)throw std::runtime_error("CUDA compiler builtins DLL is unavailable in the configured absolute directory");
  nvrtc.value=LoadLibraryExW((folder/L"nvrtc64_120_0.dll").c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!nvrtc.value)throw std::runtime_error("CUDA compiler DLLs are unavailable in the configured absolute directory");
#define LOAD_NVRTC(name) name##_=symbol<decltype(name##_)>(nvrtc.value,#name)
  LOAD_NVRTC(nvrtcCreateProgram);LOAD_NVRTC(nvrtcCompileProgram);LOAD_NVRTC(nvrtcGetPTXSize);LOAD_NVRTC(nvrtcGetPTX);LOAD_NVRTC(nvrtcGetProgramLogSize);LOAD_NVRTC(nvrtcGetProgramLog);LOAD_NVRTC(nvrtcDestroyProgram);
#undef LOAD_NVRTC
 }
};
void checked(CUresult result,const char* operation){if(result!=CUDA_SUCCESS)throw std::runtime_error(std::string(operation)+" failed (CUDA driver code "+std::to_string(static_cast<int>(result))+")");}
void compiled(nvrtcResult result,const char* operation){if(result!=NVRTC_SUCCESS)throw std::runtime_error(std::string(operation)+" failed (NVRTC code "+std::to_string(static_cast<int>(result))+")");}
struct ContextScope {Api& api;bool pushed=false;ContextScope(Api& api,CUcontext context):api(api){checked(api.cuCtxPushCurrent_(context),"CUDA context push");pushed=true;}~ContextScope(){if(pushed){CUcontext previous=nullptr;api.cuCtxPopCurrent_(&previous);}}};
GpuInfo deviceInfo(Api& api){GpuInfo info;info.compiled=true;checked(api.cuInit_(0),"CUDA initialization");CUdevice device=0;checked(api.cuDeviceGet_(&device,0),"CUDA device selection");char name[256]{};checked(api.cuDeviceGetName_(name,sizeof(name),device),"CUDA device name");size_t total=0;checked(api.cuDeviceTotalMem_(&total,device),"CUDA device memory query");int major=0,minor=0;checked(api.cuDeviceGetAttribute_(&major,CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,device),"CUDA capability query");checked(api.cuDeviceGetAttribute_(&minor,CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,device),"CUDA capability query");info.name=name;info.total_bytes=total;info.compute_major=major;info.compute_minor=minor;info.available=true;return info;}

const char* kernelSource=R"cuda(
typedef unsigned long long U64;
__device__ void keep(U64* top,unsigned k,U64 value){if(value>=top[k-1])return;unsigned p=k-1;while(p&&value<top[p-1]){top[p]=top[p-1];--p;}top[p]=value;}
__device__ void reduce(U64* shared,U64* top,unsigned k){
 unsigned t=threadIdx.x;for(unsigned n=0;n<k;++n)shared[t*k+n]=top[n];__syncthreads();
 for(unsigned stride=blockDim.x/2;stride;stride/=2){if(t<stride){U64 merged[32];unsigned a=0,b=0;for(unsigned n=0;n<k;++n){U64 left=a<k?shared[t*k+a]:~0ULL,right=b<k?shared[(t+stride)*k+b]:~0ULL;if(left<=right){merged[n]=left;++a;}else{merged[n]=right;++b;}}for(unsigned n=0;n<k;++n)shared[t*k+n]=merged[n];}__syncthreads();}
}
__device__ __forceinline__ U64 warp_min(U64 value){
 for(unsigned offset=16;offset;offset>>=1){U64 other=__shfl_down_sync(0xffffffffU,value,offset);value=other<value?other:value;}return value;
}
extern "C" __global__ void match_tiles(const U64* corpus,const U64* queries,U64* partial,unsigned corpusCount,unsigned tiles,unsigned k){
 // Each thread owns a strided subset of 4096 shared keys and keeps just its
 // current minimum in registers. Only the owner of a selected winner rescans
 // its subset. No runtime-indexed per-thread top-k arrays or local-memory
 // insertion queues are used in the distance stage.
 extern __shared__ U64 keys[];__shared__ U64 warpMinima[4],winner;
 unsigned q=blockIdx.y,tile=blockIdx.x,t=threadIdx.x,lane=t&31,warp=t>>5;
 U64 query[4];for(unsigned n=0;n<4;++n)query[n]=queries[q*4+n];
 unsigned begin=tile*4096,end=begin+4096<corpusCount?begin+4096:corpusCount;U64 localMin=~0ULL;
 for(unsigned c=begin+t;c<end;c+=blockDim.x){unsigned d=0;for(unsigned n=0;n<4;++n)d+=__popcll(query[n]^corpus[c*4+n]);U64 value=(U64(d)<<32)|c;keys[c-begin]=value;localMin=value<localMin?value:localMin;}
 for(unsigned rank=0;rank<k;++rank){
  U64 minimum=warp_min(localMin);if(lane==0)warpMinima[warp]=minimum;__syncthreads();
  if(warp==0){minimum=warp_min(lane<4?warpMinima[lane]:~0ULL);if(lane==0){winner=minimum;partial[(q*tiles+tile)*k+rank]=minimum;}}__syncthreads();
  if(localMin==winner&&winner!=~0ULL){keys[unsigned(winner)-begin]=~0ULL;localMin=~0ULL;for(unsigned c=begin+t;c<end;c+=blockDim.x){U64 value=keys[c-begin];localMin=value<localMin?value:localMin;}}
 }
}
extern "C" __global__ void merge_tiles(const U64* partial,U64* output,unsigned tiles,unsigned k){
 extern __shared__ U64 shared[];unsigned q=blockIdx.x,t=threadIdx.x;U64 top[32];for(unsigned n=0;n<k;++n)top[n]=~0ULL;
 for(unsigned n=t;n<tiles*k;n+=blockDim.x)keep(top,k,partial[q*tiles*k+n]);reduce(shared,top,k);if(t==0)for(unsigned n=0;n<k;++n)output[q*k+n]=shared[n];
}
)cuda";
struct Gpu {
 Api api;GpuInfo info;CUcontext context=nullptr;CUmodule module=nullptr;CUfunction tilesKernel=nullptr,mergeKernel=nullptr;CUstream stream=nullptr;CUevent events[4]{};int distanceLocal=0,mergeLocal=0,distanceRegisters=0,mergeRegisters=0;
 CUdeviceptr corpusBuffer=0,queryBuffer=0,partialBuffer=0,resultBuffer=0;
 uint64_t corpusBytes=0,queryCapacity=0,partialCapacity=0,resultCapacity=0;void* pinnedQueries=nullptr;void* pinnedResults=nullptr;uint64_t pinnedQueryCapacity=0,pinnedResultCapacity=0;bool uploaded=false;
 explicit Gpu(Timings& timing){auto start=Clock::now();info=deviceInfo(api);api.loadCompiler();CUdevice device=0;checked(api.cuDeviceGet_(&device,0),"CUDA device selection");checked(api.cuCtxCreate_(&context,0,device),"CUDA context creation");try{CUcontext popped=nullptr;checked(api.cuCtxPopCurrent_(&popped),"CUDA initial context detach");ContextScope scope(api,context);size_t free=0,total=0;checked(api.cuMemGetInfo_(&free,&total),"CUDA free memory query");info.free_bytes=free;compiledProgram();checked(api.cuStreamCreate_(&stream,CU_STREAM_NON_BLOCKING),"CUDA stream creation");for(auto& event:events)checked(api.cuEventCreate_(&event,CU_EVENT_DEFAULT),"CUDA event creation");timing.setup_ms+=elapsed(start);}catch(...){cleanup();throw;}}
 void compiledProgram(){nvrtcProgram program=nullptr;compiled(api.nvrtcCreateProgram_(&program,kernelSource,"scratcher_fingerprint.cu",0,nullptr,nullptr),"CUDA program creation");try{auto compute=std::min(90u,info.compute_major*10+info.compute_minor);auto architecture="--gpu-architecture=compute_"+std::to_string(compute);const char* options[]={"--std=c++14",architecture.c_str()};auto result=api.nvrtcCompileProgram_(program,2,options);if(result!=NVRTC_SUCCESS){size_t size=0;api.nvrtcGetProgramLogSize_(program,&size);std::string log(size,'\0');if(size)api.nvrtcGetProgramLog_(program,log.data());throw std::runtime_error("CUDA kernel compilation failed: "+log.substr(0,2048));}size_t size=0;compiled(api.nvrtcGetPTXSize_(program,&size),"CUDA PTX size");std::vector<char> ptx(size);compiled(api.nvrtcGetPTX_(program,ptx.data()),"CUDA PTX retrieval");checked(api.cuModuleLoadDataEx_(&module,ptx.data(),0,nullptr,nullptr),"CUDA PTX JIT");checked(api.cuModuleGetFunction_(&tilesKernel,module,"match_tiles"),"CUDA distance kernel lookup");checked(api.cuModuleGetFunction_(&mergeKernel,module,"merge_tiles"),"CUDA merge kernel lookup");checked(api.cuFuncGetAttribute_(&distanceLocal,CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,tilesKernel),"CUDA distance local memory query");checked(api.cuFuncGetAttribute_(&mergeLocal,CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,mergeKernel),"CUDA merge local memory query");checked(api.cuFuncGetAttribute_(&distanceRegisters,CU_FUNC_ATTRIBUTE_NUM_REGS,tilesKernel),"CUDA distance register query");checked(api.cuFuncGetAttribute_(&mergeRegisters,CU_FUNC_ATTRIBUTE_NUM_REGS,mergeKernel),"CUDA merge register query");api.nvrtcDestroyProgram_(&program);}catch(...){api.nvrtcDestroyProgram_(&program);throw;}}
 void cleanup()noexcept{if(!context)return;try{ContextScope scope(api,context);if(stream)api.cuStreamSynchronize_(stream);for(auto buffer:{corpusBuffer,queryBuffer,partialBuffer,resultBuffer})if(buffer)api.cuMemFree_(buffer);if(pinnedQueries)api.cuMemFreeHost_(pinnedQueries);if(pinnedResults)api.cuMemFreeHost_(pinnedResults);for(auto event:events)if(event)api.cuEventDestroy_(event);if(stream)api.cuStreamDestroy_(stream);if(module)api.cuModuleUnload_(module);}catch(...){}api.cuCtxDestroy_(context);context=nullptr;}
 ~Gpu(){cleanup();}
 void resize(CUdeviceptr& buffer,uint64_t& capacity,uint64_t required){if(capacity>=required)return;if(buffer){checked(api.cuMemFree_(buffer),"CUDA old buffer release");buffer=0;capacity=0;}checked(api.cuMemAlloc_(&buffer,static_cast<size_t>(required)),"CUDA buffer allocation");capacity=required;}
 uint64_t deviceBytes()const{return corpusBytes+queryCapacity+partialCapacity+resultCapacity;}
 std::vector<std::vector<Neighbor>> search(const std::vector<Fingerprint>& corpus,const std::vector<Fingerprint>& queries,uint32_t k,uint64_t cap,SearchResult& result){
  const uint32_t tiles=static_cast<uint32_t>((corpus.size()+tileSize-1)/tileSize);const uint64_t cb=corpus.size()*sizeof(Fingerprint),qb=queries.size()*sizeof(Fingerprint),pb=uint64_t(queries.size())*tiles*k*sizeof(uint64_t),rb=uint64_t(queries.size())*k*sizeof(uint64_t);
  // Include retained capacities before any allocation; free surplus query
  // buffers when a different batch shape would exceed the configured cap.
  if(cb+qb+pb+rb>cap)throw std::runtime_error("CUDA configured device-memory cap is too small for this batch");
  ContextScope scope(api,context);if(cb+std::max(qb,queryCapacity)+std::max(pb,partialCapacity)+std::max(rb,resultCapacity)>cap){for(auto pair:{std::pair{&queryBuffer,&queryCapacity},std::pair{&partialBuffer,&partialCapacity},std::pair{&resultBuffer,&resultCapacity}}){if(*pair.first)checked(api.cuMemFree_(*pair.first),"CUDA buffer release");*pair.first=0;*pair.second=0;}}
  result.cache_hit=uploaded;auto start=Clock::now();if(!uploaded){resize(corpusBuffer,corpusBytes,cb);checked(api.cuMemcpyHtoD_(corpusBuffer,corpus.data(),static_cast<size_t>(cb)),"CUDA corpus upload");uploaded=true;result.timings.corpus_upload_ms=elapsed(start);}
  resize(queryBuffer,queryCapacity,qb);resize(partialBuffer,partialCapacity,pb);resize(resultBuffer,resultCapacity,rb);
  if(pinnedQueryCapacity<qb){if(pinnedQueries){checked(api.cuMemFreeHost_(pinnedQueries),"CUDA pinned query release");pinnedQueries=nullptr;pinnedQueryCapacity=0;}checked(api.cuMemAllocHost_(&pinnedQueries,static_cast<size_t>(qb)),"CUDA pinned query allocation");pinnedQueryCapacity=qb;}if(pinnedResultCapacity<rb){if(pinnedResults){checked(api.cuMemFreeHost_(pinnedResults),"CUDA pinned result release");pinnedResults=nullptr;pinnedResultCapacity=0;}checked(api.cuMemAllocHost_(&pinnedResults,static_cast<size_t>(rb)),"CUDA pinned result allocation");pinnedResultCapacity=rb;}std::memcpy(pinnedQueries,queries.data(),static_cast<size_t>(qb));std::vector<uint64_t> output(queries.size()*k);checked(api.cuEventRecord_(events[0],stream),"CUDA event record");checked(api.cuMemcpyHtoDAsync_(queryBuffer,pinnedQueries,static_cast<size_t>(qb),stream),"CUDA query upload");checked(api.cuEventRecord_(events[1],stream),"CUDA event record");
  uint32_t corpusCount=static_cast<uint32_t>(corpus.size()),tileCount=tiles,topK=k;void* args[]={&corpusBuffer,&queryBuffer,&partialBuffer,&corpusCount,&tileCount,&topK};checked(api.cuLaunchKernel_(tilesKernel,tiles,static_cast<unsigned>(queries.size()),1,128,1,1,tileSize*sizeof(uint64_t),stream,args,nullptr),"CUDA top-k distance kernel launch");void* mergeArgs[]={&partialBuffer,&resultBuffer,&tileCount,&topK};checked(api.cuLaunchKernel_(mergeKernel,static_cast<unsigned>(queries.size()),1,1,128,1,1,128*k*sizeof(uint64_t),stream,mergeArgs,nullptr),"CUDA top-k merge kernel launch");checked(api.cuEventRecord_(events[2],stream),"CUDA event record");checked(api.cuMemcpyDtoHAsync_(pinnedResults,resultBuffer,static_cast<size_t>(rb),stream),"CUDA result download");checked(api.cuEventRecord_(events[3],stream),"CUDA event record");checked(api.cuStreamSynchronize_(stream),"CUDA batch synchronization");float milliseconds=0;checked(api.cuEventElapsedTime_(&milliseconds,events[0],events[1]),"CUDA timing query");result.timings.query_upload_ms=milliseconds;checked(api.cuEventElapsedTime_(&milliseconds,events[1],events[2]),"CUDA timing query");result.timings.kernel_ms=milliseconds;checked(api.cuEventElapsedTime_(&milliseconds,events[2],events[3]),"CUDA timing query");result.timings.download_ms=milliseconds;result.device_bytes=deviceBytes();result.distance_kernel_local_bytes=distanceLocal;result.merge_kernel_local_bytes=mergeLocal;result.distance_kernel_registers=distanceRegisters;result.merge_kernel_registers=mergeRegisters;std::memcpy(output.data(),pinnedResults,static_cast<size_t>(rb));return unpack(output,queries.size(),k);
 }
};
#endif
}

struct Matcher::Impl {
 std::vector<Fingerprint> corpus;uint32_t workers;uint64_t cap;std::mutex mutex;WorkerPool pool;
 struct Calibration {bool cuda=false,equal=false;double cpu_ms=0,cuda_warm_ms=0;};std::unordered_map<uint64_t,Calibration> calibrated;
#if defined(SCRATCHER_ENABLE_CUDA) && SCRATCHER_ENABLE_CUDA && defined(_WIN32)
 std::unique_ptr<Gpu> gpu;
#endif
 Impl(std::vector<Fingerprint> c,uint32_t w,uint64_t memory):corpus(std::move(c)),workers(w),cap(memory),pool(w){}
};
GpuInfo probeGpu(){GpuInfo info;
#if defined(SCRATCHER_ENABLE_CUDA) && SCRATCHER_ENABLE_CUDA && defined(_WIN32)
 info.compiled=true;try{Api api;info=deviceInfo(api);CUdevice device=0;checked(api.cuDeviceGet_(&device,0),"CUDA device selection");CUcontext context=nullptr;checked(api.cuCtxCreate_(&context,0,device),"CUDA probe context");size_t free=0,total=0;auto result=api.cuMemGetInfo_(&free,&total);CUcontext previous=nullptr;api.cuCtxPopCurrent_(&previous);api.cuCtxDestroy_(context);checked(result,"CUDA free memory query");info.free_bytes=free;}catch(const std::exception& error){info.available=false;info.reason=error.what();}
#else
 info.reason="CUDA support was disabled when this binary was built";
#endif
 return info;
}
Matcher::Matcher(std::vector<Fingerprint> corpus,uint32_t workers,uint64_t cap){if(corpus.size()>maxCorpus)throw std::invalid_argument("Fingerprint corpus exceeds 1,000,000 entries");if(workers<1||workers>32)throw std::invalid_argument("CPU workers must be between 1 and 32");if(cap>maxDeviceBytes)throw std::invalid_argument("CUDA device-memory cap exceeds 256 MiB");impl_=std::make_unique<Impl>(std::move(corpus),workers,cap);}
Matcher::~Matcher()=default;Matcher::Matcher(Matcher&&) noexcept=default;Matcher& Matcher::operator=(Matcher&&) noexcept=default;
size_t Matcher::size()const noexcept{return impl_?impl_->corpus.size():0;}
SearchResult Matcher::search(const std::vector<Fingerprint>& queries,uint32_t requestedK,Mode mode){
 auto start=Clock::now();if(!impl_)throw std::runtime_error("Cannot search a moved-from matcher");if(requestedK<1||requestedK>maxK)throw std::invalid_argument("Top-k must be between 1 and 32");if(queries.size()>maxQueries)throw std::invalid_argument("Query batch exceeds 1,024 fingerprints");if(uint64_t(queries.size())*impl_->corpus.size()>maxPairs)throw std::invalid_argument("Query batch exceeds 128 Mi comparison pairs");if(mode!=Mode::Cpu&&mode!=Mode::Cuda&&mode!=Mode::Auto)throw std::invalid_argument("Unknown accelerator mode");
 std::lock_guard lock(impl_->mutex);SearchResult result;if(mode==Mode::Auto)result.selection_policy="retained_corpus_warm_cuda";result.cpu_workers=std::min<uint32_t>(impl_->workers,static_cast<uint32_t>(std::max<size_t>(1,impl_->corpus.size())));uint32_t k=std::min<uint32_t>(requestedK,static_cast<uint32_t>(impl_->corpus.size()));if(!k||queries.empty()){result.neighbors.resize(queries.size());result.fallback_reason=mode==Mode::Cpu?"":"Empty workload requires no accelerator";result.timings.end_to_end_ms=elapsed(start);return result;}
 auto cpu=[&]{auto began=Clock::now();auto values=cpuSearch(impl_->corpus,queries,k,impl_->workers,impl_->pool);result.timings.cpu_ms+=elapsed(began);return values;};
 if(mode==Mode::Cpu){result.neighbors=cpu();result.timings.end_to_end_ms=elapsed(start);return result;}
#if defined(SCRATCHER_ENABLE_CUDA) && SCRATCHER_ENABLE_CUDA && defined(_WIN32)
 auto signature=(uint64_t(queries.size())<<32)|k;auto found=impl_->calibrated.find(signature);
 const bool calibrating=mode==Mode::Auto&&found==impl_->calibrated.end();auto calibrationStart=Clock::now();
 if(mode==Mode::Auto){result.selection_policy="retained_corpus_warm_cuda";if(found!=impl_->calibrated.end()){result.calibration_equal=found->second.equal;result.auto_cpu_baseline_ms=found->second.cpu_ms;result.auto_cuda_warm_baseline_ms=found->second.cuda_warm_ms;}else result.calibration_performed=true;}
 if(mode==Mode::Auto&&found!=impl_->calibrated.end()&&!found->second.cuda){result.neighbors=cpu();result.fallback_reason=found->second.equal?"Warm CUDA did not beat optimized CPU by the required 10% margin for this retained corpus and batch shape":"CUDA calibration disagreed with exact CPU results; CPU policy retained";result.cache_hit=true;if(impl_->gpu)result.device_bytes=impl_->gpu->deviceBytes();result.timings.end_to_end_ms=elapsed(start);return result;}
 try{
  // Reject the exact batch allocation before context, compiler or VRAM work.
  auto tiles=(impl_->corpus.size()+tileSize-1)/tileSize;uint64_t required=impl_->corpus.size()*sizeof(Fingerprint)+queries.size()*sizeof(Fingerprint)+uint64_t(queries.size())*k*(tiles+1)*sizeof(uint64_t);if(required>impl_->cap)throw std::runtime_error("CUDA configured device-memory cap is too small for this batch");
  if(!impl_->gpu)impl_->gpu=std::make_unique<Gpu>(result.timings);auto gpuValues=impl_->gpu->search(impl_->corpus,queries,k,impl_->cap,result);
  if(calibrating){
   // The initial GPU pass records cold setup/upload costs and warms the exact
   // batch. Compare the persistent CPU pool with a separate retained-corpus
   // CUDA pass, including query upload, both kernels, download and unpacking.
   auto cpuValues=cpu();SearchResult warm;auto warmStart=Clock::now();auto warmValues=impl_->gpu->search(impl_->corpus,queries,k,impl_->cap,warm);double warmMilliseconds=elapsed(warmStart);
   result.timings.query_upload_ms+=warm.timings.query_upload_ms;result.timings.kernel_ms+=warm.timings.kernel_ms;result.timings.download_ms+=warm.timings.download_ms;
   result.auto_cpu_baseline_ms=result.timings.cpu_ms;result.auto_cuda_warm_baseline_ms=warmMilliseconds;
   result.calibration_equal=cpuValues==gpuValues&&cpuValues==warmValues;
   if(!result.calibration_equal){impl_->gpu.reset();impl_->calibrated.clear();result.fallback_reason="CUDA calibration disagreed with exact CPU results; accelerator reset";result.neighbors=std::move(cpuValues);result.device_bytes=0;impl_->calibrated[signature]={false,false,result.auto_cpu_baseline_ms,warmMilliseconds};}
   else if(warmMilliseconds<=result.auto_cpu_baseline_ms*0.90){result.backend="cuda";result.neighbors=std::move(warmValues);impl_->calibrated[signature]={true,true,result.auto_cpu_baseline_ms,warmMilliseconds};}
   else{result.neighbors=std::move(cpuValues);result.fallback_reason="Warm CUDA did not beat optimized CPU by the required 10% margin for this retained corpus and batch shape";impl_->calibrated[signature]={false,true,result.auto_cpu_baseline_ms,warmMilliseconds};}
   result.timings.calibration_ms=elapsed(calibrationStart);
  }else{result.backend="cuda";result.neighbors=std::move(gpuValues);}
 }catch(const std::exception& error){impl_->gpu.reset();impl_->calibrated.clear();result.device_bytes=0;result.backend="cpu";result.cache_hit=false;result.calibration_equal=false;result.fallback_reason=error.what();result.neighbors=cpu();if(calibrating)result.timings.calibration_ms=elapsed(calibrationStart);}

#else
 result.fallback_reason="CUDA support was disabled when this binary was built";result.neighbors=cpu();
#endif
 result.timings.end_to_end_ms=elapsed(start);return result;
}
}
