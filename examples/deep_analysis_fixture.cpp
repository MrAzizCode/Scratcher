// Original redistributable validation fixture, dedicated to the public domain
// under CC0-1.0. Its exported byte arrays are test data and are NEVER executed.
#include <cstdint>

using DeepUnary = int (*)(int);
extern "C" {
__declspec(dllexport) __declspec(noinline) int deep_leaf_a(int n) { return n * 7 + 3; }
__declspec(dllexport) __declspec(noinline) int deep_leaf_b(int n) { return n ^ 0x153; }
__declspec(dllexport) __declspec(noinline) int deep_branch(int n) {
    if (n < 0) return -n + 4;
    return n % 3 == 0 ? n * 5 : n + 11;
}
__declspec(dllexport) __declspec(noinline) int deep_loop(int n) {
    unsigned value=0x193;
    for (unsigned i=0;i<(static_cast<unsigned>(n)&31);++i) value=(value*33)^i;
    return static_cast<int>(value);
}
__declspec(dllexport) __declspec(noinline) int deep_switch(int n) {
    switch(n) {
    case 0:return deep_leaf_a(n+17);
    case 1:return deep_leaf_b(n+91);
    case 2:return deep_branch(n-14);
    case 3:return deep_loop(n+8);
    case 4:return deep_leaf_a(n*19);
    case 5:return deep_leaf_b(n-37);
    default:return -127;
    }
}
// The const table belongs to a read-only PE section; the mutable table does not.
__declspec(dllexport) extern DeepUnary const deep_readonly_targets[2]={deep_leaf_a,deep_leaf_b};
__declspec(dllexport) DeepUnary deep_mutable_targets[2]={deep_leaf_a,deep_leaf_b};
__declspec(dllexport) __declspec(noinline) int deep_readonly_dispatch(int n) {
    return deep_readonly_targets[static_cast<unsigned>(n)&1](n);
}
__declspec(dllexport) __declspec(noinline) int deep_mutable_dispatch(int n) {
    return deep_mutable_targets[static_cast<unsigned>(n)&1](n);
}

// HAND-AUTHORED x64 bytecode, not compiler-generated functions. 0xCC gaps are
// deliberately unreachable trap bytes. Explicit 32-byte bounds are in the
// benchmark manifest. All relative targets are inside the respective array.
#pragma section(".text$deep", read, execute)
#define DEEP_BYTES __declspec(allocate(".text$deep")) __declspec(dllexport) __declspec(align(16)) extern const unsigned char
// LEA RAX,[RIP+9]; JMP RAX; gap; MOV EAX,42; RET.
DEEP_BYTES deep_bytes_lea_jump[32]={
    0x48,0x8d,0x05,0x09,0,0,0,0xff,0xe0,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
    0xb8,0x2a,0,0,0,0xc3,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};
// LEA RAX,[RIP+9]; CALL RAX; RET; gap; MOV EAX,7; RET.
DEEP_BYTES deep_bytes_lea_call[32]={
    0x48,0x8d,0x05,0x09,0,0,0,0xff,0xd0,0xc3,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
    0xb8,0x07,0,0,0,0xc3,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};
// LEA RAX,[RIP+9]; XOR EAX,EAX; JMP RAX. Old RAX target MUST be killed.
DEEP_BYTES deep_bytes_clobber[32]={
    0x48,0x8d,0x05,0x09,0,0,0,0x31,0xc0,0xff,0xe0,
    0xcc,0xcc,0xcc,0xcc,0xcc,
    0xb8,0x63,0,0,0,0xc3,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};
// TEST ECX,ECX; JNE +7 (to JMP); LEA RAX,[RIP+5]; JMP RAX.
// The bypass reaches JMP without defining RAX. A known-path target is only a
// path-local candidate; this diamond must retain a residual unknown route.
DEEP_BYTES deep_bytes_diamond[32]={
    0x85,0xc9,0x75,0x07,0x48,0x8d,0x05,0x05,0,0,0,0xff,0xe0,
    0xcc,0xcc,0xcc,
    0xb8,0x4d,0,0,0,0xc3,
    0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};
#undef DEEP_BYTES
}

// The benchmarking workflow reads this executable without running main.
int main(int argc,char**) { return deep_branch(argc)+deep_loop(argc); }
