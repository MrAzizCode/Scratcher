#include <windows.h>
extern "C" __declspec(dllexport) __declspec(noinline) int add_numbers(int a,int b){return a*3+b;}
extern "C" __declspec(dllexport) __declspec(noinline) int choose_larger(int a,int b){return a>b?a:b;}
extern "C" __declspec(dllexport) __declspec(noinline) unsigned rolling_hash(const char* text){unsigned hash=2166136261u;while(*text){hash^=(unsigned char)*text++;hash*=16777619u;}return hash;}
int main(){volatile auto result=add_numbers((int)GetTickCount(),choose_larger(4,9));return (int)(rolling_hash("Welcome to Scratcher native analysis")^(unsigned)result);}
