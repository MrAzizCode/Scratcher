#include <windows.h>
#include <winver.h>
#include <typeinfo>
#include <stdexcept>
#include <string>
struct Shape { virtual ~Shape()=default; virtual int area(int)=0; };
struct Rectangle:Shape { int width=7; __declspec(noinline) int area(int h)override{return width*h;} };
struct Tagged { virtual ~Tagged()=default; virtual const char* tag(){return "Scratcher readable fixture";} };
struct Panel:Rectangle,Tagged { __declspec(noinline) int area(int h)override{return Rectangle::area(h)+3;} };
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_branch(int n){if(n<0)return -n;return n*3+7;}
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_switch(int n){switch(n){case 0:return 17;case 1:return 3;case 2:return 81;case 3:return 23;case 4:return 99;case 5:return 104;default:return -1;}}
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_virtual(Shape* p,int n){return p->area(n);}
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_rtti(Shape* p){auto* r=dynamic_cast<Panel*>(p);return r?r->width:int(typeid(*p).name()[0]);}
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_exception(int n){try{if(n<0)throw std::runtime_error("negative fixture value");return fixture_branch(n);}catch(const std::exception& e){return int(e.what()[0]);}}
extern "C" __declspec(dllexport) __declspec(noinline) DWORD fixture_delay_import(const wchar_t* path){DWORD ignored=0;return GetFileVersionInfoSizeW(path,&ignored);}
int main(int argc,char**){Panel p;volatile auto indirect=&fixture_branch;int value=indirect(argc)+fixture_switch(argc)+fixture_virtual(&p,argc)+fixture_rtti(&p)+fixture_exception(argc);if(argc==12345)value+=int(fixture_delay_import(L"fixture.exe"));return value&255;}
