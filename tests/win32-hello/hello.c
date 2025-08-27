// tests/win32-hello/hello.c
#include "../../winss/include/win/minwin.h"

#ifdef __GNUC__
void __main(void) { /* CRT stub for -nostdlib */ }
#endif

static DWORD slen(const char* s){ DWORD n=0; while(s[n]) ++n; return n; }

void main(void){
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  const char* msg = "Hello from AwA-OS Win32!\r\n";
  DWORD w=0; WriteFile(h, msg, slen(msg), &w, 0);
  ExitProcess(0);
}