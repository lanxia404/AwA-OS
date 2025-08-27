// tests/win32-hello/hello.c
// Minimal Win32 console hello for AwA-OS loader (i386, -nostdlib).
// Build (CI):
//   i686-w64-mingw32-gcc tests/win32-hello/hello.c -s -o tests/win32-hello/hello.exe \
//     -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector \
//     -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
#include "../../winss/include/win/minwin.h"

#ifdef __GNUC__
// GCC/MinGW may insert a reference to __main when no CRT is linked.
// Provide a no-op stub to avoid undefined reference under -nostdlib.
void __main(void) { /* no-op */ }
#endif

#define OUT ((HANDLE)(uintptr_t)STD_OUTPUT_HANDLE)

static DWORD slen(const char* s){
  DWORD n=0; if(!s) return 0; while(s[n]) ++n; return n;
}

#ifdef __GNUC__
__attribute__((stdcall))
#endif
void main(void) {
  const char* msg = "Hello from AwA-OS Win32 personality!\r\n";
  DWORD w = 0;
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  // Even if GetStdHandle returns a pseudo-handle, our shim maps it to fd=1.
  WriteFile(h, msg, slen(msg), &w, 0);
  ExitProcess(0);
}