#include <windows.h>

static DWORD slen(const char* s){ DWORD n=0; while (s[n]) ++n; return n; }

/* MinGW 的 GCC 會插入對 __main 的呼叫；不連 CRT 時要自己補一個空實作 */
void __main(void) {}

void WINAPI main(void){                       /* stdcall；符號會是 _main@0 */
  const char* msg = "Hello from PE32 via AwA-OS WinSS!\n";
  DWORD w = 0;
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  WriteFile(h, msg, slen(msg), &w, 0);
  ExitProcess(0);
}
