// winss/loader/pe_spawn_shim.c
// Minimal spawn glue so that ntshim32(CreateProcessA) can call back into the loader.
// Current approach: re-enter the loader's main() in-process with [exe] only.
// TODO: replace with real process/thread model later.

#include <stdint.h>
#include "../include/win/minwin.h"

// forward-declare loader's main; it already exists in pe_loader32.
int main(int argc, char** argv);

int pe32_spawn(const char* app, const char* cmdline, PROCESS_INFORMATION* pi) {
  (void)cmdline; // CI 用例目前沒帶參數，先忽略。後續可解析再傳入。

  if (!app || !*app) {
    SetLastError(87 /*ERROR_INVALID_PARAMETER*/);
    return FALSE;
  }

  // 最小 argv：["pe_loader32", app, NULL]
  char* argv_local[3];
  argv_local[0] = (char*)"pe_loader32";
  argv_local[1] = (char*)app;
  argv_local[2] = NULL;

  // 先填入假句柄與 ID（目前 WaitForSingleObject/GetExitCodeProcess 的最小實作可接受）
  if (pi) {
    pi->hProcess    = (HANDLE)(uintptr_t)1;
    pi->hThread     = (HANDLE)(uintptr_t)1;
    pi->dwProcessId = 1;
    pi->dwThreadId  = 1;
  }

  // 重新進入 loader：相當於「在本程序再載入並執行 app」
  int rc = main(2, argv_local);

  // Windows BOOL：非 0 成功；這裡以 rc==0 視為成功
  return (rc == 0) ? TRUE : FALSE;
}