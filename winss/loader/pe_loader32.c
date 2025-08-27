// winss/loader/pe32_spawn_bridge.c
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

/* 嘗試相對 include（此檔位於 loader/，頭檔在 ntshim32/） */
#if defined(__has_include)
  #if __has_include("ntshim_api.h")
    #include "ntshim_api.h"
  #elif __has_include("../ntshim32/ntshim_api.h")
    #include "../ntshim32/ntshim_api.h"
  #else
    #error "Unable to locate ntshim_api.h"
  #endif
#else
  #include "../ntshim32/ntshim_api.h"
#endif

/* 由 Loader 註冊的真正實作（行程內有效） */
static pe32_spawn_fn g_spawn_impl = NULL;

void nt_set_spawn_impl(pe32_spawn_fn fn) {
  g_spawn_impl = fn;
}

/* 取得 loader 路徑（可用環境變數覆寫；否則用預設安裝路徑） */
static const char* _fallback_loader_path(void) {
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

/* 最小保底：不處理 Windows quoting，將 cmdline 當成單一 argv 直接交給 loader */
static int _fallback_spawn_exec(const char* path, const char* cmdline) {
  const char* loader = _fallback_loader_path();
  pid_t pid = fork();
  if (pid < 0) return 0;

  if (pid == 0) {
    if (cmdline && *cmdline) {
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    } else {
      execl(loader, "pe_loader32", path, (char*)NULL);
    }
    _exit(127);
  }
  /* 父行程不等待；上層 WaitForSingleObject/Process 處理 */
  return 1;
}

/* CreateProcessA 會呼叫到這裡 */
int pe32_spawn(const char* path, const char* cmdline) {
  if (g_spawn_impl) return g_spawn_impl(path, cmdline);
  return _fallback_spawn_exec(path, cmdline);
}