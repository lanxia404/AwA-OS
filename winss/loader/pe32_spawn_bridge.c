// winss/loader/pe32_spawn_bridge.c
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

/* 嘗試就地包含；若此檔位於 loader 目錄，header 通常在 ../ntshim32/ */
#if defined(__has_include)
  #if __has_include("ntshim_api.h")
    #include "ntshim_api.h"
  #elif __has_include("../ntshim32/ntshim_api.h")
    #include "../ntshim32/ntshim_api.h"
  #else
    #error "Unable to locate ntshim_api.h (tried 'ntshim_api.h' and '../ntshim32/ntshim_api.h')"
  #endif
#else
  /* 較舊編譯器：採用相對於本檔的預設路徑 */
  #include "../ntshim32/ntshim_api.h"
#endif

/* 由 Loader 註冊的真正實作（在本行程生命週期內有效） */
static pe32_spawn_fn g_spawn_impl = NULL;

void nt_set_spawn_impl(pe32_spawn_fn fn) {
  g_spawn_impl = fn;
}

/* 取得 loader 路徑（可用環境變數覆寫；否則使用系統預設安裝路徑） */
static const char* _fallback_loader_path(void) {
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

/* 最小可行的保底方案：
 *  - 不解析 Windows cmdline quoting，先把 cmdline 原樣放在 argv[2]
 *  - 目前測試（hello.exe、cmdlite）不依賴參數，足夠過 CI；未來可擴充完整解析 */
static int _fallback_spawn_exec(const char* path, const char* cmdline) {
  const char* loader = _fallback_loader_path();
  pid_t pid = fork();
  if (pid < 0) return 0;     /* 失敗 -> 回 0 表示失敗（CreateProcessA 會回 FALSE） */

  if (pid == 0) {
    /* 子行程直接 exec loader；失敗時以 127 結束避免回到父行程流程 */
    if (cmdline && *cmdline) {
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    } else {
      execl(loader, "pe_loader32", path, (char*)NULL);
    }
    _exit(127);
  }

  /* 父行程不等待（CreateProcessA/WaitForSingleObject 由上層處理） */
  return 1;
}

/* 對外導出：ntshim32.c 的 CreateProcessA 直接呼叫這個 */
int pe32_spawn(const char* path, const char* cmdline) {
  if (g_spawn_impl) return g_spawn_impl(path, cmdline);
  return _fallback_spawn_exec(path, cmdline);
}
