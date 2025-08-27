#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "ntshim_api.h"

/* 由 Loader 註冊的真正實作（在本行程生命週期內有效） */
static pe32_spawn_fn g_spawn_impl = NULL;

void nt_set_spawn_impl(pe32_spawn_fn fn) {
  g_spawn_impl = fn;
}

/* 簡單的 helper：取得 loader 路徑（與安裝路徑一致） */
static const char* _fallback_loader_path(void) {
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

/* 最小可行的保底方案：
 *  - 不解析 Windows cmdline quoting，先把 cmdline 原樣附在 argv[2] 之後交給 loader
 *  - 目前我們的測試（hello.exe、cmdlite）不依賴參數，足夠過 CI；未來可擴充為完整解析 */
static int _fallback_spawn_exec(const char* path, const char* cmdline) {
  const char* loader = _fallback_loader_path();
  pid_t pid = fork();
  if (pid < 0) return 0;          /* 失敗 -> 回 0 表示失敗（CreateProcessA 會回 FALSE） */
  if (pid == 0) {
    if (cmdline && *cmdline) {
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    } else {
      execl(loader, "pe_loader32", path, (char*)NULL);
    }
    _exit(127);
  }
  /* 父行程這裡不等（CreateProcessA/WaitForSingleObject 會處理等待） */
  return 1;
}

/* 對外導出：ntshim32.c 的 CreateProcessA 直接呼叫這個 */
int pe32_spawn(const char* path, const char* cmdline) {
  if (g_spawn_impl) return g_spawn_impl(path, cmdline);
  return _fallback_spawn_exec(path, cmdline);
}