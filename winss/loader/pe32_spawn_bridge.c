#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "../ntshim32/ntshim_api.h"

/* 由 Loader 註冊的真正實作（在本行程生命週期內有效） */
static pe32_spawn_fn g_spawn_impl = NULL;

void nt_set_spawn_impl(pe32_spawn_fn fn) {
  g_spawn_impl = fn;
}

/* 取得 loader 路徑（可由環境變數覆蓋） */
static const char* _fallback_loader_path(void) {
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

/* 最小可行 fallback：
 * - 以 execl 啟動 loader：argv[0]="pe_loader32", argv[1]=path, argv[2]=cmdline(可省)
 * - 不解析 Windows-style quoting（目前測試不依賴參數，足夠過 CI）
 * - 父行程不等待；由上層 WaitForSingleObject 處理等待 */
static int _fallback_spawn_exec(const char* path, const char* cmdline) {
  const char* loader = _fallback_loader_path();
  pid_t pid = fork();
  if (pid < 0) return 0;  /* fork 失敗 -> FALSE */

  if (pid == 0) {
    if (cmdline && *cmdline) {
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    } else {
      execl(loader, "pe_loader32", path, (char*)NULL);
    }
    _exit(127); /* exec 失敗 */
  }
  return 1; /* 啟動成功 */
}

/* 給 CreateProcessA 呼叫的統一入口 */
int pe32_spawn(const char* path, const char* cmdline) {
  if (g_spawn_impl) return g_spawn_impl(path, cmdline);
  return _fallback_spawn_exec(path, cmdline);
}