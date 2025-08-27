// winss/loader/pe32_spawn_bridge.c
// 這支檔案編進 libntshim32.a（target: winss/ntshim32）
// 作用：提供對外符號 pe32_spawn()；在 Loader 未註冊實作時，使用 fork/exec 呼叫系統安裝的 pe_loader32 做保底。

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../ntshim32/ntshim_api.h"  // 注意相對路徑，因為此檔位於 winss/loader/

// 由 Loader (選擇性) 註冊的真正實作（同程序內部 spawn）。未註冊則為 NULL。
static pe32_spawn_fn g_spawn_impl = NULL;

void nt_set_spawn_impl(pe32_spawn_fn fn) {
  g_spawn_impl = fn;
}

static const char* _fallback_loader_path(void) {
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

// 保底實作：fork + execl 執行系統上的 pe_loader32。
static int _fallback_spawn_exec(const char* path, const char* cmdline) {
  const char* loader = _fallback_loader_path();
  pid_t pid = fork();
  if (pid < 0) return 0;         // 失敗

  if (pid == 0) {
    if (cmdline && *cmdline)
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    else
      execl(loader, "pe_loader32", path, (char*)NULL);
    _exit(127); // execl 失敗
  }
  // 父行程不等待，交由 WaitForSingleObject/WaitPid 等呼叫處理
  return 1;
}

// 對外導出：被 CreateProcessA() 呼叫
int pe32_spawn(const char* path, const char* cmdline) {
  if (g_spawn_impl) return g_spawn_impl(path, cmdline);
  return _fallback_spawn_exec(path, cmdline);
}
