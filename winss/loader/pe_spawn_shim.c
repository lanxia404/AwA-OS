// winss/loader/pe_spawn_shim.c
// 在 loader 啟動時註冊 pe32_spawn 的「真實實作」，供 CreateProcessA 透過 bridge 呼叫。

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stddef.h>      // for NULL
#include "../ntshim32/ntshim_api.h"

/* 使用目前的 loader（/proc/self/exe）去載入目標 Windows exe */
static const char* _self_loader_path(void) {
  return "/proc/self/exe";  // 在大多數 Linux 環境下可行；若需覆寫，可用 AWAOS_PE_LOADER
}

int pe32_spawn(const char* path, const char* cmdline) {
  pid_t pid = fork();
  if (pid < 0) return 0;
  if (pid == 0) {
    const char* loader = _self_loader_path();
    if (cmdline && *cmdline) {
      execl(loader, "pe_loader32", path, cmdline, (char*)NULL);
    } else {
      execl(loader, "pe_loader32", path, (char*)NULL);
    }
    _exit(127);
  }
  return 1;
}

/* 供 pe_loader32.c 呼叫，用以註冊上面的實作 */
void register_loader_spawn_impl(void) {
  nt_set_spawn_impl(&pe32_spawn);
}