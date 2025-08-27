// winss/loader/pe_spawn_shim.c
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stddef.h>  // for NULL

#include "../ntshim32/ntshim_api.h"

/* Loader 端的實作：可以在這裡做更聰明的參數處理、環境、工作目錄等 */
static int pe32_spawn_impl(const char* path, const char* cmdline) {
  const char* loader = getenv("AWAOS_PE_LOADER");
  if (!loader || !*loader) loader = "/usr/lib/awaos/pe_loader32";

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
  return 1;
}

/* 以 constructor 方式在 loader 啟動時註冊實作 */
__attribute__((constructor))
static void _register_spawn_impl(void) {
  nt_set_spawn_impl(pe32_spawn_impl);
}