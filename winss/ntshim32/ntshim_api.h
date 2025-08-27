#pragma once
/* Bridge API exported by libntshim32.a for the loader (pe_loader32) */

#include "../include/win/minwin.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 由 thread.c/ntshim32.c 提供，讓 Loader 設定給子程式看的 ANSI command line */
void __attribute__((visibility("default")))
nt_set_command_lineA(const char* exe_path, char* const* argv);

/* 擷取最近一次以 CreateProcessA 方式啟動並等待之子行程退出碼（簡化器） */
DWORD __attribute__((visibility("default")))
nt_last_child_exit_code(void);

/* 以 Linux fork/exec/posix_spawn 等方式同步啟動本地 ELF（給 fallback 或測試用）*/
DWORD __attribute__((visibility("default")))
nt_spawn_sync_and_wait(const char* app, const char* cmdline);

/* 由 ntdll32/teb.c 提供：初始化當前執行緒的 TEB/FS */
void __attribute__((visibility("default"))) _nt_teb_setup_for_current(void);

#ifdef __cplusplus
}
#endif