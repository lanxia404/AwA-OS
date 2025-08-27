// winss/ntdll32/teb.c
// 以 set_thread_area(2) 建立最小可用的 TEB/TLS，並把 x86 %fs 指到該區塊。
// 這是 loader/PoC 用的最小實作，非完整 Windows TEB。

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/ldt.h>                /* struct user_desc, set_thread_area(2) */

#include "../include/win/minwin.h"  /* DWORD 等型別 */
#include "../include/nt/teb.h"      /* AWA_EXPORT 與宣告 */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* 最小化 TEB 佈局：只放我們會用到的欄位 */
typedef struct _AWA_TEB_MIN {
  void*  TebSelf;
  void*  ThreadLocalStoragePointer;  /* Tls* API 會掛在這 */
  DWORD  LastErrorValue;             /* SetLastError/GetLastError */
  DWORD  UniqueThreadId;             /* 簡化：syscall(gettid) */
  void*  Reserved[32];
} AWA_TEB_MIN;

static AWA_TEB_MIN* g_teb = NULL;

static int _is_log(void){
  static int cached = -1;
  if (cached < 0){
    const char* s = getenv("AWAOS_LOG");
    cached = (s && *s) ? 1 : 0;
  }
  return cached;
}
#define LOGF(...) do{ if(_is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* 供其他模組（例如 tls.c）取用目前 TEB 基底 */
AWA_EXPORT void* _nt_teb_base(void) {
  return g_teb;
}

/* 把 selector 寫進 %fs（RPL=3） */
static void set_fs_selector(unsigned short sel){
  asm volatile ("mov %0, %%fs" :: "r"(sel));
}

/* 建立 TLS desc 並掛到 %fs */
AWA_EXPORT void _nt_teb_setup_for_current(void) {
  if (g_teb) return; /* 已設定就略過 */

  void* base = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    perror("mmap TEB");
    _exit(127);
  }

  memset(base, 0, PAGE_SIZE);
  g_teb = (AWA_TEB_MIN*)base;
  g_teb->TebSelf = g_teb;
  g_teb->ThreadLocalStoragePointer = g_teb; /* 最小：TLS 直接用同一塊 */
  g_teb->LastErrorValue = 0;
  g_teb->UniqueThreadId = (DWORD)syscall(SYS_gettid);

  struct user_desc ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number    = -1;       /* 讓 kernel 配一個 */
  ud.base_addr       = (unsigned int)(uintptr_t)base;
  ud.limit           = 0xFFFFF;
  ud.seg_32bit       = 1;
  ud.contents        = 0;        /* data, R/W */
  ud.read_exec_only  = 0;
  ud.limit_in_pages  = 1;
  ud.useable         = 1;

  int rc = syscall(SYS_set_thread_area, &ud);
  if (rc != 0) {
    perror("set_thread_area");
    _exit(127);
  }

  unsigned short sel = (unsigned short)((ud.entry_number << 3) | 0x3); /* RPL=3 */
  set_fs_selector(sel);

  LOGF("TEB set: fs selector=0x%x base=%p", sel, base);
}