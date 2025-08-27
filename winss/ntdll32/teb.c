// winss/ntdll32/teb.c
// 建立最小可用的 TEB/TLS，並把 x86 %fs selector 指到該區塊。
// 參考：set_thread_area(2) 在 i386 以 GDT 方式設定 TLS。
//
// 注意：這裡只提供 Loader / PoC 需要的最小欄位，不等同完整 Windows TEB。

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <asm/ldt.h>        /* struct user_desc, set_thread_area(2) */
#include "../include/win/minwin.h"   /* DWORD 等型別 */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* 最小 TEB 佈局：僅保留我們實作會用到的欄位 */
typedef struct _AWA_TEB_MIN {
  void*  TebSelf;                     /* 自指標，方便除錯 */
  void*  ThreadLocalStoragePointer;   /* 讓 Tls* 可掛到這 */
  DWORD  LastErrorValue;              /* 對應 SetLastError/GetLastError */
  DWORD  UniqueThreadId;              /* 簡化：用 gettid() */
  void*  Reserved[32];                /* 預留 */
} AWA_TEB_MIN;

static AWA_TEB_MIN* g_teb = NULL;

/* 供其他模組（例如 ntdll32/tls.c）取用當前 TEB 基底 */
void* _nt_teb_base(void) {
  return g_teb;
}

static int _is_log(void){
  static int cached = -1;
  if (cached < 0){
    const char* s = getenv("AWAOS_LOG");
    cached = (s && *s) ? 1 : 0;
  }
  return cached;
}
#define LOGF(...) do{ if(_is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* 將 %fs selector 設為指定的 GDT entry（RPL=3） */
static void set_fs_selector(unsigned short sel){
  /* sel 已包含 index<<3 | RPL(3) */
  asm volatile ("mov %0, %%fs" :: "r"(sel));
}

/* 將 base 地址寫入 TLS descriptor（GDT）並裝到 %fs */
void _nt_teb_setup_for_current(void) {
  if (g_teb) return; /* 重入保護 */

  /* 配一頁做 TEB/TLS 區塊 */
  void* base = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    perror("mmap TEB");
    _exit(127);
  }

  memset(base, 0, PAGE_SIZE);
  g_teb = (AWA_TEB_MIN*)base;
  g_teb->TebSelf = g_teb;
  g_teb->ThreadLocalStoragePointer = g_teb; /* 最小化：TLS API 都掛在這 */
  g_teb->LastErrorValue = 0;
  /* gettid() 在較新 glibc 可能要用 syscall(SYS_gettid)；為避免相依，直接 syscall */
  g_teb->UniqueThreadId = (DWORD)syscall(SYS_gettid);

  struct user_desc ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number    = -1;               /* 讓 kernel 指派 */
  ud.base_addr       = (unsigned int)(uintptr_t)base;
  ud.limit           = 0xFFFFF;
  ud.seg_32bit       = 1;
  ud.contents        = 0;                /* 0 = Data, Read/Write */
  ud.read_exec_only  = 0;                /* 非唯讀 */
  ud.limit_in_pages  = 1;                /* 以頁為單位 */
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