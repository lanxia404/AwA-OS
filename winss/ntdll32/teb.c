#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/ldt.h>
#include "../include/nt/ntdef.h"

static __thread TEB_MIN* g_teb;
static PEB_MIN g_peb; /* 簡化版，全進程單一個 */

static int set_fs_base(void* base){
  struct user_desc ud = {0};
  ud.entry_number   = -1;
  ud.base_addr      = (unsigned long)base;
  ud.limit          = 0xFFFFF;
  ud.seg_32bit      = 1;
  ud.contents       = 0;
  ud.read_exec_only = 0;
  ud.limit_in_pages = 1;
  ud.useable        = 1;
  if (syscall(SYS_set_thread_area, &ud) < 0) return -1;
  unsigned short sel = (ud.entry_number << 3) | 0x3;
  __asm__ volatile ("mov %0, %%fs" : : "r"(sel));
  return 0;
}

TEB_MIN* NtCurrentTeb(void){
  if (g_teb) return g_teb;
  void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) _exit(127);
  TEB_MIN* teb = (TEB_MIN*)mem;
  memset(teb, 0, 4096);
  teb->NtTib.Self = (void*)&teb->NtTib;
  teb->ClientId_UniqueThread = (DWORD)getpid(); /* 簡化：可改 gettid */
  g_teb = teb;
  if (set_fs_base(teb) < 0) _exit(127);
  return g_teb;
}

PEB_MIN* RtlGetCurrentPeb(void){
  (void)NtCurrentTeb();
  return &g_peb;
}
