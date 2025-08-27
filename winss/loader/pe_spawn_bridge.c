// winss/loader/pe_spawn_bridge.c
#include <stdint.h>
#include "../include/win/minwin.h"

// 假設 loader 內部已有 run_pe32(...)；使用 weak 避免硬依賴
extern int run_pe32(const char* path, const char* cmdline, unsigned* out_code)
  __attribute__((weak));

__attribute__((visibility("default")))
BOOL pe32_spawn(const char* app, const char* cmdline, DWORD* exit_code){
  if(!run_pe32) return FALSE;  // 找不到內部實作就回報失敗
  unsigned code = 0;
  int ok = run_pe32(app, cmdline, &code);
  if(exit_code) *exit_code = (DWORD)code;
  return ok ? TRUE : FALSE;
}