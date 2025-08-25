#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <errno.h>
#include "../include/win/minwin.h"


/* 昨数十三個「Windows」概念件找出它們的倭文代碼 -> Linux fd 0/1/2 */
static int map_handle(DWORD h) {
  if (h == (DWORD)-10) return 0;
  if (h == (DWORD)-11) return 1;
  if (h == (DWORD)-12) return 2;
  return -1;
}

/* kernel32.dll 匯出——以名稱指向的方法 */
HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  (void)nStdHandle;
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, DWORD* written, void* ovl) {
  (void)ovl;
  int fd = map_handle((DWORD)(uintptr_t)h);
  if (fd < 0) return FALSE;
  ssize_t n = write(fd, buf, len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  return (n >= 0) ? TRUE : FALSE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

/* 匯入解析表——dll 名 + 稱美名 + 函数指鏈 */
struct Hook { const char* dll; const char* name; void* fn; };


/* 注意大小字——Windows 對匯入名大小字效应能位似不比——PoC 先粗粗小線苝不一致 */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL", "GetStdHandle", (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",    (void*)WriteFile},
  {"KERNEL32.DLL", "ExitProcess",  (void*)ExitProcess},
  {NULL, NULL, NULL}
};
