#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "../include/win/minwin.h"


/* 映射三個「Windows」概念句柄 -> Linux fd 0/1/2 */
static int map_handle(DWORD h) {
  if (h == (DWORD)-10) return 0;
  if (h == (DWORD)-11) return 1;
  if (h == (DWORD)-12) return 2;
  return -1;
}

/* kernel32.dll 匯出（以名稱掛鉤） */
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

// 追加 ReadFile 的最小實作
BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = (int)(uintptr_t)h;        // 我們用 0/1/2 對應 stdin/stdout/stderr
  if (toRead == 0) { if (out) *out = 0; return TRUE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

/* 匯入解析表——dll 名 + 符號名 + 函數指標 */
struct Hook { const char* dll; const char* name; void* fn; };


/* 注意大小寫——Windows 對匯入名大小寫敏感度低，但PoC優先匹配 */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL", "GetStdHandle", GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",    WriteFile},
  {"KERNEL32.DLL", "ReadFile",     ReadFile},
  {"KERNEL32.DLL", "ExitProcess",  ExitProcess},
  {NULL, NULL, NULL}
};
