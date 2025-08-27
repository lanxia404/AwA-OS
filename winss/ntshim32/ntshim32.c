// winss/ntshim32/ntshim32.c
// AwA-OS Win32 personality (kernel32 shim) - 32-bit minimal implementation
// 提供：基礎 I/O、退出、GetStartupInfoA / GetCommandLineA、CreateProcessA 橋接、
// 以及對 Loader 綁定用的匯出 Hook 表 NT_HOOKS。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "../include/win/minwin.h"     // 基本 Win32 型別/宣告（HANDLE/DWORD/BOOL/...）
#include "../ntshim32/ntshim_api.h"    // nt_set_command_lineA / nt_set_spawn_impl / pe32_spawn

// ---------------------------------------------------------------------
// 簡易日誌
static int is_log(void){
  static int inited = 0;
  static int val = 0;
  if(!inited){
    inited = 1;
    const char* v = getenv("AWAOS_LOG");
    val = (v && *v) ? 1 : 0;
  }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n', stderr);} }while(0)

// ---------------------------------------------------------------------
// Windows 概念句柄 → Linux fd 映射（僅處理 STD_*）
static int map_handle(HANDLE h) {
  uintptr_t v = (uintptr_t)h;
  if (v == (uintptr_t)STD_INPUT_HANDLE)  return 0;
  if (v == (uintptr_t)STD_OUTPUT_HANDLE) return 1;
  if (v == (uintptr_t)STD_ERROR_HANDLE)  return 2;
  return -1;
}

// ---------------------------------------------------------------------
// KERNEL32: 基礎 APIs（最小實作）

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  (void)nStdHandle;
  return (HANDLE)(uintptr_t)nStdHandle;  // 回傳 pseudo-handle
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0) { SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }
  ssize_t n = write(fd, buf, (size_t)len);
  if (n < 0) { SetLastError((DWORD)errno); n = 0; }
  if (written) *written = (DWORD)n;
  LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = map_handle(h);
  if (fd < 0) { SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) { SetLastError((DWORD)errno); n = 0; }
  if (out) *out = (DWORD)n;
  LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x",
       fd, (unsigned)toRead, n, (n>0)?((unsigned char*)buf)[0]:0);
  return (n >= 0) ? TRUE : FALSE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

// ---------------------------------------------------------------------
// GetStartupInfoA / GetCommandLineA

static char g_cmdlineA[1024] = {0};

VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = (DWORD)sizeof(*psi);
  // 這裡不強制 STARTF_USESTDHANDLES，只提供預設 pseudo handles
  psi->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA[0] ? g_cmdlineA : "";
}

// Loader 會呼叫此函式設定目前行程的「命令列字串」（Windows 風格：單一字串）
void nt_set_command_lineA(const char* path, const char* argv /*可為NULL*/){
  if(!path) path = "";
  if(argv && *argv){
    size_t lp = strlen(path), la = strlen(argv);
    if (lp + 1 + la >= sizeof(g_cmdlineA)) {
      // truncate
      lp = (sizeof(g_cmdlineA) - 1);
      la = 0;
    }
    memcpy(g_cmdlineA, path, lp);
    g_cmdlineA[lp] = ' ';
    memcpy(g_cmdlineA + lp + 1, argv, la);
    g_cmdlineA[lp + 1 + la] = 0;
  }else{
    strncpy(g_cmdlineA, path, sizeof(g_cmdlineA)-1);
    g_cmdlineA[sizeof(g_cmdlineA)-1] = 0;
  }
}

// ---------------------------------------------------------------------
// CreateProcessA: 最小橋接到 pe32_spawn（由 Loader 註冊實作）
//
// 注意：目前不回填 PROCESS_INFORMATION，後續可擴充為 PID/Thread 句柄模型。
BOOL WINAPI CreateProcessA(
  LPCSTR appName, LPSTR commandLine,
  LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
  BOOL inherit, DWORD flags, LPVOID env,
  LPCSTR cwd, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa; (void)tsa; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si; (void)pi;

  const char* path = appName;
  if (!path || !*path) path = commandLine;
  LOGF("CreateProcessA app='%s' cmdline='%s'", path?path:"(null)", commandLine?commandLine:"(null)");

  if (!path || !*path) { SetLastError(2 /*ERROR_FILE_NOT_FOUND*/); return FALSE; }

  int ok = pe32_spawn(path, commandLine ? commandLine : NULL);
  if (!ok) { SetLastError(193 /*ERROR_BAD_EXE_FORMAT 或一般錯誤*/); return FALSE; }
  return TRUE;
}

// ---------------------------------------------------------------------
// 其餘 KERNEL32 API（由 ntdll32/*.c 提供），在這裡不重複實作，但要能在 Hook 表裡引用。
// 這些原型在 minwin.h 已宣告，這裡直接使用標識符即可。

// extern 宣告可省略（minwin.h 已有），保留註解示意：
// DWORD   WINAPI TlsAlloc(void);
// BOOL    WINAPI TlsFree(DWORD);
// LPVOID  WINAPI TlsGetValue(DWORD);
// BOOL    WINAPI TlsSetValue(DWORD, LPVOID);
// HANDLE  WINAPI CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
// VOID    WINAPI ExitThread(DWORD);
// VOID    WINAPI Sleep(DWORD);
// DWORD   WINAPI GetCurrentThreadId(void);
// DWORD   WINAPI WaitForSingleObject(HANDLE, DWORD);
// BOOL    WINAPI GetExitCodeProcess(HANDLE, LPDWORD);
// BOOL    WINAPI CloseHandle(HANDLE);
// VOID    WINAPI SetLastError(DWORD);
// DWORD   WINAPI GetLastError(void);

// ---------------------------------------------------------------------
// 匯出給 Loader 綁定用的 Hook 表
struct Hook { const char* dll; const char* name; void* fn; };

__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  // 基本 I/O / 行程
  {"KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL", "ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA},
  {"KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle},

  // 執行緒 & TLS
  {"KERNEL32.DLL", "CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL", "ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL", "Sleep",               (void*)Sleep},
  {"KERNEL32.DLL", "GetCurrentThreadId",  (void*)GetCurrentThreadId},
  {"KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL", "TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue},

  // 錯誤碼
  {"KERNEL32.DLL", "SetLastError",        (void*)SetLastError},
  {"KERNEL32.DLL", "GetLastError",        (void*)GetLastError},

  {NULL, NULL, NULL}
};