// winss/ntshim32/ntshim32.c
// 提供最小的 KERNEL32 匯出（stdin/stdout/stderr、CreateProcess 等）
// 並導出 NT_HOOKS 供 loader 綁定。

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"      // struct Hook, NT_HOOKS
#include "ntshim_api.h"               // nt_set_command_lineA (decl)

// ---- 環境變數開關：簡單日誌（可由 loader 先行處理 AWAOS_LOG）----
static int _log_enabled = 0;
static void log_set(int on){ _log_enabled = on; }
#define LOGF(...) do{ if(_log_enabled){ /* 可視需要加上 dprintf(2, ...) */ } }while(0)

// ---- Windows 三個標準句柄 對映到 Linux fd 0/1/2 ----
static int map_handle(HANDLE h) {
  uintptr_t v = (uintptr_t)h;
  if (v == (uintptr_t)STD_INPUT_HANDLE)  return 0;
  if (v == (uintptr_t)STD_OUTPUT_HANDLE) return 1;
  if (v == (uintptr_t)STD_ERROR_HANDLE)  return 2;
  return -1;
}

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  (void)nStdHandle;  // 直接把常數當作句柄回傳
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, DWORD* written, void* ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0) return FALSE;
  ssize_t n = write(fd, buf, (size_t)len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = map_handle(h);
  if (fd < 0) return FALSE;
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

// ---- 命令列（ANSI）支援 ----
static char g_cmdlineA[1024];

__attribute__((visibility("default")))
void nt_set_command_lineA(const char* s){
  if(!s){ g_cmdlineA[0]=0; return; }
  size_t n = strlen(s);
  if(n >= sizeof(g_cmdlineA)) n = sizeof(g_cmdlineA)-1;
  memcpy(g_cmdlineA, s, n);
  g_cmdlineA[n] = 0;
}

LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA;
}

// ---- StartupInfo / ProcessInformation 最小值 ----
VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
  // 其他欄位先留白
}

// 假進程/執行緒句柄：本階段只需讓 WaitForSingleObject/GetExitCodeProcess 可用
static HANDLE const FAKE_PROCESS = (HANDLE)(uintptr_t)0x10001;
static HANDLE const FAKE_THREAD  = (HANDLE)(uintptr_t)0x10002;

BOOL WINAPI CloseHandle(HANDLE h){
  // 目前皆視為可關閉
  (void)h;
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  (void)h; (void)ms;
  // 目前僞同步：目標在 pe32_spawn 內已經同步執行完成
  return WAIT_OBJECT_0;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  (void)h;
  if(code) *code = 0; // 目前 demo 子行程固定回傳 0（run_pe32 已把錯誤轉 FALSE）
  return TRUE;
}

// ---- CreateProcessA：交給 loader 端的 pe32_spawn 來執行 ----
BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline,
  LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
  BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
  LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa; (void)tsa; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si;

  if(!app || !pi){ SetLastError(87 /*ERROR_INVALID_PARAMETER*/); return FALSE; }

  // 由 loader 提供的真正執行函式（弱符號，避免編譯期綁死）
  extern BOOL pe32_spawn(const char* app, const char* cmdline, DWORD* exit_code)
    __attribute__((weak));

  if(!pe32_spawn){
    SetLastError(127 /*ERROR_PROC_NOT_FOUND*/);
    return FALSE;
  }

  DWORD exit_code = 0;
  BOOL ok = pe32_spawn(app, cmdline, &exit_code);

  // 填一組可用的假句柄（目前不做 Job/Handle 表）
  pi->hProcess    = FAKE_PROCESS;
  pi->hThread     = FAKE_THREAD;
  pi->dwProcessId = 1;
  pi->dwThreadId  = 1;

  // 若需要把退出碼保存到哪裡，可在此擴充；目前由 GetExitCodeProcess 回 0
  (void)exit_code;
  return ok;
}

// ---- 匯出表供 loader 綁定 ----
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL", "ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle},
  {"KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA},

  // 下面這些在 ntdll32/thread.c, tls.c 內有實作（KERNEL32 封裝）
  {"KERNEL32.DLL", "CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL", "ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL", "Sleep",               (void*)Sleep},
  {"KERNEL32.DLL", "GetCurrentThreadId",  (void*)GetCurrentThreadId},
  {"KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL", "TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue},

  {NULL, NULL, NULL}
};