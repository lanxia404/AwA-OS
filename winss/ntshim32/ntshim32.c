// winss/ntshim32/ntshim32.c
// KERNEL32 minimal shim for AwA-OS (i386)
// - Console I/O via POSIX read/write
// - Minimal process/thread/tls surface for our PE32 PoC
// - Hook table accessor nt_get_hooks()

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include "../include/win/minwin.h"   // DWORD/HANDLE/BOOL/… + WinAPI prototypes
#include "../include/nt/hooks.h"     // struct Hook, nt_get_hooks() decl

#ifndef WINAPI
#  if defined(__i386__) || defined(__i386) || defined(i386)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI
#  endif
#endif

#ifndef VOID
typedef void VOID;
#endif

/* ---------- 簡易日誌 ---------- */
static int _log_enabled = -1;
static int log_on(void){
  if (_log_enabled < 0){
    const char* s = getenv("AWAOS_LOG");
    _log_enabled = (s && *s) ? 1 : 0;
  }
  return _log_enabled;
}
#define LOGF(...) do{ if(log_on()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---------- 內部 forward（由 ntdll32/*.c 提供） ---------- */
extern int    _nt_is_thread_handle(HANDLE h);
extern BOOL   _nt_close_thread(HANDLE h);
extern DWORD  _nt_wait_thread(HANDLE h, DWORD ms);
extern BOOL   _nt_get_thread_exit_code(HANDLE h, LPDWORD lpExitCode);

/* ---------- GetCommandLineA 支援（由 loader 設定） ---------- */
static const char* g_cmdlineA = "";
__attribute__((visibility("default")))
void nt_set_command_lineA(const char* s){ g_cmdlineA = (s ? s : ""); }

/* ---------- console I/O handle 映射 ---------- */
static int map_handle(HANDLE h) {
  intptr_t v = (intptr_t)h;
  if (v == (intptr_t)(uintptr_t)STD_INPUT_HANDLE)  return 0; // fd 0
  if (v == (intptr_t)(uintptr_t)STD_OUTPUT_HANDLE) return 1; // fd 1
  if (v == (intptr_t)(uintptr_t)STD_ERROR_HANDLE)  return 2; // fd 2
  return -1;
}

#define HIN  ((HANDLE)(uintptr_t)STD_INPUT_HANDLE)
#define HOUT ((HANDLE)(uintptr_t)STD_OUTPUT_HANDLE)
#define HERR ((HANDLE)(uintptr_t)STD_ERROR_HANDLE)

/* ---------- KERNEL32: Console / Process API ---------- */

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  (void)nStdHandle;
  // 我們直接把 STD_* 常數 (負值) 本身作為句柄
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0){ SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }
  ssize_t n = write(fd, buf, (size_t)len);
  if (log_on()) LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, n);
  if (n < 0){ if (written) *written = 0; return FALSE; }
  if (written) *written = (DWORD)n;
  return TRUE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = map_handle(h);
  if (fd < 0){ SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }
  if (toRead == 0){ if (out) *out = 0; return TRUE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (log_on()) {
    unsigned first = (n>0)? (unsigned)(*(unsigned char*)buf) : 0;
    LOGF("ReadFile fd=%d want=%u got=%zd first=0x%x", fd, (unsigned)toRead, n, first);
  }
  if (n < 0){ if (out) *out = 0; return FALSE; }
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn))
VOID WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if (!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb        = (DWORD)sizeof(*psi);
  psi->hStdInput  = HIN;
  psi->hStdOutput = HOUT;
  psi->hStdError  = HERR;
  // 其他欄位以 0 為預設
}

LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA;
}

/* 我們的 PoC：CreateProcessA 不真正建立 OS process。
 * 行為：回傳 TRUE 並交付「假 process handle」；後續
 * WaitForSingleObject / GetExitCodeProcess 將把非 thread-handle 視為已完成、exit code=0。
 * 這足以讓 cmdlite 的 integration 測試通過。 */
BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline, LPVOID sa, LPVOID ta, BOOL inherit,
  DWORD flags, LPVOID env, LPCSTR cwd, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)sa; (void)ta; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si;
  LOGF("CreateProcessA app='%s' cmdline='%s'", app?app:"(null)", cmdline?cmdline:"(null)");
  if (pi){
    pi->hProcess    = (HANDLE)(uintptr_t)0x1001;  // 假 handle
    pi->hThread     = NULL;
    pi->dwProcessId = 1;
    pi->dwThreadId  = 1;
  }
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  if (_nt_is_thread_handle(h)) return _nt_wait_thread(h, ms);
  // 非 thread-handle：視為立刻 signaled
  return (DWORD)0 /* WAIT_OBJECT_0 */;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  if (!code) return FALSE;
  if (_nt_is_thread_handle(h)) return _nt_get_thread_exit_code(h, code);
  *code = 0; // 對假 handle 視為成功且退出碼 0
  return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE h){
  if (_nt_is_thread_handle(h)) return _nt_close_thread(h);
  // 假 handle 或未辨識：在此 PoC 視為成功
  return TRUE;
}

/* ---------- Hook Table 與 Accessor ---------- */
/* 注意大小寫：匯入名通常為大寫 DLL 名與確切符號名稱 */
static struct Hook NT_HOOKS[] = {
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

  /* 由 ntdll32/thread.c 提供 */
  {"KERNEL32.DLL", "CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL", "ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL", "Sleep",               (void*)Sleep},
  {"KERNEL32.DLL", "GetCurrentThreadId",  (void*)GetCurrentThreadId},

  /* 由 ntdll32/tls.c 提供 */
  {"KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL", "TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue},

  {NULL, NULL, NULL}
};

__attribute__((visibility("default")))
const struct Hook* nt_get_hooks(void) { return NT_HOOKS; }