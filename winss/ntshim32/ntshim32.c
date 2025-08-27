// winss/ntshim32/ntshim32.c
// KERNEL32 32-bit minimal shim for AwA-OS / WinSS
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"   // struct Hook

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

#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0x00000000u
#endif

static int _log_enabled = 0;
#define LOGF(...) do{ if(_log_enabled){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* 有些 thread 幫手由 ntdll32/thread.c 提供（弱符號，缺席也能鏈結） */
__attribute__((weak)) int   _nt_is_thread_handle(HANDLE h);
__attribute__((weak)) BOOL  _nt_close_thread(HANDLE h);
__attribute__((weak)) DWORD _nt_wait_thread(HANDLE h, DWORD ms);
__attribute__((weak)) BOOL  _nt_get_thread_exit_code(HANDLE h, LPDWORD code);

/* TLS / Thread API 來自 ntdll32/（這裡宣告原型供 NT_HOOKS 取址） */
extern DWORD WINAPI TlsAlloc(void);
extern BOOL  WINAPI TlsFree(DWORD idx);
extern LPVOID WINAPI TlsGetValue(DWORD idx);
extern BOOL  WINAPI TlsSetValue(DWORD idx, LPVOID val);

extern HANDLE WINAPI CreateThread(LPVOID sa, SIZE_T stack,
  LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid);
extern VOID   WINAPI ExitThread(DWORD code);
extern VOID   WINAPI Sleep(DWORD ms);
extern DWORD  WINAPI GetCurrentThreadId(void);

/* ---- 命令列儲存區（供 GetCommandLineA） ---- */
static char g_cmdlineA[1024] = {0};

__attribute__((visibility("default")))
void nt_set_command_lineA(const char* s) {
  if (!s) { g_cmdlineA[0] = 0; return; }
  size_t n = strlen(s);
  if (n >= sizeof(g_cmdlineA)) n = sizeof(g_cmdlineA)-1;
  memcpy(g_cmdlineA, s, n);
  g_cmdlineA[n] = 0;
}

/* ---- 句柄映射 ---- */
static int map_handle(HANDLE h) {
  DWORD key = (DWORD)(uintptr_t)h;
  if (key == (DWORD)-10) return 0; // STD_INPUT_HANDLE
  if (key == (DWORD)-11) return 1; // STD_OUTPUT_HANDLE
  if (key == (DWORD)-12) return 2; // STD_ERROR_HANDLE
  return -1;
}

/* ---- KERNEL32 exports：I/O ---- */
HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  if (getenv("AWAOS_LOG")) _log_enabled = 1;
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  if (!_log_enabled && getenv("AWAOS_LOG")) _log_enabled = 1;
  if (written) *written = 0;

  int fd = map_handle(h);
  if (fd < 0) { SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }

  ssize_t n = write(fd, buf, (size_t)len);
  if (_log_enabled) LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, n);
  if (n < 0) return FALSE;
  if (written) *written = (DWORD)n;
  return TRUE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  if (!_log_enabled && getenv("AWAOS_LOG")) _log_enabled = 1;
  if (out) *out = 0;

  int fd = map_handle(h);
  if (fd < 0) { SetLastError(6 /*ERROR_INVALID_HANDLE*/); return FALSE; }
  if (toRead == 0) return TRUE;

  ssize_t n = read(fd, buf, (size_t)toRead);
  if (_log_enabled) {
    int c = (n>0)? ((unsigned char*)buf)[0] : -1;
    LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x", fd, (unsigned)toRead, n, (unsigned)(c&0xff));
  }
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

/* ---- KERNEL32 exports：handles/wait/exitcode ---- */
BOOL WINAPI CloseHandle(HANDLE h) {
  int fd = map_handle(h);
  if (fd >= 0) return TRUE;
  if (_nt_is_thread_handle && _nt_is_thread_handle(h)) {
    if (_nt_close_thread) return _nt_close_thread(h);
    return TRUE;
  }
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms) {
  if (_nt_is_thread_handle && _nt_is_thread_handle(h)) {
    if (_nt_wait_thread) return _nt_wait_thread(h, ms);
    return WAIT_OBJECT_0;
  }
  (void)ms;
  return WAIT_OBJECT_0;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code) {
  if (!code) return FALSE;
  *code = 0;
  if (_nt_is_thread_handle && _nt_is_thread_handle(h)) {
    if (_nt_get_thread_exit_code) return _nt_get_thread_exit_code(h, code);
    *code = 0;
    return TRUE;
  }
  *code = 0;
  return TRUE;
}

VOID WINAPI GetStartupInfoA(STARTUPINFOA* psi) {
  if (!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
  psi->dwFlags = 0;
  psi->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

/* 與現行 minwin.h 宣告一致（LPCSTR） */
LPCSTR WINAPI GetCommandLineA(void) { return g_cmdlineA; }

/* 測試用 stub：回傳成功（不真正啟動子行程） */
BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline,
  LPVOID psa, LPVOID tsa, BOOL inherit, DWORD flags,
  LPVOID env, LPCSTR cwd, STARTUPINFOA* si, PROCESS_INFORMATION* pi)
{
  (void)psa; (void)tsa; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si;
  if (getenv("AWAOS_LOG")) _log_enabled = 1;
  if (!pi) { SetLastError(87 /*ERROR_INVALID_PARAMETER*/); return FALSE; }
  LOGF("CreateProcessA app='%s' cmdline='%s'", app?app:"(null)", cmdline?cmdline:"(null)");
  memset(pi, 0, sizeof(*pi));
  pi->hProcess   = (HANDLE)(uintptr_t)0x1001;
  pi->hThread    = (HANDLE)(uintptr_t)0x1001;
  pi->dwProcessId= 1;
  pi->dwThreadId = 1;
  return TRUE;
}

/* ---- 匯出表：補上 Thread/TLS API ---- */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  /* I/O */
  {"KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL", "ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess},

  /* handles/wait/exit */
  {"KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle},
  {"KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA},
  {"KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA},

  /* threading */
  {"KERNEL32.DLL", "CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL", "ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL", "Sleep",               (void*)Sleep},
  {"KERNEL32.DLL", "GetCurrentThreadId",  (void*)GetCurrentThreadId},

  /* TLS */
  {"KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL", "TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue},

  {NULL, NULL, NULL}
};