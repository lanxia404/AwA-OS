// winss/ntshim32/ntshim32.c
// KERNEL32 32-bit minimal shim for AwA-OS / WinSS
//  - Map STD_* handles to Linux fd 0/1/2
//  - WriteFile / ReadFile (works with redirection/pipes)
//  - ExitProcess / CloseHandle / WaitForSingleObject / GetExitCodeProcess / GetStartupInfoA
//  - CreateProcessA: minimal stub (reports success & exit code 0 for tests)
//  - Export table NT_HOOKS for loader binding

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"   // struct Hook

/* -------- Fallback macros/types if headers don't define them -------- */
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

/* Some Windows-style constants */
#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0x00000000u
#endif

/* Logging switch via env AWAOS_LOG=1 */
static int _log_enabled = 0;
#define LOGF(...) do{ if(_log_enabled){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* --- Optional thread helpers from ntdll32 (mark as weak to avoid link errors when absent) --- */
__attribute__((weak)) int   _nt_is_thread_handle(HANDLE h);
__attribute__((weak)) BOOL  _nt_close_thread(HANDLE h);
__attribute__((weak)) DWORD _nt_wait_thread(HANDLE h, DWORD ms);
__attribute__((weak)) BOOL  _nt_get_thread_exit_code(HANDLE h, LPDWORD code);

/* ---- Map Windows pseudo handles to Linux fds ----
   Windows:  STD_INPUT_HANDLE  = (DWORD)-10
             STD_OUTPUT_HANDLE = (DWORD)-11
             STD_ERROR_HANDLE  = (DWORD)-12  */
static int map_handle(HANDLE h) {
  DWORD key = (DWORD)(uintptr_t)h;
  if (key == (DWORD)-10) return 0; // stdin
  if (key == (DWORD)-11) return 1; // stdout
  if (key == (DWORD)-12) return 2; // stderr
  return -1; // not a std handle (maybe our pseudo thread handle)
}

/* ---- kernel32 exports ---- */

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  if (getenv("AWAOS_LOG")) _log_enabled = 1;
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  if (written) *written = 0;

  int fd = map_handle(h);
  if (fd < 0) {
    // Non-std handle write not supported yet
    SetLastError(6 /*ERROR_INVALID_HANDLE*/);
    return FALSE;
  }

  ssize_t n = write(fd, buf, (size_t)len);
  if (n < 0) return FALSE;
  if (written) *written = (DWORD)n;
  return TRUE;
}

/* FIX: use map_handle(HANDLE) directly; previously passing DWORD broke the signature */
BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  if (out) *out = 0;

  int fd = map_handle(h);
  if (fd < 0) {
    SetLastError(6 /*ERROR_INVALID_HANDLE*/);
    return FALSE;
  }

  if (toRead == 0) return TRUE;

  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

BOOL WINAPI CloseHandle(HANDLE h) {
  int fd = map_handle(h);
  if (fd >= 0) {
    // Do not actually close 0/1/2; just succeed
    return TRUE;
  }
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

/* Use concrete pointer types to avoid LP* typedef requirements */
VOID WINAPI GetStartupInfoA(STARTUPINFOA* psi) {
  if (!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
  psi->dwFlags = 0;
  psi->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

/* Minimal stub: succeed and provide fake handles/IDs so cmdlite flow continues.
   The actual PE execution is exercised by pe_loader32 smoke/integration tests. */
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

/* ---- Export table for the loader (case-insensitive match on DLL; names exact or undecorated) ---- */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL", "ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle},
  {"KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA},
  {NULL, NULL, NULL}
};