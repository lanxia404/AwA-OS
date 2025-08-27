// winss/ntshim32/ntshim32.c
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include "../include/win/minwin.h"
#include "../include/nt/ntdef.h"
#include "../ntdll32/teb_tls.h"      // NtCurrentTeb, teb helpers
#include "../ntdll32/thread.h"       // thread shim
#include "../ntdll32/error.h"        // SetLastError/GetLastError

static int is_log(void){
  static int inited=0, val=0;
  if(!inited){ inited=1; val = (getenv("AWAOS_LOG")!=NULL); }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- std handles mapping ---- */
static int map_handle(HANDLE h) {
  uintptr_t v = (uintptr_t)h;
  if (v == (uintptr_t)STD_INPUT_HANDLE)  return 0;
  if (v == (uintptr_t)STD_OUTPUT_HANDLE) return 1;
  if (v == (uintptr_t)STD_ERROR_HANDLE)  return 2;
  return -1;
}

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0){ SetLastError(6); return FALSE; } /* ERROR_INVALID_HANDLE */
  ssize_t n = write(fd, buf, len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  if (is_log()) LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = map_handle(h);
  if (fd < 0){ SetLastError(6); return FALSE; }
  if (toRead == 0) { if (out) *out = 0; return TRUE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) { SetLastError(5); return FALSE; } /* ERROR_ACCESS_DENIED-ish */
  if (out) *out = (DWORD)n;
  if (is_log()) LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x", fd, (unsigned)toRead, n,
                     (n>0? ((unsigned char*)buf)[0] : 0));
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

/* ---- Process/Thread minimal ---- */
VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
}

/* 簡化：用 loader 自行啟動子 PE（在 cmdlite 內） */
BOOL WINAPI CreateProcessA(LPCSTR app, LPSTR cmdline, LPVOID psa, LPVOID tsa,
                           BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
                           LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa; (void)tsa; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si;
  if(is_log()) LOGF("CreateProcessA app='%s' cmdline='%s'", app?app:"(null)", cmdline?cmdline:"(null)");
  if(!app || !pi){ SetLastError(87); return FALSE; } /* ERROR_INVALID_PARAMETER */

  /* 我們在 cmdlite 中以同步方式呼叫 loader（同執行緒），因此回報一個假 handle。 */
  static DWORD last_exit = 0;
  DWORD code = nt_spawn_sync_and_wait(app, cmdline); /* 實作於 thread.c / 執行 run_pe32 的簡化管道 */
  last_exit = code;

  memset(pi, 0, sizeof(*pi));
  pi->hProcess = (HANDLE)(uintptr_t)0x3333; /* fake */
  pi->dwProcessId = 1;
  SetLastError(0);
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  (void)h; (void)ms;
  /* 簡化：同步執行，直接已經完成 */
  return 0; /* WAIT_OBJECT_0 */
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD lpExitCode){
  (void)h;
  if(lpExitCode) *lpExitCode = nt_last_child_exit_code();
  return TRUE;
}

/* ---- Command line bridge ---- */
static const char* g_cmdlineA = "";
void nt_set_command_lineA(const char* exe, char* const* argv){
  static char buf[1024];
  size_t n=0;
  n += snprintf(buf+n, sizeof(buf)-n, "%s", exe?exe:"");
  if(argv){
    for(char* const* p=argv; *p && n+1<sizeof(buf); ++p){
      n += snprintf(buf+n, sizeof(buf)-n, " %s", *p);
    }
  }
  g_cmdlineA = buf;
}
LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA;
}

/* ---- Export hook table ---- */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL", "WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL", "ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA},
  {NULL, NULL, NULL}
};