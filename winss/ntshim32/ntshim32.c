// winss/ntshim32/ntshim32.c
// AwA-OS Win32 personality (kernel32 shim) - 32-bit minimal implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "../include/win/minwin.h"
#include "../ntshim32/ntshim_api.h"

// ----- log -----
static int is_log(void){
  static int inited = 0, val = 0;
  if(!inited){ inited=1; val = (getenv("AWAOS_LOG") && *getenv("AWAOS_LOG")) ? 1 : 0; }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

// ----- std handle map -----
static int map_handle(HANDLE h){
  uintptr_t v = (uintptr_t)h;
  if(v==(uintptr_t)STD_INPUT_HANDLE)  return 0;
  if(v==(uintptr_t)STD_OUTPUT_HANDLE) return 1;
  if(v==(uintptr_t)STD_ERROR_HANDLE)  return 2;
  return -1;
}

HANDLE WINAPI GetStdHandle(DWORD nStdHandle){
  (void)nStdHandle; return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl){
  (void)ovl;
  int fd = map_handle(h);
  if(fd<0){ SetLastError(6); return FALSE; }
  ssize_t n = write(fd, buf, (size_t)len);
  if(n<0){ SetLastError((DWORD)errno); n=0; }
  if(written) *written=(DWORD)n;
  LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, n);
  return (n>=0)?TRUE:FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped){
  (void)overlapped;
  int fd = map_handle(h);
  if(fd<0){ SetLastError(6); return FALSE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if(n<0){ SetLastError((DWORD)errno); n=0; }
  if(out) *out=(DWORD)n;
  LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x", fd, (unsigned)toRead, n, (n>0)?((unsigned char*)buf)[0]:0);
  return (n>=0)?TRUE:FALSE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code){ _exit((int)code); }

// ----- startup info & cmdline -----
static char g_cmdlineA[1024]={0};

VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  memset(psi,0,sizeof(*psi));
  psi->cb = (DWORD)sizeof(*psi);
  psi->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

LPCSTR WINAPI GetCommandLineA(void){ return g_cmdlineA[0]? g_cmdlineA : ""; }

void nt_set_command_lineA(const char* path, const char* argv /*nullable*/){
  if(!path) path="";
  if(argv && *argv){
    size_t lp=strlen(path), la=strlen(argv);
    if(lp+1+la >= sizeof(g_cmdlineA)){ lp=sizeof(g_cmdlineA)-1; la=0; }
    memcpy(g_cmdlineA, path, lp); g_cmdlineA[lp]=' ';
    memcpy(g_cmdlineA+lp+1, argv, la);
    g_cmdlineA[lp+1+la]=0;
  }else{
    strncpy(g_cmdlineA, path, sizeof(g_cmdlineA)-1);
    g_cmdlineA[sizeof(g_cmdlineA)-1]=0;
  }
}

// ----- CreateProcessA -> pe32_spawn bridge -----
BOOL WINAPI CreateProcessA(
  LPCSTR appName, LPSTR commandLine,
  LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
  BOOL inherit, DWORD flags, LPVOID env,
  LPCSTR cwd, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa;(void)tsa;(void)inherit;(void)flags;(void)env;(void)cwd;(void)si;(void)pi;
  const char* path = (appName && *appName) ? appName : commandLine;
  LOGF("CreateProcessA app='%s' cmdline='%s'", path?path:"(null)", commandLine?commandLine:"(null)");
  if(!path || !*path){ SetLastError(2); return FALSE; }
  int ok = pe32_spawn(path, commandLine? commandLine: NULL);
  if(!ok){ SetLastError(193); return FALSE; }
  return TRUE;
}

// ----- hook table -----
struct Hook { const char* dll; const char* name; void* fn; };

__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL","GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL","WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL","ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL","ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL","GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL","GetCommandLineA",     (void*)GetCommandLineA},
  {"KERNEL32.DLL","CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL","WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL","GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL","CloseHandle",         (void*)CloseHandle},

  {"KERNEL32.DLL","CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL","ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL","Sleep",               (void*)Sleep},
  {"KERNEL32.DLL","GetCurrentThreadId",  (void*)GetCurrentThreadId},

  {"KERNEL32.DLL","TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL","TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL","TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL","TlsSetValue",         (void*)TlsSetValue},

  {"KERNEL32.DLL","SetLastError",        (void*)SetLastError},
  {"KERNEL32.DLL","GetLastError",        (void*)GetLastError},
  {NULL,NULL,NULL}
};
