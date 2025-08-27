/* Minimal kernel32 shims used by loader/tests on Linux */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../include/win/minwin.h"
#include "../ntshim32/ntshim_api.h"  /* nt_set_command_lineA, nt_teb_setup_for_current (由 loader 呼叫) */

/* ---- log ---- */
static int is_log(void){
  static int inited=0, val=0;
  if(!inited){ inited=1; val = (getenv("AWAOS_LOG")!=NULL); }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- cmdline 管理 ------------------------------------------------------ */
static char g_cmdlineA[1024];
void nt_set_command_lineA(const char* path, const char* argv /*可為 NULL*/){
  size_t n=0; g_cmdlineA[0]=0;
  if(path){ n = strlen(path); if(n>sizeof(g_cmdlineA)-2) n=sizeof(g_cmdlineA)-2; memcpy(g_cmdlineA, path, n); g_cmdlineA[n]=0; }
  if(argv && *argv){
    size_t m = strlen(argv);
    if(n+1+m >= sizeof(g_cmdlineA)) m = sizeof(g_cmdlineA)-1-n-1;
    g_cmdlineA[n++]=' ';
    memcpy(g_cmdlineA+n, argv, m); g_cmdlineA[n+m]=0;
  }
}
LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA[0] ? g_cmdlineA : "";
}

/* ---- I/O ---------------------------------------------------------------- */
static int map_handle(HANDLE h){
  intptr_t v = (intptr_t)h;
  if(v==(intptr_t)STD_INPUT_HANDLE)  return 0;
  if(v==(intptr_t)STD_OUTPUT_HANDLE) return 1;
  if(v==(intptr_t)STD_ERROR_HANDLE)  return 2;
  return -1; /* 簡化：目前只支援三個標準 handle */
}
HANDLE WINAPI GetStdHandle(DWORD nStdHandle){
  return (HANDLE)(uintptr_t)nStdHandle;
}
BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD len, LPDWORD rd, LPVOID ovlp){
  (void)ovlp;
  int fd = map_handle(h); if(fd<0){ if(rd) *rd=0; return FALSE; }
  ssize_t r = read(fd, buf, len);
  if(r<0){ if(rd) *rd=0; return FALSE; }
  if(rd) *rd=(DWORD)r;
  LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x", fd, len, r, (r>0? (unsigned)((unsigned char*)buf)[0]:0));
  return TRUE;
}
BOOL WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD wr, LPVOID ovlp){
  (void)ovlp;
  int fd = map_handle(h); if(fd<0){ if(wr) *wr=0; return FALSE; }
  ssize_t n = write(fd, buf, len);
  if(n<0){ if(wr) *wr=0; return FALSE; }
  if(wr) *wr=(DWORD)n;
  LOGF("WriteFile fd=%d want=%u got=%zd", fd, len, n);
  return TRUE;
}

/* ---- Process 啟動（以 pe_loader32 當中介） ----------------------------- */
static const char* loader_path(void){
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

/* 簡化：只回傳 pid 當作 HANDLE（轉成非零指標） */
static HANDLE pid_to_handle(pid_t pid){ return (HANDLE)(uintptr_t)(pid ? pid : 1); }
static pid_t  handle_to_pid(HANDLE h){ return (pid_t)(uintptr_t)h; }

/* Wait/GetExitCode 簡易快取（足夠支援我們的 CI 測試） */
static pid_t  g_last_pid  = 0;
static int    g_last_have = 0;
static DWORD  g_last_code = STILL_ACTIVE;

static int spawn_with_loader(LPCSTR app, LPCSTR cmdline, LPPROCESS_INFORMATION pi){
  const char* loader = loader_path();

  pid_t pid = fork();
  if(pid < 0) return 0;
  if(pid == 0){
    if(cmdline && *cmdline){
      execl(loader, "pe_loader32", app, cmdline, (char*)NULL);
    }else{
      execl(loader, "pe_loader32", app, (char*)NULL);
    }
    _exit(127);
  }

  pi->hProcess   = pid_to_handle(pid);
  pi->hThread    = NULL;
  pi->dwProcessId= (DWORD)pid;
  pi->dwThreadId = 0;

  LOGF("spawn pid=%d app=%s cmd='%s'", (int)pid, app?app:"(null)", cmdline?cmdline:"");
  return 1;
}

BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline,
  LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
  BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
  LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa;(void)tsa;(void)inherit;(void)flags;(void)env;(void)cwd;(void)si;

  if(!app || !*app){
    SetLastError(2 /*ERROR_FILE_NOT_FOUND*/);
    return FALSE;
  }
  memset(pi, 0, sizeof(*pi));
  if(!spawn_with_loader(app, cmdline, pi)){
    SetLastError(193 /*ERROR_BAD_EXE_FORMAT*/);
    return FALSE;
  }
  return TRUE;
}

/* ---- 其他 KERNEL32 小函式 --------------------------------------------- */
VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
  psi->hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
  psi->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  psi->hStdError  = GetStdHandle(STD_ERROR_HANDLE);
}

VOID WINAPI ExitProcess(UINT code){
  _exit((int)code);
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  (void)ms; /* 目前不支援超時，直接等待 */
  pid_t pid = handle_to_pid(h);
  int status = 0;
  if(pid <= 0) return WAIT_OBJECT_0;

  if(waitpid(pid, &status, 0) < 0){
    /* 已經被等過也算完成 */
    return WAIT_OBJECT_0;
  }
  g_last_pid  = pid;
  g_last_have = 1;
  if(WIFEXITED(status)) g_last_code = (DWORD)WEXITSTATUS(status);
  else                  g_last_code = 1;
  return WAIT_OBJECT_0;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  pid_t pid = handle_to_pid(h);
  if(code) *code = STILL_ACTIVE;
  if(pid <= 0) return FALSE;

  if(g_last_have && g_last_pid == pid){
    if(code) *code = g_last_code;
    return TRUE;
  }

  int status = 0;
  pid_t r = waitpid(pid, &status, WNOHANG);
  if(r == 0){
    if(code) *code = STILL_ACTIVE;
    return TRUE;
  }
  if(r < 0){
    /* 沒 child；視為已完結但無法取碼，回 TRUE/1 */
    if(code) *code = 0;
    return TRUE;
  }
  if(WIFEXITED(status)){
    if(code) *code = (DWORD)WEXITSTATUS(status);
  }else{
    if(code) *code = 1;
  }
  return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE h){
  (void)h;
  /* 我們的 HANDLE 只是 pid/標準描述子的包裝，這裡不需要做事 */
  return TRUE;
}