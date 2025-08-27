// winss/ntshim32/ntshim32.c
// Minimal Win32 kernel32 shims used by the PE32 loader (i386)
// Provides: CloseHandle, WaitForSingleObject, GetExitCodeProcess,
//           ReadFile, WriteFile, ExitProcess, GetStartupInfoA,
//           CreateProcessA, GetCommandLineA (+ setter via ntshim_api.h)
//
// Notes:
// - This is a pragmatic shim for CI: process handles are backed by a small
//   struct recording child pid/exit code. STD handles map to POSIX fds.
// - Timeouts in WaitForSingleObject are approximated (polling when finite).

#include "../include/win/minwin.h"
#include "../ntshim32/ntshim_api.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>   // getenv, malloc, free
#include <string.h>   // memset, strlen, strcpy, strcat
#include <unistd.h>   // read, write, _exit, fork, execv
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h> // waitpid
#include <signal.h>
#include <time.h>     // nanosleep
#include <stdio.h>    // debug (optional)

// ----------------------------- logging ---------------------------------
static int is_log(void){
  static int inited=0, val=0;
  if(!inited){ inited=1; val = (getenv("AWAOS_LOG")!=NULL); }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

// -------------------------- helpers / types ----------------------------

// Map Win32 special std handles (-10,-11,-12) to fds 0/1/2
static int map_std_handle(HANDLE h){
  intptr_t v = (intptr_t)h;
  if (v == (intptr_t)STD_INPUT_HANDLE)  return 0;
  if (v == (intptr_t)STD_OUTPUT_HANDLE) return 1;
  if (v == (intptr_t)STD_ERROR_HANDLE)  return 2;
  return -1;
}

// Minimal process-handle backing store
typedef struct AWA_PROC {
  pid_t  pid;
  int    exited;       // 0/1
  DWORD  exit_code;    // Windows-style exit code
} AWA_PROC;

static int is_proc_handle(HANDLE h){
  int fd = map_std_handle(h);
  return (fd<0 && h!=NULL);
}

static AWA_PROC* to_proc(HANDLE h){
  return (AWA_PROC*)h;
}

// Loader path: env override or default install path
static const char* loader_path(void){
  const char* p = getenv("AWAOS_PE_LOADER");
  return (p && *p) ? p : "/usr/lib/awaos/pe_loader32";
}

// ---------------------- basic kernel32 I/O shims -----------------------

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD want, LPDWORD got, LPVOID ovlp){
  (void)ovlp;
  int fd = map_std_handle(h);
  if (fd < 0) { errno=EBADF; if(got) *got=0; return FALSE; }
  ssize_t n = read(fd, buf, want);
  if (n < 0){ if(got) *got=0; return FALSE; }
  if (got) *got = (DWORD)n;
  LOGF("ReadFile fd=%d want=%u got=%ld", fd, (unsigned)want, (long)n);
  return TRUE;
}

BOOL WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD wr, LPVOID ovlp){
  (void)ovlp;
  int fd = map_std_handle(h);
  if (fd < 0) { errno=EBADF; if(wr) *wr=0; return FALSE; }
  ssize_t n = write(fd, buf, len);
  if (n < 0){ if(wr) *wr=0; return FALSE; }
  if (wr) *wr = (DWORD)n;
  LOGF("WriteFile fd=%d want=%u got=%ld", fd, (unsigned)len, (long)n);
  return TRUE;
}

VOID WINAPI ExitProcess(UINT code){
  _exit((int)code);
}

// ------------------------- Startup / CmdLine ---------------------------

static char g_cmdlineA[1024] = {0};

VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if (!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb         = sizeof(*psi);
  psi->dwFlags    = 0;
  psi->wShowWindow= 0;
  psi->hStdInput  = (HANDLE)(intptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(intptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(intptr_t)STD_ERROR_HANDLE;
}

LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA[0] ? g_cmdlineA : "";
}

// provided by ntshim_api.h for the loader to set visible command line
void nt_set_command_lineA(const char* path, const char* argv /*nullable*/){
  g_cmdlineA[0] = 0;
  if (path) {
    strncat(g_cmdlineA, path, sizeof(g_cmdlineA)-1);
  }
  if (argv && *argv) {
    size_t have = strlen(g_cmdlineA);
    if (have+1 < sizeof(g_cmdlineA)) {
      g_cmdlineA[have++] = ' ';
      g_cmdlineA[have] = 0;
    }
    strncat(g_cmdlineA, argv, sizeof(g_cmdlineA)-1);
  }
  LOGF("Set cmdlineA: %s", g_cmdlineA);
}

// ----------------------- Process / wait shims -------------------------

// STILL_ACTIVE is 259 in Win32
#ifndef STILL_ACTIVE
#define STILL_ACTIVE 259
#endif

// Simple spawn using current loader; fills PROCESS_INFORMATION
// Behavior: fork+execv(loader, ["pe_loader32", app, NULL or cmdline])
static int spawn_with_loader(LPCSTR app, LPCSTR cmdline, LPPROCESS_INFORMATION pi){
  const char* loader = loader_path();

  // Build argv for execv
  // We pass at most: ["pe_loader32", app, cmdline?]
  const char* argvv[4];
  int argc = 0;
  argvv[argc++] = "pe_loader32";
  argvv[argc++] = app ? app : "";
  if (cmdline && *cmdline) argvv[argc++] = cmdline;
  argvv[argc] = NULL;

  pid_t pid = fork();
  if (pid < 0) {
    return 0;
  }
  if (pid == 0) {
    execv(loader, (char* const*)argvv);
    _exit(127);
  }

  // parent: wrap pid into a handle
  AWA_PROC* ph = (AWA_PROC*)malloc(sizeof(AWA_PROC));
  if (!ph) return 0;
  ph->pid = pid;
  ph->exited = 0;
  ph->exit_code = STILL_ACTIVE;

  if (pi){
    memset(pi, 0, sizeof(*pi));
    pi->hProcess    = (HANDLE)ph;
    pi->dwProcessId = (DWORD)pid;
    // We don't model primary thread separately in this shim
    pi->hThread     = NULL;
    pi->dwThreadId  = 0;
  }
  LOGF("spawn pid=%d app=%s cmd='%s'", (int)pid, app?app:"(null)", cmdline?cmdline:"");
  return 1;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  if (!is_proc_handle(h)) { errno=EBADF; return FALSE; }
  AWA_PROC* ph = to_proc(h);
  if (!ph->exited){
    int st = 0;
    pid_t r = waitpid(ph->pid, &st, WNOHANG);
    if (r == ph->pid){
      ph->exited = 1;
      if (WIFEXITED(st)) ph->exit_code = (DWORD)WEXITSTATUS(st);
      else if (WIFSIGNALED(st)) ph->exit_code = (DWORD)(128 + WTERMSIG(st));
      else ph->exit_code = 0;
    }
  }
  if (code) *code = ph->exit_code;
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  if (!is_proc_handle(h)) { errno=EBADF; return 0xFFFFFFFFu; /* WAIT_FAILED */ }
  AWA_PROC* ph = to_proc(h);
  const int infinite = (ms==0xFFFFFFFFu);

  if (ph->exited) return 0; // WAIT_OBJECT_0

  if (infinite){
    int st=0;
    pid_t r;
    do { r = waitpid(ph->pid, &st, 0); } while (r<0 && errno==EINTR);
    ph->exited = 1;
    if (WIFEXITED(st)) ph->exit_code = (DWORD)WEXITSTATUS(st);
    else if (WIFSIGNALED(st)) ph->exit_code = (DWORD)(128 + WTERMSIG(st));
    else ph->exit_code = 0;
    return 0; // WAIT_OBJECT_0
  }

  // crude polling for finite timeout
  const long step_ms = 10;
  struct timespec ts = { .tv_sec=0, .tv_nsec=step_ms*1000000L };
  DWORD waited=0;
  while (waited < ms){
    int st=0;
    pid_t r = waitpid(ph->pid, &st, WNOHANG);
    if (r == ph->pid){
      ph->exited = 1;
      if (WIFEXITED(st)) ph->exit_code = (DWORD)WEXITSTATUS(st);
      else if (WIFSIGNALED(st)) ph->exit_code = (DWORD)(128 + WTERMSIG(st));
      else ph->exit_code = 0;
      return 0; // WAIT_OBJECT_0
    }
    nanosleep(&ts, NULL);
    waited += step_ms;
  }
  return 0x00000102u; // WAIT_TIMEOUT
}

BOOL WINAPI CloseHandle(HANDLE h){
  int fd = map_std_handle(h);
  if (fd >= 0) return TRUE; // std handles: nothing to do
  if (!h) return FALSE;
  if (is_proc_handle(h)){
    free(h);
    return TRUE;
  }
  // unknown
  return FALSE;
}

// ---------------------- Process creation (ANSI) -----------------------

BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline,
  LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
  BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
  LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
  (void)psa; (void)tsa; (void)inherit; (void)flags; (void)env; (void)cwd; (void)si;

  // If caller passed NULL app but a command line, try to split first token.
  const char* exe = app;
  char  tmpbuf[1024];
  if (!exe && cmdline){
    // extract first token as exe (very minimal, no quotes handling for now)
    size_t n = 0;
    while (cmdline[n] && cmdline[n]!=' ' && cmdline[n]!='\t' && n+1<sizeof(tmpbuf)) { tmpbuf[n]=cmdline[n]; n++; }
    tmpbuf[n]=0;
    if (n>0) exe = tmpbuf;
  }
  if (!exe || !*exe){
    LOGF("CreateProcessA: no app path");
    SetLastError(2); // ERROR_FILE_NOT_FOUND
    return FALSE;
  }

  if (!spawn_with_loader(exe, cmdline, pi)){
    SetLastError(193); // ERROR_BAD_EXE_FORMAT as a generic failure
    return FALSE;
  }
  return TRUE;
}