#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../include/win/minwin.h"

/* 三個 STD* Handle 轉 Linux fd 0/1/2 */
static int map_handle(DWORD h) {
  if (h == (DWORD)-10) return 0;
  if (h == (DWORD)-11) return 1;
  if (h == (DWORD)-12) return 2;
  return -1;
}

/* ---- KERNEL32 基礎 I/O ---- */

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  /* 直接把 Windows 常數當作 HANDLE，之後用 map_handle() 轉 fd */
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle((DWORD)(uintptr_t)h);
  if (fd < 0) return FALSE;
  ssize_t n = write(fd, buf, (size_t)len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  int fd = map_handle((DWORD)(uintptr_t)h);
  if (fd < 0) return FALSE;
  if (toRead == 0) { if (out) *out = 0; return TRUE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

/* ---- 內部：字串/轉碼/時間工具 ---- */

static void ms_sleep(unsigned ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/* 簡易 ASCII->UTF16 / UTF16->ASCII（無多國語系，PoC 夠用） */
static size_t a2w(const char* a, WCHAR* w, size_t cap /*以 WCHAR 計*/) {
  size_t i=0;
  for (; a && *a && i+1<cap; ++a,++i) w[i] = (unsigned char)(*a);
  if (w && cap) w[i] = 0;
  return i;
}
static size_t w2a(const WCHAR* w, char* a, size_t cap /*含結尾*/) {
  size_t i=0;
  for (; w && *w && i+1<cap; ++w,++i) a[i] = (char)((*w) & 0xFF);
  if (a && cap) a[i] = 0;
  return i;
}

/* ---- 內部：選擇 loader 路徑 ---- */

static const char* pick_loader(void) {
  if (access("/usr/lib/awaos/pe_loader32", X_OK) == 0) return "/usr/lib/awaos/pe_loader32";
  if (access("/usr/local/lib/awaos/pe_loader32", X_OK) == 0) return "/usr/local/lib/awaos/pe_loader32";
  return NULL;
}

/* ---- CreateProcess/Wait/GetExitCode/CloseHandle ---- */

/* 最簡單的切詞：空白分隔；不處理引號/跳脫。PoC 夠用。 */
static int split_args(char* s, char** outv, int maxv) {
  int n=0;
  while (s && *s && n < maxv-1) {
    while (*s==' ' || *s=='\t') ++s;
    if (!*s) break;
    outv[n++] = s;
    while (*s && *s!=' ' && *s!='\t') ++s;
    if (*s) *s++ = '\0';
  }
  outv[n] = NULL;
  return n;
}

/* 記錄最近 wait 的結果，供 GetExitCodeProcess 使用 */
static pid_t g_last_pid = -1;
static int   g_last_status = 0;

BOOL WINAPI CreateProcessA(
  LPCSTR appName, LPSTR cmdLine,
  LPVOID lpProcAttrs, LPVOID lpThreadAttrs,
  BOOL bInherit, DWORD dwFlags,
  LPVOID lpEnv, LPCSTR lpCurDir,
  STARTUPINFOA* si, PROCESS_INFORMATION* pi
){
  (void)lpProcAttrs; (void)lpThreadAttrs; (void)bInherit;
  (void)dwFlags; (void)lpEnv; (void)si;

  const char* loader = pick_loader();
  if (!loader) return FALSE;
  if (!appName || !*appName) return FALSE;

  char* args_buf = NULL;
  char* argv[64];
  int ai = 0;
  argv[ai++] = (char*)loader;  /* argv[0] = loader */
  argv[ai++] = (char*)appName; /* argv[1] = exe 路徑 */

  if (cmdLine && *cmdLine) {
    size_t L = strlen(cmdLine);
    args_buf = (char*)malloc(L+1);
    if (!args_buf) return FALSE;
    memcpy(args_buf, cmdLine, L+1);
    ai += split_args(args_buf, &argv[ai], (int)(64 - ai));
  }
  argv[ai] = NULL;

  pid_t pid = fork();
  if (pid < 0) { if (args_buf) free(args_buf); return FALSE; }

  if (pid == 0) {
    if (lpCurDir && *lpCurDir) chdir(lpCurDir);
    execv(loader, argv);
    _exit(127);
  }

  if (args_buf) free(args_buf);
  if (pi) {
    pi->hProcess    = (HANDLE)(uintptr_t)pid;
    pi->hThread     = 0;
    pi->dwProcessId = (DWORD)pid;
    pi->dwThreadId  = 0;
  }
  return TRUE;
}

BOOL WINAPI CreateProcessW(
  LPCWSTR appNameW, LPWSTR cmdLineW,
  LPVOID lpProcAttrs, LPVOID lpThreadAttrs,
  BOOL bInherit, DWORD dwFlags,
  LPVOID lpEnv, LPCWSTR lpCurDirW,
  STARTUPINFOW* siW, PROCESS_INFORMATION* pi
){
  char app[512] = {0};
  char* cmd = NULL;
  char curdir[512] = {0};
  if (appNameW) w2a(appNameW, app, sizeof(app));
  if (lpCurDirW) w2a(lpCurDirW, curdir, sizeof(curdir));
  if (cmdLineW) {
    size_t L = 0; while (cmdLineW[L]) ++L;
    cmd = (char*)malloc(L+1);
    if (!cmd) return FALSE;
    w2a(cmdLineW, cmd, L+1);
  }
  BOOL ok = CreateProcessA(appNameW ? app : NULL, cmd,
                           lpProcAttrs, lpThreadAttrs,
                           bInherit, dwFlags, lpEnv,
                           lpCurDirW ? curdir : NULL,
                           (STARTUPINFOA*)siW, pi);
  if (cmd) free(cmd);
  return ok;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms) {
  pid_t pid = (pid_t)(uintptr_t)h;
  int st = 0;

  if (ms == INFINITE) {
    if (waitpid(pid, &st, 0) < 0) return WAIT_FAILED;
    g_last_pid = pid; g_last_status = st;
    return WAIT_OBJECT_0;
  }

  /* 簡易 polling：每 5ms 查詢一次 */
  const unsigned step = 5;
  unsigned waited = 0;
  for (;;) {
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r < 0) return WAIT_FAILED;
    if (r > 0) { g_last_pid = pid; g_last_status = st; return WAIT_OBJECT_0; }
    if (waited >= ms) return WAIT_TIMEOUT;
    ms_sleep(step);
    waited += step;
  }
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD lpExitCode) {
  pid_t pid = (pid_t)(uintptr_t)h;
  int st = 0;

  if (pid == g_last_pid) {
    st = g_last_status;
  } else {
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r == 0) { if (lpExitCode) *lpExitCode = STILL_ACTIVE; return TRUE; }
    if (r < 0) return FALSE;
  }

  if (WIFEXITED(st)) {
    if (lpExitCode) *lpExitCode = (DWORD)WEXITSTATUS(st);
    return TRUE;
  }
  if (WIFSIGNALED(st)) {
    if (lpExitCode) *lpExitCode = (DWORD)(128 + WTERMSIG(st));
    return TRUE;
  }
  if (lpExitCode) *lpExitCode = STILL_ACTIVE;
  return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE h) {
  /* PoC：沒有真實的 kernel object；對於我們的 pid handle 直接返回 TRUE */
  (void)h;
  return TRUE;
}

/* ---- GetCommandLineA/W ----
   PoC：回傳固定的暫存字串；若未由 loader 設定，就回基本字串。
   若你想更精確，可讓 pe_loader32 在跳到入口前呼叫我們的 setter。 */

static char  g_cmdlineA[512] = "AwAProcess";
static WCHAR g_cmdlineW[512] = { 'A','w','A','P','r','o','c','e','s','s',0 };

__attribute__((visibility("default")))
void nt_set_command_lineA(const char* s) {
  if (!s) return;
  size_t L = strlen(s);
  if (L >= sizeof(g_cmdlineA)) L = sizeof(g_cmdlineA)-1;
  memcpy(g_cmdlineA, s, L); g_cmdlineA[L] = 0;
  a2w(g_cmdlineA, g_cmdlineW, sizeof(g_cmdlineW)/sizeof(g_cmdlineW[0]));
}

LPCSTR WINAPI GetCommandLineA(void) { return g_cmdlineA; }
LPCWSTR WINAPI GetCommandLineW(void) { return g_cmdlineW; }

/* ---- 匯入解析表（供 loader 修 IAT 用） ---- */

struct Hook { const char* dll; const char* name; void* fn; };

__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL","GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL","WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL","ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL","ExitProcess",         (void*)ExitProcess},
  {"KERNEL32.DLL","CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL","CreateProcessW",      (void*)CreateProcessW},
  {"KERNEL32.DLL","WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL","GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL","CloseHandle",         (void*)CloseHandle},
  {"KERNEL32.DLL","GetCommandLineA",     (void*)GetCommandLineA},
  {"KERNEL32.DLL","GetCommandLineW",     (void*)GetCommandLineW},
  {NULL, NULL, NULL}
};
