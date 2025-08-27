#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/win/minwin.h"
#include "../ntshim32/ntshim_api.h"

/* --- 環境變數控管日誌 --- */
static int _log_enabled = -1;
static int is_log(void){
  if(_log_enabled < 0){
    const char* v = getenv("AWAOS_LOG");
    _log_enabled = (v && *v) ? 1 : 0;
  }
  return _log_enabled;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* --- 命令列暫存（GetCommandLineA 會回傳它） --- */
static char g_cmdlineA[1024] = {0};

void nt_set_command_lineA(const char* path, const char* argv){
  /* 產生："path" + [空白 + argv] */
  char* p = g_cmdlineA;
  size_t cap = sizeof(g_cmdlineA);
  size_t n = 0;

  g_cmdlineA[0] = 0;
  if(path && *path){
    if(n + 1 < cap) g_cmdlineA[n++] = '"';
    while(*path && n + 1 < cap) g_cmdlineA[n++] = *path++;
    if(n + 1 < cap) g_cmdlineA[n++] = '"';
    g_cmdlineA[n] = 0;
  }
  if(argv && *argv){
    if(n + 1 < cap) g_cmdlineA[n++] = ' ';
    while(*argv && n + 1 < cap) g_cmdlineA[n++] = *argv++;
    g_cmdlineA[n] = 0;
  }
}

/* --- 最小 Win32 -> Linux FD 對應（僅 STD*） --- */
static int map_handle(HANDLE h){
  DWORD v = (DWORD)(uintptr_t)h;
  if(v == (DWORD)-10) return 0;  /* stdin  */
  if(v == (DWORD)-11) return 1;  /* stdout */
  if(v == (DWORD)-12) return 2;  /* stderr */
  return -1; /* 其他交給執行緒/行程假句柄處理或直接忽略 */
}

/* ---- KERNEL32.DLL 模擬 ---- */

HANDLE WINAPI GetStdHandle(DWORD nStdHandle){
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, DWORD* written, LPVOID ovl){
  (void)ovl;
  int fd = map_handle(h);
  if(fd < 0) return FALSE;
  ssize_t n = write(fd, buf, len);
  if(written) *written = (DWORD)((n < 0) ? 0 : n);
  LOGF("WriteFile fd=%d want=%u got=%zd", fd, (unsigned)len, (ssize_t)n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped){
  (void)overlapped;
  int fd = map_handle(h);
  if(fd < 0){ if(out) *out = 0; return FALSE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if(out) *out = (DWORD)((n < 0) ? 0 : n);
  LOGF("ReadFile fd=%d want=%u got=%zd first=0x%02x",
       fd, (unsigned)toRead, (ssize_t)n,
       (n > 0 ? (unsigned)(unsigned char)((const unsigned char*)buf)[0] : 0));
  return (n >= 0) ? TRUE : FALSE;
}

__attribute__((noreturn)) VOID WINAPI ExitProcess(UINT code){
  _exit((int)code);
}

/* GetStartupInfoA：最小填充（交互用不到實際控制台繫結） */
VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA psi){
  if(!psi) return;
  STARTUPINFOA si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
  *psi = si;
}

/* 假行程模型：
 *  - CreateProcessA 直接呼叫 pe32_spawn()「同步」執行
 *  - WaitForSingleObject 立即返回已訊號
 *  - GetExitCodeProcess 回傳我們記錄的上次退出碼
 *  注意：這是 PoC，之後會改成真正的子執行緒/子程序模型。 */
static DWORD g_last_exit = 0;
static HANDLE g_proc_handle = (HANDLE)(uintptr_t)0x1111;

BOOL WINAPI CreateProcessA(
  LPCSTR appName, LPSTR cmdLine,
  LPSECURITY_ATTRIBUTES procAttr, LPSECURITY_ATTRIBUTES threadAttr,
  BOOL inheritHandles, DWORD flags, LPVOID env, LPCSTR cwd,
  LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi
){
  (void)procAttr; (void)threadAttr; (void)inheritHandles;
  (void)flags; (void)env; (void)cwd; (void)si;

  if(!appName || !*appName){
    LOGF("CreateProcessA: appName NULL"); return FALSE;
  }

  /* 將命令列也寫進 GetCommandLineA */
  nt_set_command_lineA(appName,
    (cmdLine && *cmdLine) ? cmdLine : NULL);

  LOGF("CreateProcessA app='%s' cmdline='%s'",
       appName, (cmdLine ? cmdLine : "(null)"));

  int rc = pe32_spawn(appName, (cmdLine ? cmdLine : NULL));
  g_last_exit = (DWORD)((rc < 0) ? (DWORD)rc : (DWORD)rc);

  if(pi){
    pi->hProcess = g_proc_handle;
    pi->hThread  = (HANDLE)(uintptr_t)0x2222;
    pi->dwProcessId = 1;
    pi->dwThreadId  = 1;
  }
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  (void)h; (void)ms;
  return WAIT_OBJECT_0;
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  (void)h;
  if(code) *code = g_last_exit;
  return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE h){
  (void)h;
  return TRUE;
}

/* GetCommandLineA 回傳我們的緩衝 */
LPCSTR WINAPI GetCommandLineA(void){
  return g_cmdlineA[0] ? g_cmdlineA : "";
}

/* ---- 其他 API 的匯出實際在 ntdll32/*.c，各自已定義 ---- */
/* SetLastError / GetLastError / TLS / Thread 等由 error.c / tls.c / thread.c 提供 */