// winss/ntshim32/ntshim32.c
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include "../include/win/minwin.h"
#include "../include/nt/ntdef.h"
#include "../ntdll32/teb_tls.h"     // nt_teb_setup_for_current
#include "../ntdll32/thread.h"      // _nt_* helpers

// --- 雜項 --------------------------------------------------------------

static int _log_enabled = 0;
static int is_log(void){
  if(!_log_enabled){
    const char* e = getenv("AWAOS_LOG");
    _log_enabled = (e && *e) ? 1 : 0;
  }
  return _log_enabled;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

// --- Windows 基本型別小工具 -------------------------------------------

static int map_handle(HANDLE h) {
  uintptr_t v = (uintptr_t)h;
  // Windows 常量：STD_INPUT_HANDLE = (DWORD)-10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
  if (v == (uintptr_t)-10) return 0;
  if (v == (uintptr_t)-11) return 1;
  if (v == (uintptr_t)-12) return 2;
  return -1;
}

// --- kernel32 最小實作（I/O，Process，TLS/Thread 綁定） ----------------

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
  (void)nStdHandle;
  return (HANDLE)(uintptr_t)nStdHandle;
}

BOOL WINAPI WriteFile(HANDLE h, const void* buf, DWORD len, LPDWORD written, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0) return FALSE;
  ssize_t n = write(fd, buf, (size_t)len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  return (n >= 0) ? TRUE : FALSE;
}

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID ovl) {
  (void)ovl;
  int fd = map_handle(h);
  if (fd < 0) return FALSE;
  if (toRead == 0) { if (out) *out = 0; return TRUE; }
  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) return FALSE;
  if (out) *out = (DWORD)n;
  return TRUE;
}

__attribute__((noreturn)) VOID WINAPI ExitProcess(UINT code) {
  _exit((int)code);
}

// 命令列暫存（簡化用）
static char g_cmdline[512];
LPCSTR WINAPI GetCommandLineA(void) {
  return g_cmdline[0] ? g_cmdline : "";
}

VOID WINAPI GetStartupInfoA(STARTUPINFOA* psi){
  if(!psi) return;
  memset(psi, 0, sizeof(*psi));
  psi->cb = sizeof(*psi);
  psi->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  psi->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  psi->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

// 宣告由 loader 提供的執行器（在 pe_loader32.c 內定義）
BOOL pe32_spawn(const char* app, const char* cmdline, DWORD* exit_code);

// 最小 CreateProcessA：在同一進程內載入並執行子 exe（同步等待）
BOOL WINAPI CreateProcessA(
  LPCSTR app, LPSTR cmdline, LPVOID p1, LPVOID p2, BOOL inheritHandles,
  DWORD flags, LPVOID env, LPCSTR cwd, STARTUPINFOA* si, PROCESS_INFORMATION* pi)
{
  (void)p1; (void)p2; (void)inheritHandles; (void)flags; (void)env; (void)cwd; (void)si;
  if(!app || !*app){ SetLastError(2 /*ERROR_FILE_NOT_FOUND*/); return FALSE; }

  DWORD code = (DWORD)-1;
  LOGF("CreateProcessA app='%s' cmdline='%s'", app, (cmdline? cmdline:"(null)"));
  // 將 app + cmdline 合併為目前行程的 GetCommandLineA 可見字串（簡化）
  g_cmdline[0] = 0;
  strncat(g_cmdline, app, sizeof(g_cmdline)-1);
  if(cmdline){
    strncat(g_cmdline, " ", sizeof(g_cmdline)-1);
    strncat(g_cmdline, cmdline, sizeof(g_cmdline)-1);
  }

  if(!pe32_spawn(app, cmdline, &code)){
    SetLastError(193 /*ERROR_BAD_EXE_FORMAT*/);
    return FALSE;
  }

  if(pi){
    memset(pi, 0, sizeof(*pi));
    // 我們是「同進程載入」模型，這裡給個假的 thread/process handle（不開放）
    pi->hProcess = (HANDLE)(uintptr_t)1;
    pi->hThread  = (HANDLE)(uintptr_t)1;
    pi->dwProcessId = 1;
    pi->dwThreadId  = 1;
  }
  // 讓 cmdlite 能讀到退出碼
  SetLastError(0);
  return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  if(!_nt_is_thread_handle(h)) return 0 /*WAIT_OBJECT_0*/;
  return _nt_wait_thread(h, ms);
}

BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code){
  if(!_nt_is_thread_handle(h)) { if(code) *code = 0; return TRUE; }
  return _nt_get_thread_exit_code(h, code);
}

BOOL WINAPI CloseHandle(HANDLE h){
  if(_nt_is_thread_handle(h)){ _nt_close_thread(h); return TRUE; }
  return TRUE;
}

// ---- 匯入解析表（KERNEL32 匯出名稱 -> 本檔實作） ----------------------

struct Hook { const char* dll; const char* name; void* fn; };

// 將此表以 default visibility 匯出，供 loader 綁定 IAT 使用
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
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

  // TLS/Thread：讓 TLS demo 能跑起來
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