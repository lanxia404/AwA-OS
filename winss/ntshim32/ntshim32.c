#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../include/win/minwin.h"
#include "../include/nt/ntdef.h"
#include "../include/nt/hooks.h"

/* 由 ntdll32/thread.c 提供 */
int   _nt_is_thread_handle(HANDLE h);
int   _nt_wait_thread(HANDLE ms_handle, DWORD ms);
DWORD _nt_get_thread_exit_code(HANDLE h);
BOOL  _nt_close_thread(HANDLE h);

/* ---- 日誌 ---- */
static int _log_enabled = 0;
__attribute__((constructor))
static void _init_log(void){
  const char* e = getenv("AWAOS_LOG");
  _log_enabled = (e && *e && strcmp(e,"0")!=0) ? 1 : 0;
}
#define LOGF(...) do{ if(_log_enabled){ fprintf(stderr,"[ntshim32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- 標準把手映射（允許 SetStdHandle 覆寫） ---- */
static int g_std_fd_in  = 0;
static int g_std_fd_out = 1;
static int g_std_fd_err = 2;

static int map_handle(HANDLE h) {
  uintptr_t v = (uintptr_t)h;
  if (v == (uintptr_t)STD_INPUT_HANDLE)  return g_std_fd_in;
  if (v == (uintptr_t)STD_OUTPUT_HANDLE) return g_std_fd_out;
  if (v == (uintptr_t)STD_ERROR_HANDLE)  return g_std_fd_err;
  if (v <= 2u) return (int)v; /* 容忍直接傳 0/1/2 */
  return -1;
}

/* ---- KERNEL32 I/O ---- */
HANDLE WINAPI GetStdHandle(DWORD nStdHandle){
  switch (nStdHandle) {
    case STD_INPUT_HANDLE:  return (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
    case STD_OUTPUT_HANDLE: return (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
    case STD_ERROR_HANDLE:  return (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
    default: return (HANDLE)(uintptr_t)nStdHandle;
  }
}
BOOL WINAPI SetStdHandle(DWORD nStdHandle, HANDLE h){
  int fd = map_handle(h);
  if (fd < 0) return FALSE;
  switch (nStdHandle) {
    case STD_INPUT_HANDLE:  g_std_fd_in  = fd; break;
    case STD_OUTPUT_HANDLE: g_std_fd_out = fd; break;
    case STD_ERROR_HANDLE:  g_std_fd_err = fd; break;
    default: return FALSE;
  }
  LOGF("SetStdHandle(%ld -> fd=%d)", (long)nStdHandle, fd);
  return TRUE;
}

BOOL WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD written, LPVOID ovl){
  (void)ovl; int fd = map_handle(h); if (fd < 0) return FALSE;
  ssize_t n = write(fd, buf, (size_t)len);
  if (written) *written = (DWORD)((n < 0) ? 0 : n);
  return (n >= 0) ? TRUE : FALSE;
}

// ReadFile 

BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD out, LPVOID overlapped) {
  (void)overlapped;
  if (out) *out = 0;

  // 把 Windows 概念句柄 (-10/-11/-12) 轉換到 Linux fd (0/1/2)
  int fd = map_handle((DWORD)(uintptr_t)h);
  if (fd < 0) {
    // ERROR_INVALID_HANDLE
    SetLastError(6);
    return FALSE;
  }

  if (toRead == 0) {
    return TRUE;
  }

  ssize_t n = read(fd, buf, (size_t)toRead);
  if (n < 0) {
    // 讀取失敗：保留 errno -> 轉成合適的 Win32 錯誤碼的話可再細化
    return FALSE;
  }

  if (out) *out = (DWORD)n;
  return TRUE;
}

/* Console A 版：重導/管線時官方建議使用 WriteFile（參見 MS Docs） */
BOOL WINAPI WriteConsoleA(HANDLE h, const char* buf, DWORD len, LPDWORD written, LPVOID ovl){ return WriteFile(h, buf, len, written, ovl); }
BOOL WINAPI ReadConsoleA (HANDLE h, char*       buf, DWORD len, LPDWORD readout, LPVOID ovl){ return ReadFile (h, buf, len, readout, ovl); }

BOOL WINAPI FlushFileBuffers(HANDLE h){
  int fd = map_handle(h); if (fd < 0) return FALSE;
  if (fd > 2) (void)fsync(fd);
  return TRUE;
}

/* **修正點**：GetFileType 準確辨識 PIPE/TTY/FILE */
DWORD WINAPI GetFileType(HANDLE hFile){
  int fd = map_handle(hFile);
  if (fd < 0) return FILE_TYPE_UNKNOWN;

  struct stat st;
  if (fstat(fd, &st) == 0) {
    if (S_ISFIFO(st.st_mode)) return FILE_TYPE_PIPE;
    if (S_ISCHR (st.st_mode)) return FILE_TYPE_CHAR;
    if (S_ISREG (st.st_mode)) return FILE_TYPE_DISK;
  }
  if (isatty(fd)) return FILE_TYPE_CHAR;
  return FILE_TYPE_DISK;
}
BOOL WINAPI GetConsoleMode(HANDLE h, LPDWORD mode){ if (mode) *mode = 0; return TRUE; }
BOOL WINAPI SetConsoleMode(HANDLE h, DWORD mode){ (void)h; (void)mode; return TRUE; }

__attribute__((noreturn)) void WINAPI ExitProcess(UINT code){ _exit((int)code); }

/* ---- Startup Info ---- */
void WINAPI GetStartupInfoA(STARTUPINFOA* si){
  if (!si) return;
  memset(si, 0, sizeof(*si));
  si->cb = sizeof(*si);
  si->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  si->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  si->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}
void WINAPI GetStartupInfoW(STARTUPINFOW* si){
  if (!si) return;
  memset(si, 0, sizeof(*si));
  si->cb = sizeof(*si);
  si->hStdInput  = (HANDLE)(uintptr_t)STD_INPUT_HANDLE;
  si->hStdOutput = (HANDLE)(uintptr_t)STD_OUTPUT_HANDLE;
  si->hStdError  = (HANDLE)(uintptr_t)STD_ERROR_HANDLE;
}

/* ---- Environment（最小可用實作，回雙 0 結尾） ---- */
static char  g_envA[] = "PATH=\0\0";
static WCHAR g_envW[] = { 'P','A','T','H','=','\0','\0' };
LPSTR  WINAPI GetEnvironmentStringsA(void){ return g_envA; }
LPWSTR WINAPI GetEnvironmentStringsW(void){ return g_envW; }
BOOL   WINAPI FreeEnvironmentStringsA(LPSTR p){ (void)p; return TRUE; }
BOOL   WINAPI FreeEnvironmentStringsW(LPWSTR p){ (void)p; return TRUE; }

/* ---- 命令列 ---- */
static char  g_cmdlineA[512] = "AwAProcess";
static WCHAR g_cmdlineW[512] = { 'A','w','A','P','r','o','c','e','s','s',0 };

static size_t a2w(const char* a, WCHAR* w, size_t cap){
  size_t i=0; for (; a && *a && i+1<cap; ++a,++i) w[i] = (unsigned char)(*a);
  if (w && cap) w[i] = 0; return i;
}
__attribute__((visibility("default"))) void nt_set_command_lineA(const char* s){
  if (!s) return; size_t L = strlen(s); if (L >= sizeof(g_cmdlineA)) L = sizeof(g_cmdlineA)-1;
  memcpy(g_cmdlineA, s, L); g_cmdlineA[L] = 0; a2w(g_cmdlineA, g_cmdlineW, sizeof(g_cmdlineW)/sizeof(g_cmdlineW[0]));
}
LPCSTR  WINAPI GetCommandLineA(void){ return g_cmdlineA; }
LPCWSTR WINAPI GetCommandLineW(void){ return g_cmdlineW; }

/* ---- 模組/符號 ---- */
static HMODULE g_kernel32 = (HMODULE)(uintptr_t)1;
static int ieq(const char* a, const char* b){
  for (; *a && *b; ++a,++b){ int ca = (*a>='A'&&*a<='Z') ? (*a+32) : (unsigned char)*a; int cb = (*b>='A'&&*b<='Z') ? (*b+32) : (unsigned char)*b; if (ca!=cb) return 0; }
  return *a==0 && *b==0;
}
HMODULE WINAPI GetModuleHandleA(LPCSTR name){
  if (!name || !*name) return g_kernel32;
  char buf[64]; size_t j=0;
  for (size_t i=0; name[i] && j+1<sizeof(buf); ++i){ char c = name[i]; if (c>='A'&&c<='Z') c=(char)(c+32); buf[j++]=c; }
  buf[j]=0; size_t L=strlen(buf);
  /* 修正：正確剝除 .dll 後綴 */
  if (L>=4 && buf[L-4]=='.' && buf[L-3]=='d' && buf[L-2]=='l' && buf[L-1]=='l') buf[L-4]=0;
  if (ieq(buf,"kernel32")) return g_kernel32;
  return NULL;
}
HMODULE WINAPI GetModuleHandleW(LPCWSTR name){
  if (!name) return g_kernel32; char tmp[64]; size_t i=0; for (; name[i] && i+1<sizeof(tmp); ++i) tmp[i] = (char)(name[i] & 0xFF); tmp[i]=0;
  return GetModuleHandleA(tmp);
}

extern struct Hook NT_HOOKS[];
FARPROC WINAPI GetProcAddress(HMODULE h, LPCSTR name){
  if (!h || !name) return NULL;
  for (struct Hook* p=NT_HOOKS; p && p->dll; ++p){ if (strcmp(p->name, name)==0) return (FARPROC)p->fn; }
  /* 去除 _ 與 @N（stdcall 裝飾） */
  char clean[128]; size_t i=0,j=0; if (name[0]=='_') ++i;
  for (; name[i] && j+1<sizeof(clean); ++i){
    if (name[i]=='@'){ size_t k=i+1; int all=1; while (name[k]){ if (!isdigit((unsigned char)name[k])){ all=0; break; } ++k; } if (all) break; }
    clean[j++] = name[i];
  }
  clean[j]=0;
  for (struct Hook* p=NT_HOOKS; p && p->dll; ++p){ if (strcmp(p->name, clean)==0) return (FARPROC)p->fn; }
  LOGF("GetProcAddress miss: \"%s\" (clean=\"%s\")", name, clean);
  return NULL;
}

/* ---- CreateProcess / Wait / ExitCode / Close ---- */
static void ms_sleep(unsigned ms){ struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)(ms%1000)*1000000L; nanosleep(&ts,NULL); }

static const char* pick_loader(void){
  if (access("/usr/lib/awaos/pe_loader32", X_OK) == 0) return "/usr/lib/awaos/pe_loader32";
  if (access("/usr/local/lib/awaos/pe_loader32", X_OK) == 0) return "/usr/local/lib/awaos/pe_loader32";
  return NULL;
}
static int split_args(char* s, char** outv, int maxv){
  int n=0; while (s && *s && n < maxv-1){ while (*s==' ' || *s=='\t') ++s; if (!*s) break; outv[n++]=s; while (*s && *s!=' ' && *s!='\t') ++s; if (*s) *s++='\0'; }
  outv[n]=NULL; return n;
}
static pid_t g_last_pid=-1; static int g_last_status=0;

BOOL WINAPI CreateProcessA(LPCSTR appName, LPSTR cmdLine, LPVOID a, LPVOID b, BOOL inh, DWORD flags, LPVOID env, LPCSTR curdir, STARTUPINFOA* si, PROCESS_INFORMATION* pi){
  (void)a;(void)b;(void)inh;(void)flags;(void)env;(void)si;
  const char* loader = pick_loader(); if (!loader || !appName || !*appName) return FALSE;
  char* args_buf=NULL; char* argv[64]; int ai=0; argv[ai++]=(char*)loader; argv[ai++]=(char*)appName;
  if (cmdLine && *cmdLine){ size_t L=strlen(cmdLine); args_buf=(char*)malloc(L+1); if(!args_buf) return FALSE; memcpy(args_buf,cmdLine,L+1); ai += split_args(args_buf,&argv[ai],(int)(64-ai)); }
  argv[ai]=NULL;
  pid_t pid=fork(); if(pid<0){ if(args_buf) free(args_buf); return FALSE; }
  if(pid==0){ if (curdir && *curdir) chdir(curdir); execv(loader, argv); _exit(127); }
  if(args_buf) free(args_buf);
  if (pi){ pi->hProcess=(HANDLE)(uintptr_t)pid; pi->hThread=0; pi->dwProcessId=(DWORD)pid; pi->dwThreadId=0; }
  return TRUE;
}
BOOL WINAPI CreateProcessW(LPCWSTR a, LPWSTR c, LPVOID d, LPVOID e, BOOL f, DWORD g, LPVOID h, LPCWSTR cur, STARTUPINFOW* si, PROCESS_INFORMATION* pi){
  char app[512]={0}, *cmd=NULL, curdir[512]={0};
  if (a){ for(size_t i=0;a[i]&&i<sizeof(app)-1;++i) app[i]=(char)(a[i]&0xFF); }
  if (cur){ for(size_t i=0;cur[i]&&i<sizeof(curdir)-1;++i) curdir[i]=(char)(cur[i]&0xFF); }
  if (c){ size_t L=0; while(c[L]) ++L; cmd=(char*)malloc(L+1); if(!cmd) return FALSE; for(size_t i=0;i<L;++i) cmd[i]=(char)(c[i]&0xFF); cmd[L]=0; }
  BOOL ok = CreateProcessA(a?app:NULL, cmd, d, e, f, g, h, cur?curdir:NULL, (STARTUPINFOA*)si, pi);
  if (cmd) free(cmd); return ok;
}

DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms){
  if (_nt_is_thread_handle(h)){ int r=_nt_wait_thread(h,ms); if(r==0) return WAIT_OBJECT_0; if(r==1) return WAIT_TIMEOUT; return WAIT_FAILED; }
  pid_t pid=(pid_t)(uintptr_t)h; int st=0;
  if (ms==INFINITE){ if (waitpid(pid,&st,0)<0) return WAIT_FAILED; g_last_pid=pid; g_last_status=st; return WAIT_OBJECT_0; }
  const unsigned step=5; unsigned waited=0;
  for(;;){ pid_t r=waitpid(pid,&st,WNOHANG); if (r<0) return WAIT_FAILED; if(r>0){ g_last_pid=pid; g_last_status=st; return WAIT_OBJECT_0; } if(waited>=ms) return WAIT_TIMEOUT; ms_sleep(step); waited+=step; }
}
BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD lpExitCode){
  if (_nt_is_thread_handle(h)){ if(lpExitCode) *lpExitCode=_nt_get_thread_exit_code(h); return TRUE; }
  pid_t pid=(pid_t)(uintptr_t)h; int st=0; pid_t r=waitpid(pid,&st,WNOHANG);
  if (r==0){ if(lpExitCode) *lpExitCode=STILL_ACTIVE; return TRUE; }
  if (r<0) return FALSE;
  if (WIFEXITED(st)){ if(lpExitCode) *lpExitCode=(DWORD)WEXITSTATUS(st); return TRUE; }
  if (WIFSIGNALED(st)){ if(lpExitCode) *lpExitCode=(DWORD)(128+WTERMSIG(st)); return TRUE; }
  if (lpExitCode) *lpExitCode=STILL_ACTIVE; return TRUE;
}
BOOL WINAPI CloseHandle(HANDLE h){ if (_nt_is_thread_handle(h)) return _nt_close_thread(h); return TRUE; }

/* ---- 匯入表 ---- */
__attribute__((visibility("default")))
struct Hook NT_HOOKS[] = {
  {"KERNEL32.DLL","GetStdHandle",        (void*)GetStdHandle},
  {"KERNEL32.DLL","SetStdHandle",        (void*)SetStdHandle},
  {"KERNEL32.DLL","WriteFile",           (void*)WriteFile},
  {"KERNEL32.DLL","ReadFile",            (void*)ReadFile},
  {"KERNEL32.DLL","WriteConsoleA",       (void*)WriteConsoleA},
  {"KERNEL32.DLL","ReadConsoleA",        (void*)ReadConsoleA},
  {"KERNEL32.DLL","FlushFileBuffers",    (void*)FlushFileBuffers},
  {"KERNEL32.DLL","GetFileType",         (void*)GetFileType},
  {"KERNEL32.DLL","GetConsoleMode",      (void*)GetConsoleMode},
  {"KERNEL32.DLL","SetConsoleMode",      (void*)SetConsoleMode},
  {"KERNEL32.DLL","GetStartupInfoA",     (void*)GetStartupInfoA},
  {"KERNEL32.DLL","GetStartupInfoW",     (void*)GetStartupInfoW},
  {"KERNEL32.DLL","GetEnvironmentStringsA", (void*)GetEnvironmentStringsA},
  {"KERNEL32.DLL","GetEnvironmentStringsW", (void*)GetEnvironmentStringsW},
  {"KERNEL32.DLL","FreeEnvironmentStringsA",(void*)FreeEnvironmentStringsA},
  {"KERNEL32.DLL","FreeEnvironmentStringsW",(void*)FreeEnvironmentStringsW},
  {"KERNEL32.DLL","ExitProcess",         (void*)ExitProcess},

  {"KERNEL32.DLL","CreateProcessA",      (void*)CreateProcessA},
  {"KERNEL32.DLL","CreateProcessW",      (void*)CreateProcessW},
  {"KERNEL32.DLL","WaitForSingleObject", (void*)WaitForSingleObject},
  {"KERNEL32.DLL","GetExitCodeProcess",  (void*)GetExitCodeProcess},
  {"KERNEL32.DLL","CloseHandle",         (void*)CloseHandle},
  {"KERNEL32.DLL","GetCommandLineA",     (void*)GetCommandLineA},
  {"KERNEL32.DLL","GetCommandLineW",     (void*)GetCommandLineW},
  {"KERNEL32.DLL","GetModuleHandleA",    (void*)GetModuleHandleA},
  {"KERNEL32.DLL","GetModuleHandleW",    (void*)GetModuleHandleW},
  {"KERNEL32.DLL","GetProcAddress",      (void*)GetProcAddress},

  /* Threads & TLS（由 ntdll32 提供） */
  {"KERNEL32.DLL","CreateThread",        (void*)CreateThread},
  {"KERNEL32.DLL","ExitThread",          (void*)ExitThread},
  {"KERNEL32.DLL","Sleep",               (void*)Sleep},
  {"KERNEL32.DLL","GetCurrentThreadId",  (void*)GetCurrentThreadId},
  {"KERNEL32.DLL","TlsAlloc",            (void*)TlsAlloc},
  {"KERNEL32.DLL","TlsFree",             (void*)TlsFree},
  {"KERNEL32.DLL","TlsGetValue",         (void*)TlsGetValue},
  {"KERNEL32.DLL","TlsSetValue",         (void*)TlsSetValue},
  {NULL,NULL,NULL}
};
