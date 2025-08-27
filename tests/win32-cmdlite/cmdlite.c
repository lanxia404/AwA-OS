// tests/win32-cmdlite/cmdlite.c
// Minimal cmd-like shell for AwA-OS Win32 personality (i386)
// Build (CI): i686-w64-mingw32-gcc -s -o tests/win32-cmdlite/cmdlite.exe \
//   -ffreestanding -fno-asynchronous-unwind-tables \
//   -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
#include "../../winss/include/win/minwin.h"

/* MinGW/GCC 可能插入對 __main 的呼叫；-nostdlib 時自行提供空符號 */
#ifdef __GNUC__
void __main(void) { /* no-op */ }
#endif

#define IN  ((HANDLE)(uintptr_t)STD_INPUT_HANDLE)
#define OUT ((HANDLE)(uintptr_t)STD_OUTPUT_HANDLE)
#define ERR ((HANDLE)(uintptr_t)STD_ERROR_HANDLE)

static DWORD s_len(const char* s){ DWORD n=0; if(!s) return 0; while(s[n]) ++n; return n; }
static int   s_eq(const char* a, const char* b){ DWORD i=0; if(!a||!b) return 0; for(;;){ char ca=a[i], cb=b[i]; if(ca!=cb) return 0; if(!ca) return 1; ++i; } }
static void  s_move(char* d, const char* s, DWORD n){ if(d<s){ for(DWORD i=0;i<n;++i) d[i]=s[i]; } else if(d>s){ for(DWORD i=n;i>0;--i) d[i-1]=s[i-1]; } }

static void putsA(const char* s){
  DWORD w=0; WriteFile(OUT, s, s_len(s), &w, 0);
}
static void putln(const char* s){
  DWORD w=0; WriteFile(OUT, s, s_len(s), &w, 0);
  WriteFile(OUT, "\r\n", 2, &w, 0);
}
static void putu(unsigned v){
  char buf[16]; int i=15; buf[i--]=0;
  if(v==0){ buf[i]='0'; putsA(&buf[i]); return; }
  while(v && i>=0){ buf[i--] = (char)('0'+(v%10)); v/=10; }
  putsA(&buf[i+1]);
}

static int readline(char* out, DWORD cap){
  if(cap==0) return 0;
  DWORD used=0;
  for(;;){
    char ch; DWORD n=0;
    if(!ReadFile(IN, &ch, 1, &n, 0) || n==0) break;
    if(ch=='\r') continue;
    if(ch=='\n'){ out[used]=0; return 1; }
    if(used+1<cap){ out[used++]=ch; }
  }
  out[used]=0;
  return used>0;
}

static void trim(char* s){
  DWORD L=s_len(s), i=0, j=L;
  while(i<L && (s[i]==' '||s[i]=='\t')) ++i;
  while(j>i && (s[j-1]==' '||s[j-1]=='\t')) --j;
  if(i>0) s_move(s, s+i, j-i);
  s[j-i]=0;
}

static int cmd_echo(char* args){
  trim(args);
  putln(args);
  return 0;
}

/* 更保守的 run 參數解析：跳過空白 → 取第一段為程式路徑 → 其餘整段當 cmdline */
static int cmd_run(char* args){
  char* p=args;
  /* 跳過前置空白 */
  while(*p==' '||*p=='\t') ++p;
  if(!*p){ putln("Usage: run <exe> [args...]"); return 1; }

  /* 擷取程式路徑 */
  char* prog = p;
  while(*p && *p!=' ' && *p!='\t') ++p;

  /* 分隔與擷取後續 cmdline */
  char* cmdline = 0;
  if(*p){ *p++ = 0; /* NUL 結束路徑 */
    while(*p==' '||*p=='\t') ++p;
    if(*p) cmdline = p;
  }

  STARTUPINFOA si; PROCESS_INFORMATION pi;
  GetStartupInfoA(&si);

  if(!CreateProcessA(prog, cmdline, 0, 0, TRUE, 0, 0, 0, &si, &pi)){
    putln("CreateProcess failed"); return 1;
  }
  (void)WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code=0; GetExitCodeProcess(pi.hProcess, &code);
  putsA("exit code: "); putu(code); putln("");
  CloseHandle(pi.hProcess);
  return (int)code;
}

static void show_help(void){
  putln("Commands:");
  putln("  help              - show this help");
  putln("  echo <text>       - print text");
  putln("  run <exe> [args]  - run PE32 using loader");
  putln("  exit              - quit");
}

#ifdef __GNUC__
__attribute__((stdcall))
#endif
void main(void){
  putsA("AwA-OS cmdlite (help/run/echo/exit)\r\n");
  char line[512];

  for(;;){
    putsA("A> ");
    if(!readline(line, sizeof(line))) break;
    trim(line);
    if(!*line) continue;

    /* 取第一個 token 作為命令（僅判斷，不破壞其後字串） */
    char* p=line;
    while(*p==' '||*p=='\t') ++p;
    char* cmd=p;
    while(*p && *p!=' ' && *p!='\t') ++p;
    char saved=*p; *p=0;          /* 暫時截斷命令 */
    char* rest = (saved? p+1 : p);/* 指向可能的參數起點 */

    if(s_eq(cmd,"help")){ *p=saved; show_help(); continue; }
    if(s_eq(cmd,"echo")){ *p=saved; cmd_echo(rest); continue; }
    if(s_eq(cmd,"run")) { *p=saved; (void)cmd_run(rest); continue; }
    if(s_eq(cmd,"exit")){ ExitProcess(0); }

    *p=saved;
    putln("Unknown command. Try 'help'");
  }
  ExitProcess(0);
}