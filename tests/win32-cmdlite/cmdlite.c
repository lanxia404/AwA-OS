// tests/win32-cmdlite/cmdlite.c
// Minimal cmd-like shell for AwA-OS Win32 personality (i386)
// Build (CI):
//   i686-w64-mingw32-gcc -s -o tests/win32-cmdlite/cmdlite.exe \
//     -ffreestanding -fno-asynchronous-unwind-tables \
//     -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
#include "../../winss/include/win/minwin.h"
#include <stdint.h>

#ifdef __GNUC__
void __main(void) { /* no-op for -nostdlib */ }
#endif

#define IN  ((HANDLE)(uintptr_t)STD_INPUT_HANDLE)
#define OUT ((HANDLE)(uintptr_t)STD_OUTPUT_HANDLE)

static DWORD s_len(const char* s){ DWORD n=0; if(!s) return 0; while(s[n]) ++n; return n; }
static int   s_eq(const char* a, const char* b){ DWORD i=0; if(!a||!b) return 0; for(;;){ char ca=a[i], cb=b[i]; if(ca!=cb) return 0; if(!ca) return 1; ++i; } }
static void  put(const char* s){ DWORD w; WriteFile(OUT, s, s_len(s), &w, 0); }
static void  putln(const char* s){ DWORD w; WriteFile(OUT, s, s_len(s), &w, 0); WriteFile(OUT, "\r\n", 2, &w, 0); }
static void  putu(unsigned v){ char b[16]; int i=15; b[i--]=0; if(!v){ b[i]='0'; put(&b[i]); return; } while(v&&i>=0){ b[i--]='0'+(v%10); v/=10; } put(&b[i+1]); }

/* ---- 緩衝式讀行：能處理管線短讀與一次多行輸入 ---- */
static char  ibuf[1024];
static DWORD ilen = 0, ipos = 0;

static int fill_input(void){
  if (ipos > 0 && ipos < ilen){
    DWORD rem = ilen - ipos;
    for (DWORD i=0;i<rem;++i) ibuf[i] = ibuf[ipos + i];
    ilen = rem; ipos = 0;
  } else if (ipos >= ilen){ ilen = 0; ipos = 0; }

  if (ilen >= sizeof(ibuf)) return 1;

  DWORD got = 0;
  if (!ReadFile(IN, ibuf + ilen, (DWORD)(sizeof(ibuf) - ilen), &got, 0))
    return 0;
  ilen += got;
  return got > 0;
}

static int readline(char* out, DWORD cap){
  if (cap == 0) return 0;
  DWORD used = 0;

  for (;;){
    for (; ipos < ilen; ++ipos){
      char c = ibuf[ipos];
      if (c == '\r') continue;
      if (c == '\n'){ ipos++; out[used] = 0; return 1; }
      if (used + 1 < cap) out[used++] = c;
    }
    if (!fill_input()){
      out[used] = 0;
      return used > 0;
    }
  }
}

/* ---- 簡易工具 ---- */
static void trim(char* s){
  DWORD L=s_len(s), i=0, j=L;
  while(i<L && (s[i]==' '||s[i]=='\t')) ++i;
  while(j>i && (s[j-1]==' '||s[j-1]=='\t')) --j;
  if (i>0){ for(DWORD k=0;k<j-i;++k) s[k]=s[i+k]; s[j-i]=0; } else s[L]=0;
}

/* ---- 指令實作 ---- */
static int cmd_echo(char* args){ trim(args); putln(args); return 0; }

/* 重點：把 run 後面的整段視為目標可執行檔（避免就地分詞的邊界行為） */
static int cmd_run(char* args){
  trim(args);
  if(!*args){ putln("Usage: run <exe> [args...]"); return 1; }

  const char* prog = args;             /* 本測試路徑無空白，直接用整段 */
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  GetStartupInfoA(&si);

  if(!CreateProcessA(prog, 0, 0, 0, TRUE, 0, 0, 0, &si, &pi)){
    putln("CreateProcess failed");
    return 1;
  }
  (void)WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code=0; GetExitCodeProcess(pi.hProcess, &code);
  put("exit code: "); putu(code); putln("");
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
  put("AwA-OS cmdlite (help/run/echo/exit)\r\n");

  char line[512];
  for(;;){
    put("A> ");
    if(!readline(line, sizeof(line))) break;
    trim(line);
    if(!*line) continue;

    /* 只取第一個 token 判斷指令，餘下整段交給各指令自己處理 */
    char* p = line;
    while(*p==' '||*p=='\t') ++p;
    char* cmd = p;
    while(*p && *p!=' ' && *p!='\t') ++p;
    char* args = (*p ? (p+1) : p);
    *p = 0;

    if(s_eq(cmd,"help")){ show_help(); continue; }
    if(s_eq(cmd,"echo")){ cmd_echo(args); continue; }
    if(s_eq(cmd,"run")) { (void)cmd_run(args); continue; }
    if(s_eq(cmd,"exit")){ ExitProcess(0); }

    putln("Unknown command. Try 'help'");
  }
  ExitProcess(0);
}