// tests/win32-cmdlite/cmdlite.c
// Minimal cmd-like shell for AwA-OS Win32 personality (i386)
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

/* -------- 緩衝式讀行（處理短讀與一次多行） -------- */
static char  ibuf[1024];
static DWORD ilen = 0, ipos = 0;

static int fill_input(void){
  if (ipos > 0 && ipos < ilen){ /* 壓縮未消耗資料到起點 */
    DWORD rem = ilen - ipos;
    for (DWORD i=0;i<rem;++i) ibuf[i] = ibuf[ipos + i];
    ilen = rem; ipos = 0;
  } else if (ipos >= ilen){ ilen = 0; ipos = 0; }

  if (ilen >= sizeof(ibuf)) return 1; /* buffer full */

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
    /* 先在緩衝中找 \n */
    for (; ipos < ilen; ++ipos){
      char c = ibuf[ipos];
      if (c == '\r') continue;
      if (c == '\n'){ /* 完整一行 */
        ipos++;
        out[used] = 0;
        return 1;
      }
      if (used + 1 < cap) out[used++] = c;
    }
    /* 沒找到 \n，嘗試再讀些資料；若讀不到則當 EOF */
    if (!fill_input()){
      out[used] = 0;
      return used > 0; /* 最後一行無換行也可回傳 */
    }
  }
}

/* -------- 簡易 token 解析 -------- */
static void trim(char* s){
  DWORD L=s_len(s), i=0, j=L;
  while(i<L && (s[i]==' '||s[i]=='\t')) ++i;
  while(j>i && (s[j-1]==' '||s[j-1]=='\t')) --j;
  if (i>0){ for(DWORD k=0;k<j-i;++k) s[k]=s[i+k]; s[j-i]=0; } else s[L]=0;
}

static char* next_token(char* s, char** token){
  char* p=s;
  while(*p==' '||*p=='\t') ++p;
  if(!*p){ *token=0; return p; }
  char* start=p; char* outp=p; int quoted=0;
  if(*p=='"'){ quoted=1; ++p; start=p; }
  for(;;){
    char c=*p++;
    if(c==0) break;
    if(quoted){ if(c=='"') break; }
    else { if(c==' '||c=='\t'){ --p; break; } }
    *outp++ = c;
  }
  *outp=0; *token = start;
  while(*p==' '||*p=='\t') ++p;
  return p;
}

/* -------- 指令實作 -------- */
static int cmd_echo(char* args){ trim(args); putln(args); return 0; }

static int cmd_run(char* args){
  char *prog=0; char* rest = next_token(args, &prog);
  if(!prog || !*prog){ putln("Usage: run <exe> [args...]"); return 1; }

  STARTUPINFOA si; PROCESS_INFORMATION pi;
  GetStartupInfoA(&si);

  if(!CreateProcessA(prog, (*rest? rest: 0), 0, 0, TRUE, 0, 0, 0, &si, &pi)){
    putln("CreateProcess failed"); return 1;
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

    char* tok=0; char* rest = next_token(line, &tok);
    if(!tok) continue;

    if(s_eq(tok,"help")){ show_help(); continue; }
    if(s_eq(tok,"echo")){ cmd_echo(rest); continue; }
    if(s_eq(tok,"run")) { (void)cmd_run(rest); continue; }
    if(s_eq(tok,"exit")){ ExitProcess(0); }

    putln("Unknown command. Try 'help'");
  }
  ExitProcess(0);
}