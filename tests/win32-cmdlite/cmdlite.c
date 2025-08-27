// tests/win32-cmdlite/cmdlite.c
// Minimal cmd-like shell for AwA-OS Win32 personality (i386)
// Build (CI): i686-w64-mingw32-gcc -s -o cmdlite.exe \
//   -ffreestanding -fno-asynchronous-unwind-tables \
//   -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
#include "../../winss/include/win/minwin.h"

#define IN  ((HANDLE)(uintptr_t)STD_INPUT_HANDLE)
#define OUT ((HANDLE)(uintptr_t)STD_OUTPUT_HANDLE)
#define ERR ((HANDLE)(uintptr_t)STD_ERROR_HANDLE)

static DWORD s_len(const char* s){ DWORD n=0; if(!s) return 0; while(s[n]) ++n; return n; }
static int   s_eq(const char* a, const char* b){ DWORD i=0; if(!a||!b) return 0; for(;;){ char ca=a[i], cb=b[i]; if(ca!=cb) return 0; if(!ca) return 1; ++i; } }
static int   s_ncmp(const char* a, const char* b, DWORD n){ for(DWORD i=0;i<n;++i){ char ca=a[i], cb=b[i]; if(ca!=cb) return (unsigned char)ca - (unsigned char)cb; if(!ca) return 0; } return 0; }
static void  s_copy(char* d, const char* s){ while((*d++=*s++)); }
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
  // 逐次 ReadFile，直到 \n 或緩衝滿
  if(cap==0) return 0;
  DWORD used=0;
  for(;;){
    char ch;
    DWORD n=0;
    if(!ReadFile(IN, &ch, 1, &n, 0) || n==0) break;
    if(ch=='\r') continue;
    if(ch=='\n'){ out[used]=0; return 1; }
    if(used+1<cap){ out[used++]=ch; }
  }
  out[used]=0;
  return used>0;
}

static void trim(char* s){
  // 左右去空白
  DWORD L=s_len(s), i=0, j=L;
  while(i<L && (s[i]==' '||s[i]=='\t')) ++i;
  while(j>i && (s[j-1]==' '||s[j-1]=='\t')) --j;
  if(i>0) s_move(s, s+i, j-i);
  s[j-i]=0;
}

static char* next_token(char* s, char** token){
  // 以空白切 token；支援引號
  char* p=s;
  while(*p==' '||*p=='\t') ++p;
  if(!*p){ *token=0; return p; }
  char* start=p; char* out=p; int quoted=0;
  if(*p=='"'){ quoted=1; ++p; start=p; }
  for(;;){
    char c=*p++;
    if(c==0) break;
    if(quoted){
      if(c=='"') break;
    }else{
      if(c==' '||c=='\t') { --p; break; }
    }
    *out++ = c;
  }
  *out=0;
  *token = start;
  while(*p==' '||*p=='\t') ++p;
  return p;
}

static int cmd_echo(char* args){
  trim(args);
  putln(args);
  return 0;
}

static int cmd_run(char* args){
  // run <path> [args...]
  char* p=args; char *prog=0; p = next_token(p, &prog);
  if(!prog || !*prog){ putln("Usage: run <exe> [args...]"); return 1; }

  // 把剩餘字串當作 cmdline 傳遞（不含程式名），Windows CreateProcess 規範允許
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  GetStartupInfoA(&si);
  // 我們不更動標準把手，維持繼承（CI 會重導）
  if(!CreateProcessA(prog, (*p? p: 0), 0, 0, TRUE, 0, 0, 0, &si, &pi)){
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
    putsA("A> "); // 提示字元
    if(!readline(line, sizeof(line))) break;
    trim(line);
    if(!*line) continue;

    // 取第一個 token 作為命令
    char* rest=line; char* tok=0;
    rest = next_token(rest, &tok);
    if(!tok) continue;

    if(s_eq(tok,"help")){ show_help(); continue; }
    if(s_eq(tok,"echo")){ cmd_echo(rest); continue; }
    if(s_eq(tok,"run")) { (void)cmd_run(rest); continue; }
    if(s_eq(tok,"exit")){ ExitProcess(0); }

    putln("Unknown command. Try 'help'");
  }
  ExitProcess(0);
}