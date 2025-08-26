#include <windows.h>

// 小工具：字串長度與比較（避免 CRT）
static DWORD slen(const char* s){ DWORD n=0; while (s[n]) ++n; return n; }
static int starts_with(const char* s, const char* p){
  for (; *p; ++s,++p) if (*s!=*p) return 0; return 1;
}
static void trim_crlf(char* s, DWORD* len){
  while (*len && (s[*len-1]=='\n' || s[*len-1]=='\r')) { s[*len-1]=0; (*len)--; }
}

// MinGW 在 -nostdlib 會預期 __main
void __main(void) {}

static void put(HANDLE hOut, const char* s){
  DWORD w=0; WriteFile(hOut, s, slen(s), &w, 0);
}

void WINAPI main(void){
  HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

  char buf[512];
  put(hOut, "AwA-OS cmdlite (type 'help')\r\n");

  for(;;){
    put(hOut, "A> ");

    DWORD n=0;
    if (!ReadFile(hIn, buf, sizeof(buf)-1, &n, 0) || n==0) {
      // EOF 或讀取失敗就離開
      ExitProcess(0);
    }
    buf[n]=0; trim_crlf(buf, &n);

    if (n==0) continue;

    if (starts_with(buf, "exit")) {
      ExitProcess(0);
    } else if (starts_with(buf, "help")) {
      put(hOut, "Builtins: help, echo <text>, exit\r\n");
    } else if (starts_with(buf, "echo ")) {
      put(hOut, buf+5);
      put(hOut, "\r\n");
    } else {
      put(hOut, "Unknown command. Try 'help'\r\n");
    }
  }
}
