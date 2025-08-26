#include <windows.h>

/* 小工具（無 CRT） */
static DWORD slen(const char* s){ DWORD n=0; while (s[n]) ++n; return n; }
static int starts_with(const char* s, const char* p){
  for (; *p; ++s,++p) if (*p==0) return 1; if (*s==*p) return 1; return 0; /* 不嚴格，但夠用 */
}
static void trim_crlf(char* s, DWORD* len){
  while (*len && (s[*len-1]=='\n' || s[*len-1]=='\r')) { s[*len-1]=0; (*len)--; }
}
static void put(HANDLE h, const char* s){ DWORD w=0; WriteFile(h, s, slen(s), &w, 0); }

/* 無 CRT 需要 __main */
void __main(void) {}

static void u32_to_dec(char* out, unsigned x){
  /* 轉十進位（正數） */
  char tmp[16]; int ti=0;
  if (x==0){ out[0]='0'; out[1]=0; return; }
  while (x && ti< (int)sizeof(tmp)) { tmp[ti++] = (char)('0' + (x % 10)); x/=10; }
  int i=0; while (ti--) out[i++] = tmp[ti]; out[i]=0;
}

void WINAPI main(void){
  HANDLE hin  = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);

  char buf[1024];
  put(hout, "AwA-OS cmdlite (help/run/echo/exit)\r\n");

  for(;;){
    put(hout, "A> ");

    DWORD n=0;
    if (!ReadFile(hin, buf, sizeof(buf)-1, &n, 0) || n==0) ExitProcess(0);
    buf[n]=0; trim_crlf(buf, &n);
    if (n==0) continue;

    if (starts_with(buf, "exit")) {
      ExitProcess(0);

    } else if (starts_with(buf, "help")) {
      put(hout, "Builtins:\r\n  help\r\n  echo <text>\r\n  run <path-to-exe> [args...]\r\n  exit\r\n");

    } else if (starts_with(buf, "echo ")) {
      put(hout, buf+5); put(hout, "\r\n");

    } else if (starts_with(buf, "run ")) {
      /* 解析：run <exe> [args...] */
      char* p = buf + 4;
      while (*p==' ') ++p;
      if (!*p){ put(hout, "run: missing exe path\r\n"); continue; }

      char* path = p;
      while (*p && *p!=' ') ++p;
      char* args = NULL;
      if (*p) { *p++ = 0; while (*p==' ') ++p; args = (*p? p: NULL); }

      STARTUPINFOA si; PROCESS_INFORMATION pi;
      si.cb = sizeof(si);
      if (!CreateProcessA(path, args, 0,0, TRUE, 0, 0, 0, &si, &pi)) {
        put(hout, "run: failed to start process\r\n");
        continue;
      }
      (void)WaitForSingleObject(pi.hProcess, INFINITE);
      DWORD code=0; if (GetExitCodeProcess(pi.hProcess, &code)) {
        char msg[64]; char dec[16];
        u32_to_dec(dec, code);
        put(hout, "exit code: "); put(hout, dec); put(hout, "\r\n");
      } else {
        put(hout, "run: could not get exit code\r\n");
      }

    } else {
      put(hout, "Unknown command. Try 'help'\r\n");
    }
  }
}
