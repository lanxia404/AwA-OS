#include <windows.h>

/* ===== 小工具：無 CRT 版本 ===== */
static DWORD slen(const char* s){ DWORD n=0; while (s && s[n]) ++n; return n; }
static void put(HANDLE h, const char* s){ DWORD w=0; WriteFile(h, s, slen(s), &w, 0); }
static char tolower_ascii(char c){ return (c>='A' && c<='Z') ? (c+32) : c; }

/* 去掉前後的空白+CRLF */
static void trim(char* s, DWORD* len){
  DWORD n = *len;
  /* 去尾巴 CR/LF/空白 */
  while (n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) { s[n-1]=0; --n; }
  /* 去頭部空白 */
  DWORD i=0; while (i<n && (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) ++i;
  if (i && i<n){ /* 左移 */
    DWORD j=0; for (; i<n; ++i,++j) s[j]=s[i]; s[j]=0; n=j;
  } else if (i==n){ s[0]=0; n=0; }
  *len = n;
}

/* 擷取第一個 token（以空白/Tab 分隔），回傳 token 長度；*rest 指到剩餘字串起點 */
static int first_token(char* s, char** rest){
  int i=0; while (s[i] && s[i]!=' ' && s[i]!='\t' && s[i]!='\r' && s[i]!='\n') ++i;
  if (s[i]){ s[i]=0; *rest = (s[i+1]? s+i+1 : s+i); }
  else { *rest = s+i; }
  return i;
}

/* 無 CRT：itoa(正整數) */
static void u32_to_dec(char* out, unsigned x){
  char tmp[16]; int ti=0; if (x==0){ out[0]='0'; out[1]=0; return; }
  while (x && ti<(int)sizeof(tmp)) { tmp[ti++] = (char)('0' + (x % 10)); x/=10; }
  int i=0; while (ti--) out[i++] = tmp[ti]; out[i]=0;
}

/* MinGW 無 CRT 時需要此符號 */
void __main(void) {}

/* ===== 主程式 ===== */
void WINAPI main(void){
  HANDLE hin  = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);

  char buf[1024];
  put(hout, "AwA-OS cmdlite (help/run/echo/exit)\r\n");

  for(;;){
    put(hout, "A> ");

    DWORD n=0;
    if (!ReadFile(hin, buf, sizeof(buf)-1, &n, 0) || n==0) {
      /* EOF 或讀取失敗就離開 */
      ExitProcess(0);
    }
    buf[n]=0;
    trim(buf, &n);
    if (n==0) continue;

    /* 取第一個 token（小寫化比較） */
    char* rest = NULL;
    int tlen = first_token(buf, &rest);
    if (tlen==0) continue;

    /* 把 token 轉小寫到 tok[] */
    char tok[32]; int i=0;
    for (; i<tlen && i<(int)(sizeof(tok)-1); ++i) tok[i] = tolower_ascii(buf[i]);
    tok[i]=0;

    if (tok[0]=='e' && tok[1]=='x' && tok[2]=='i' && tok[3]=='t' && tok[4]==0) {
      ExitProcess(0);

    } else if (tok[0]=='h' && tok[1]=='e' && tok[2]=='l' && tok[3]=='p' && tok[4]==0) {
      put(hout, "Builtins:\r\n  help\r\n  echo <text>\r\n  run <path-to-exe> [args...]\r\n  exit\r\n");

    } else if (tok[0]=='e' && tok[1]=='c' && tok[2]=='h' && tok[3]=='o' && tok[4]==0) {
      /* rest 直接輸出 */
      put(hout, rest); put(hout, "\r\n");

    } else if (tok[0]=='r' && tok[1]=='u' && tok[2]=='n' && tok[3]==0) {
      /* rest: "<exe> [args...]" */
      char* p = rest;
      while (*p==' '||*p=='\t') ++p;
      if (!*p){ put(hout, "run: missing exe path\r\n"); continue; }

      char* path = p;
      while (*p && *p!=' ' && *p!='\t' && *p!='\r' && *p!='\n') ++p;
      char* args = NULL;
      if (*p){ *p++ = 0; while (*p==' '||*p=='\t') ++p; if (*p) args = p; }

      STARTUPINFOA si; PROCESS_INFORMATION pi;
      si.cb = sizeof(si);

      if (!CreateProcessA(path, args, 0,0, TRUE, 0, 0, 0, &si, &pi)) {
        put(hout, "run: failed to start process\r\n");
        continue;
      }
      (void)WaitForSingleObject(pi.hProcess, INFINITE);
      DWORD code=0;
      if (GetExitCodeProcess(pi.hProcess, &code)) {
        char dec[16];
        u32_to_dec(dec, code);
        put(hout, "exit code: "); put(hout, dec); put(hout, "\r\n");
      } else {
        put(hout, "run: could not get exit code\r\n");
      }

    } else {
      put(hout, "Unknown command: ");
      put(hout, buf);
      put(hout, "\r\nTry 'help'\r\n");
    }
  }
}
