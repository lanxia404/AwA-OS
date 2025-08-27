// winss/loader/pe_loader32.c
// AwA-OS PE32 loader (i386) - minimal, with Windows-style command line building
// NOTE: focuses on fixing nt_set_command_lineA usage and getenv include.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>         // <-- for getenv, malloc, free
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "../include/win/minwin.h"
#include "../include/nt/ntdef.h"
#include "../ntshim32/ntshim_api.h"   // nt_set_command_lineA(), nt_teb_setup_for_current(), etc.
#include "../include/nt/hooks.h"      // extern struct Hook NT_HOOKS[];

static int is_log(void){
  static int inited = 0, val = 0;
  if(!inited){
    inited = 1;
    const char* v = getenv("AWAOS_LOG");
    val = (v && *v) ? 1 : 0;
  }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr, "[pe_loader32] " __VA_ARGS__); fputc('\n', stderr);} }while(0)

/* -------- Windows 命令列拼接 --------
 * 把 exe 路徑與 argv[1..] 轉成 Windows 期望的一整條命令列字串。
 * 規則要點（簡版）：
 * - 若參數含空白或引號，外層加雙引號。
 * - 位於引號前的連續反斜線要加倍；引號本身要以反斜線脫逸。
 */
static char* quote_argA(const char* s){
  int need_quote = 0;
  for(const char* p=s; *p; ++p){
    if(*p==' ' || *p=='\t' || *p=='"'){ need_quote = 1; break; }
  }
  size_t len = strlen(s);
  // worst case：每個字元都可能擴張（反斜線加倍 + 引號前加 \），再加上包住的 " 與 NUL
  size_t cap = len*2 + 3;
  char* out = (char*)malloc(cap);
  if(!out) return NULL;

  char* o = out;
  if(need_quote) *o++ = '"';

  size_t bs_count = 0;
  for(const char* p=s; *p; ++p){
    char c = *p;
    if(c == '\\'){
      bs_count++;
      *o++ = '\\';
    }else if(c == '"'){
      // 需要把前面的反斜線再加倍一次
      for(size_t i=0;i<bs_count;i++) *o++ = '\\';
      bs_count = 0;
      *o++ = '\\';  // escape the quote
      *o++ = '"';
    }else{
      bs_count = 0;
      *o++ = c;
    }
  }
  if(need_quote){
    // 結尾引號前的反斜線也要加倍
    if(bs_count){
      for(size_t i=0;i<bs_count;i++) *o++ = '\\';
    }
    *o++ = '"';
  }
  *o = '\0';
  return out;
}

static char* build_cmdlineA(const char* exe, char* const* argv){
  // 把 exe 當作第一個 token；argv 指向 main 的 argv，argv[0] 是 loader 自己，argv[1] 應是 exe 路徑（或我們的 path）
  // 這裡用我們 loader 確認的 exe 路徑 `exe` 作為第一個 token，之後接上 argv[2..]（若 argv[1] == exe）。
  // 為了安全起見，不假設 argv[1] 必定等於 exe；我們直接從 argv[2] 開始附加。
  char* qexe = quote_argA(exe);
  if(!qexe) return NULL;

  // 預估容量：先給一個適中緩衝，必要時擴張
  size_t cap = strlen(qexe) + 1 /*space or NUL*/ + 64;
  char* buf = (char*)malloc(cap);
  if(!buf){ free(qexe); return NULL; }
  strcpy(buf, qexe);
  free(qexe);

  // 將 argv 之中的其餘參數拼上去
  // 呼叫端會傳入 main 的 argv；假設 argv[0] = loader, argv[1] = exe, 從 argv[2] 起是被轉傳的參數
  // 若呼叫端用別的方式傳入，這裡仍然只是把 argv[1..] 全部接上去也可。
  int first = 1;
  for(char* const* ap = argv; *ap; ++ap){
    // 跳過 loader 自己與 exe 路徑重複（如果你在呼叫端傳的是 main 的 argv，建議這裡從 argv+2 起迭代）
    // 為了通用性，這裡簡化：從 argv[0] 開始，但跳過第一個（視為 loader 自己），並且若等於 exe 就跳過一次。
    if(first){ first = 0; continue; }
    if(strcmp(*ap, exe) == 0){ continue; }

    char* q = quote_argA(*ap);
    if(!q){ free(buf); return NULL; }

    size_t need = strlen(buf) + 1 /*space*/ + strlen(q) + 1 /*NUL*/;
    if(need > cap){
      cap = need + 64;
      char* nb = (char*)realloc(buf, cap);
      if(!nb){ free(q); free(buf); return NULL; }
      buf = nb;
    }
    strcat(buf, " ");
    strcat(buf, q);
    free(q);
  }
  return buf;
}

/* ...（此處省略：你原本的 PE 讀檔、對齊、重定位、IAT 綁定、進入點跳轉等實作）... */
/* 假設已有：extern struct Hook NT_HOOKS[]; 並在綁定時使用它們。 */

static int run_pe32(const char* path, char* const* argv){
  // ...（載入、重定位、綁定等過程）...

  // 構造 Windows 端看到的命令列
  char* cmdline = build_cmdlineA(path, argv);
  if(!cmdline){
    LOGF("build_cmdlineA failed");
    return -1;
  }
  // 將命令列交給 NT shim（A 版）
  nt_set_command_lineA(path, cmdline);

  // 設定目前執行緒的 TEB/TLS（必要）
  nt_teb_setup_for_current();

  // ...（跳轉到 PE entrypoint；執行；擷取退出碼等）...

  free(cmdline);
  return 0;
}

int main(int argc, char** argv){
  if(argc < 2){
    fprintf(stderr, "Usage: %s <pe32.exe> [args...]\n", argv[0]);
    return 1;
  }
  const char* path = argv[1];
  LOGF("loading %s", path);
  int rc = run_pe32(path, argv);
  return (rc == 0) ? 0 : 1;
}