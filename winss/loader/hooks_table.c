// winss/loader/hooks_table.c
#include <stddef.h>
#include "../include/nt/hooks.h"   // struct Hook
#include "../include/win/minwin.h" // WriteFile/ReadFile/... 的宣告

// 將 loader 要綁定到 IAT 的函式對應到我們在 ntshim32 裡的實作
// 注意：此表要以 {NULL,NULL,NULL} 結尾
const struct Hook NT_HOOKS[] = {
  { "KERNEL32.DLL", "WriteFile",           (void*)WriteFile           },
  { "KERNEL32.DLL", "ReadFile",            (void*)ReadFile            },
  { "KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle        },
  { "KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA      },
  { "KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess         },
  { "KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA     },
  { "KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA     },

  // 你先前連結報錯缺的三個：
  { "KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject },
  { "KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess  },
  { "KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle         },

  // TLS / Thread 相關（之後 TLS demo 會用到）
  { "KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc            },
  { "KERNEL32.DLL", "TlsFree",             (void*)TlsFree             },
  { "KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue         },
  { "KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue         },
  { "KERNEL32.DLL", "CreateThread",        (void*)CreateThread        },
  { "KERNEL32.DLL", "ExitThread",          (void*)ExitThread          },
  { "KERNEL32.DLL", "Sleep",               (void*)Sleep               },

  { NULL, NULL, NULL } // terminator
};