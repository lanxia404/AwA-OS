// winss/loader/hooks_table.c
#include <stddef.h>
#include "../include/win/minwin.h"  // 我們的迷你 Win32 型別/原型
#include "../include/nt/hooks.h"    // struct Hook 與 NT_HOOKS 的 extern 宣告

// 不再重複前置宣告，全部由 minwin.h 提供

const struct Hook NT_HOOKS[] = {
  /* I/O */
  { "KERNEL32.DLL", "WriteFile",           (void*)WriteFile           },
  { "KERNEL32.DLL", "ReadFile",            (void*)ReadFile            },
  { "KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle        },

  /* Process / startup */
  { "KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA      },
  { "KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess         },
  { "KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA     },
  { "KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA     },

  /* Wait / exit / handle */
  { "KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject },
  { "KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess  },
  { "KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle         },

  /* TLS */
  { "KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc            },
  { "KERNEL32.DLL", "TlsFree",             (void*)TlsFree             },
  { "KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue         },
  { "KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue         },

  /* Threads */
  { "KERNEL32.DLL", "CreateThread",        (void*)CreateThread        },
  { "KERNEL32.DLL", "ExitThread",          (void*)ExitThread          },
  { "KERNEL32.DLL", "Sleep",               (void*)Sleep               },

  { NULL, NULL, NULL } // terminator
};