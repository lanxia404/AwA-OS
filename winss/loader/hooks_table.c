// winss/loader/hooks_table.c
#include "../include/nt/hooks.h"     // struct Hook 定義 & 對外符號宣告
#include "../include/win/minwin.h"   // KERNEL32 API 原型（由我們的 shim 實作）

/* 這裡放你的 NT_HOOKS 陣列 */
const struct Hook NT_HOOKS[] = {
  { "KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle },
  { "KERNEL32.DLL", "ReadFile",            (void*)ReadFile },
  { "KERNEL32.DLL", "WriteFile",           (void*)WriteFile },
  { "KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA },
  { "KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA },
  { "KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess },
  { "KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA },
  { "KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle },
  { "KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject },
  { "KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess },
  { "KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc },
  { "KERNEL32.DLL", "TlsFree",             (void*)TlsFree },
  { "KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue },
  { "KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue },
  { "KERNEL32.DLL", "CreateThread",        (void*)CreateThread },
  { "KERNEL32.DLL", "ExitThread",          (void*)ExitThread },
  { "KERNEL32.DLL", "Sleep",               (void*)Sleep },
};
const size_t NT_HOOKS_COUNT = sizeof(NT_HOOKS) / sizeof(NT_HOOKS[0]);