// winss/loader/hooks_table.c
#include <stddef.h>
#include "../include/win/minwin.h"   // 基本 Win32 型別與 WINAPI

// ---- 前置宣告（extern prototypes）---------------------------------
// I/O
BOOL   WINAPI WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
BOOL   WINAPI ReadFile(HANDLE,  LPVOID,  DWORD, LPDWORD, LPVOID);
HANDLE WINAPI GetStdHandle(DWORD);

// Process / startup
BOOL   WINAPI CreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR  lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL   bInheritHandles,
  DWORD  dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
VOID   WINAPI ExitProcess(UINT code);
VOID   WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
LPCSTR WINAPI GetCommandLineA(void);

// Wait/exit/handle
DWORD  WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL   WINAPI GetExitCodeProcess(HANDLE, LPDWORD);
BOOL   WINAPI CloseHandle(HANDLE);

// TLS / Thread
DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD);
LPVOID WINAPI TlsGetValue(DWORD);
BOOL   WINAPI TlsSetValue(DWORD, LPVOID);

HANDLE WINAPI CreateThread(
  LPSECURITY_ATTRIBUTES,
  SIZE_T,
  LPTHREAD_START_ROUTINE,
  LPVOID,
  DWORD,
  LPDWORD
);
VOID   WINAPI ExitThread(DWORD);
VOID   WINAPI Sleep(DWORD);

// ---- Hook 表（唯一實體定義）---------------------------------------
#include "../include/nt/hooks.h"     // struct Hook 與 extern 宣告

const struct Hook NT_HOOKS[] = {
  { "KERNEL32.DLL", "WriteFile",           (void*)WriteFile           },
  { "KERNEL32.DLL", "ReadFile",            (void*)ReadFile            },
  { "KERNEL32.DLL", "GetStdHandle",        (void*)GetStdHandle        },

  { "KERNEL32.DLL", "CreateProcessA",      (void*)CreateProcessA      },
  { "KERNEL32.DLL", "ExitProcess",         (void*)ExitProcess         },
  { "KERNEL32.DLL", "GetStartupInfoA",     (void*)GetStartupInfoA     },
  { "KERNEL32.DLL", "GetCommandLineA",     (void*)GetCommandLineA     },

  { "KERNEL32.DLL", "WaitForSingleObject", (void*)WaitForSingleObject },
  { "KERNEL32.DLL", "GetExitCodeProcess",  (void*)GetExitCodeProcess  },
  { "KERNEL32.DLL", "CloseHandle",         (void*)CloseHandle         },

  { "KERNEL32.DLL", "TlsAlloc",            (void*)TlsAlloc            },
  { "KERNEL32.DLL", "TlsFree",             (void*)TlsFree             },
  { "KERNEL32.DLL", "TlsGetValue",         (void*)TlsGetValue         },
  { "KERNEL32.DLL", "TlsSetValue",         (void*)TlsSetValue         },

  { "KERNEL32.DLL", "CreateThread",        (void*)CreateThread        },
  { "KERNEL32.DLL", "ExitThread",          (void*)ExitThread          },
  { "KERNEL32.DLL", "Sleep",               (void*)Sleep               },

  { NULL, NULL, NULL } // terminator
};