#pragma once
#include <stdint.h>

typedef uint32_t DWORD;
typedef int32_t BOOL;
typedef void* HANDLE;
typedef uint32_t UINT;
#ifndef WINAPI
#define WINAPI __attribute__((stdcall))
#endif
#define TRUE 1
#define FALSE 0
#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)

/* 基本指標型別（如你已有可略） */
#ifndef LPVOID
typedef void* LPVOID;
#endif
#ifndef LPDWORD
typedef DWORD* LPDWORD;
#endif
#ifndef LPSTR
typedef char* LPSTR;
#endif
#ifndef LPCSTR
typedef const char* LPCSTR;
#endif
#ifndef UINT
typedef unsigned int UINT;
#endif

/* 等待/常數 */
#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0u
#endif
#ifndef STILL_ACTIVE
#define STILL_ACTIVE 259u
#endif

/* 最小結構定義（CreateProcessA 用；欄位暫不使用但需存在） */
typedef struct _STARTUPINFOA {
  DWORD cb;
  LPSTR lpReserved;
  LPSTR lpDesktop;
  LPSTR lpTitle;
  DWORD dwX, dwY, dwXSize, dwYSize;
  DWORD dwXCountChars, dwYCountChars, dwFillAttribute;
  DWORD dwFlags;
  WORD  wShowWindow;
  WORD  cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;      /* 未用 */
  DWORD  dwProcessId;
  DWORD  dwThreadId;   /* 未用 */
} PROCESS_INFORMATION;
