#pragma once
#include <stdint.h>
#include <stddef.h>

/* --- 基本 Windows 風格型別/巨集（最小集合） --- */

#ifndef WINAPI
#  if defined(__i386__)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI /* ignored on non-i386 */
#  endif
#endif

typedef uint32_t DWORD;
typedef int32_t  BOOL;
typedef uint16_t WORD;
typedef unsigned char BYTE;

#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

typedef void*   HANDLE;

#ifndef LPVOID
typedef void*   LPVOID;
#endif
#ifndef LPDWORD
typedef DWORD*  LPDWORD;
#endif
#ifndef LPBYTE
typedef BYTE*   LPBYTE;
#endif

typedef char*       LPSTR;
typedef const char* LPCSTR;

/* 注意：為了相容 Windows 寬字元，我們讓 WCHAR=16-bit */
typedef unsigned short WCHAR;
typedef WCHAR*       LPWSTR;
typedef const WCHAR* LPCWSTR;

#ifndef UINT
typedef unsigned int UINT;
#endif

/* 標準 Handle 常數 */
#ifndef STD_INPUT_HANDLE
#  define STD_INPUT_HANDLE  ((DWORD)-10)
#  define STD_OUTPUT_HANDLE ((DWORD)-11)
#  define STD_ERROR_HANDLE  ((DWORD)-12)
#endif

/* Wait/Process 常數 */
#ifndef INFINITE
#  define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#  define WAIT_OBJECT_0 0u
#endif
#ifndef WAIT_TIMEOUT
#  define WAIT_TIMEOUT 0x00000102u
#endif
#ifndef WAIT_FAILED
#  define WAIT_FAILED 0xFFFFFFFFu
#endif
#ifndef STILL_ACTIVE
#  define STILL_ACTIVE 259u
#endif

/* 最小 STARTUPINFO/PROCESS_INFORMATION 結構（欄位未必皆使用） */
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

typedef struct _STARTUPINFOW {
  DWORD cb;
  LPWSTR lpReserved;
  LPWSTR lpDesktop;
  LPWSTR lpTitle;
  DWORD dwX, dwY, dwXSize, dwYSize;
  DWORD dwXCountChars, dwYCountChars, dwFillAttribute;
  DWORD dwFlags;
  WORD  wShowWindow;
  WORD  cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOW;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION;#endif
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
