#ifndef AWA_MINWIN_H
#define AWA_MINWIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 基本型別 */
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef int      BOOL;
typedef uint8_t  BYTE;
typedef BYTE*    LPBYTE;
typedef void*    PVOID;
typedef void*    LPVOID;
typedef const char* LPCSTR;
typedef char*       LPSTR;
typedef void     VOID;
typedef uint32_t UINT;
typedef uintptr_t SIZE_T;
typedef DWORD*   LPDWORD;
typedef void*    HANDLE;

#ifndef WINAPI
#  if defined(__i386__)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI
#  endif
#endif

/* 常數 */
#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

#define INFINITE       0xFFFFFFFFu
#define WAIT_OBJECT_0  0

/* 標準 I/O 句柄（Windows 宏值） */
#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

/* 結構：STARTUPINFOA / PROCESS_INFORMATION / SECURITY_ATTRIBUTES */
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* KERNEL32 最小 API 原型（我們在 shim 內提供實作/掛鉤） */
HANDLE  WINAPI GetStdHandle(DWORD nStdHandle);
BOOL    WINAPI WriteFile(HANDLE, const void*, DWORD, DWORD*, LPVOID);
BOOL    WINAPI ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
VOID    WINAPI ExitProcess(UINT code);

VOID    WINAPI GetStartupInfoA(LPSTARTUPINFOA);
BOOL    WINAPI CreateProcessA(
  LPCSTR appName, LPSTR cmdLine,
  LPSECURITY_ATTRIBUTES procAttr, LPSECURITY_ATTRIBUTES threadAttr,
  BOOL inheritHandles, DWORD flags, LPVOID env, LPCSTR cwd,
  LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi
);
DWORD   WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL    WINAPI GetExitCodeProcess(HANDLE, LPDWORD);
BOOL    WINAPI CloseHandle(HANDLE);
LPCSTR  WINAPI GetCommandLineA(void);

VOID    WINAPI SetLastError(DWORD);
DWORD   WINAPI GetLastError(void);

/* 執行緒 / TLS（最小子集） */
typedef DWORD (__attribute__((stdcall)) *LPTHREAD_START_ROUTINE)(LPVOID);
HANDLE  WINAPI CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
VOID    WINAPI ExitThread(DWORD);
VOID    WINAPI Sleep(DWORD);
DWORD   WINAPI GetCurrentThreadId(void);
DWORD   WINAPI TlsAlloc(void);
BOOL    WINAPI TlsFree(DWORD);
LPVOID  WINAPI TlsGetValue(DWORD);
BOOL    WINAPI TlsSetValue(DWORD, LPVOID);

#ifdef __cplusplus
}
#endif

#endif /* AWA_MINWIN_H */