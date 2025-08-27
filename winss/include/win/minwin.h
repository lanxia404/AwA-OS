#ifndef AWA_MINWIN_H
#define AWA_MINWIN_H

/* Minimal Win32 type & API surface for AwA-OS (i386) */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 基本型別 ---- */
typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint32_t  DWORD;
typedef int32_t   LONG;
typedef uint32_t  UINT;
typedef size_t    SIZE_T;
typedef int       BOOL;

#ifndef TRUE
#  define TRUE  1
#  define FALSE 0
#endif

/* ---- 指標／文字別名 ---- */
typedef void*        HANDLE;
typedef void*        PVOID;
typedef void*        LPVOID;
typedef const void*  LPCVOID;
typedef char*        LPSTR;
typedef const char*  LPCSTR;
typedef DWORD*       LPDWORD;

/* ---- 呼叫慣例 ---- */
#ifndef WINAPI
# if defined(__GNUC__) && (defined(__i386__) || defined(_M_IX86))
#   define WINAPI __attribute__((stdcall))
# else
#   define WINAPI
# endif
#endif

#ifndef VOID
typedef void VOID;
#endif

/* ---- 常數 ---- */
#ifndef INFINITE
# define INFINITE        0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
# define WAIT_OBJECT_0   0u
#endif

/* Windows Console 標準句柄常數（以數值表示，AwA 以此映射到 0/1/2） */
#ifndef STD_INPUT_HANDLE
# define STD_INPUT_HANDLE   ((DWORD)-10)
# define STD_OUTPUT_HANDLE  ((DWORD)-11)
# define STD_ERROR_HANDLE   ((DWORD)-12)
#endif

/* ---- Thread Proc ---- */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* ---- 結構 ---- */
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
} STARTUPINFOA, *PSTARTUPINFOA, *LPSTARTUPINFOA;  /* ← 補齊 LPSTARTUPINFOA 別名 */

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION; /* ← 補齊 LPPROCESS_INFORMATION */

/* ---- KERNEL32 API 原型（本專案最小需求） ---- */

/* console I/O */
HANDLE  WINAPI GetStdHandle(DWORD nStdHandle);
BOOL    WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                         LPDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped);
BOOL    WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                        LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped);

/* process */
VOID    WINAPI ExitProcess(UINT uExitCode);
VOID    WINAPI GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
LPCSTR  WINAPI GetCommandLineA(void);
BOOL    WINAPI CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                              LPVOID lpProcessAttributes, LPVOID lpThreadAttributes,
                              BOOL bInheritHandles, DWORD dwCreationFlags,
                              LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
                              LPSTARTUPINFOA lpStartupInfo,
                              LPPROCESS_INFORMATION lpProcessInformation);
DWORD   WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL    WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
BOOL    WINAPI CloseHandle(HANDLE hObject);

/* error */
VOID    WINAPI SetLastError(DWORD dwErrCode);
DWORD   WINAPI GetLastError(void);

/* threads (由 ntdll32/thread.c 提供實作，這裡只宣告) */
HANDLE  WINAPI CreateThread(LPVOID lpThreadAttributes, SIZE_T dwStackSize,
                            LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                            DWORD dwCreationFlags, LPDWORD lpThreadId);
VOID    WINAPI ExitThread(DWORD dwExitCode);
VOID    WINAPI Sleep(DWORD dwMilliseconds);
DWORD   WINAPI GetCurrentThreadId(void);

/* TLS (由 ntdll32/tls.c 提供實作，這裡只宣告) */
DWORD   WINAPI TlsAlloc(void);
BOOL    WINAPI TlsFree(DWORD dwTlsIndex);
LPVOID  WINAPI TlsGetValue(DWORD dwTlsIndex);
BOOL    WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);

#ifdef __cplusplus
}
#endif
#endif /* AWA_MINWIN_H */