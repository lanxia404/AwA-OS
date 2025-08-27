#pragma once
/* Minimal Win32 subset for AwA-OS build (i386) */

#include <stdint.h>
#include <stddef.h>

#ifndef WINAPI
#  define WINAPI __attribute__((stdcall))
#endif

/* ----- 基本型別 ----- */
#ifndef VOID
#  define VOID void
#endif

typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint32_t  DWORD;
typedef unsigned  UINT;
typedef int       BOOL;

typedef void*       HANDLE;
typedef void*       LPVOID;
typedef const void* LPCVOID;

typedef BYTE*    LPBYTE;
typedef DWORD*   LPDWORD;
typedef uintptr_t SIZE_T;

#ifndef TRUE
#  define TRUE  1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

/* ----- 常數 ----- */
#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

#define INFINITE  0xFFFFFFFFu

/* ----- 結構 ----- */
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

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
  LPBYTE lpReserved2;   /* 先前編譯錯就卡在這個型別 */
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

/* 執行緒起始函式型別（Win32） */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* ----- KERNEL32 匯入 API（宣告） ----- */
/* error handling */
VOID  WINAPI SetLastError(DWORD dwErrCode);
DWORD WINAPI GetLastError(void);

/* process & cmdline */
VOID  WINAPI ExitProcess(UINT uExitCode);
VOID  WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
BOOL  WINAPI CreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR  lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL  WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
BOOL  WINAPI CloseHandle(HANDLE hObject);
LPCSTR WINAPI GetCommandLineA(void);

/* std handles & I/O */
HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
BOOL   WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                       LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped);
BOOL   WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                        LPDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped);

/* threads & TLS */
HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                           SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress,
                           LPVOID lpParameter,
                           DWORD dwCreationFlags,
                           LPDWORD lpThreadId);
VOID   WINAPI ExitThread(DWORD dwExitCode);
VOID   WINAPI Sleep(DWORD dwMilliseconds);
DWORD  WINAPI GetCurrentThreadId(void);

DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD dwTlsIndex);
LPVOID WINAPI TlsGetValue(DWORD dwTlsIndex);
BOOL   WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);

/* ----- 方便的別名（C-only）：LPCSTR/LPSTR ----- */
#ifndef _INC_WINDOWS_LPCSTR
typedef const char* LPCSTR;
typedef char*       LPSTR;
#endif