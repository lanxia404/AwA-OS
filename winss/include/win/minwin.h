// winss/include/win/minwin.h
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __GNUC__
  #define WINAPI __attribute__((stdcall))
#else
  #define WINAPI
#endif
#ifndef APIENTRY
  #define APIENTRY WINAPI
#endif

/* ===== 基本整數 / 指標型別 ===== */
typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef int32_t   BOOL;
typedef uint32_t  UINT;
typedef uint32_t  DWORD;
typedef uint32_t  ULONG;
typedef int32_t   LONG;
typedef uint32_t  SIZE_T;

typedef void*       HANDLE;
typedef void*       LPVOID;
typedef const void* LPCVOID;
typedef char*       LPSTR;
typedef const char* LPCSTR;
typedef BYTE*       LPBYTE;
typedef DWORD*      LPDWORD;

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif

/* ===== 句柄/等待/錯誤 常數 ===== */
#ifndef INVALID_HANDLE_VALUE
  #define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#endif

/* GetStdHandle 常量（與 Win32 一致） */
#ifndef STD_INPUT_HANDLE
  #define STD_INPUT_HANDLE  ((DWORD)-10)
  #define STD_OUTPUT_HANDLE ((DWORD)-11)
  #define STD_ERROR_HANDLE  ((DWORD)-12)
#endif

/* 等待/超時/常用返回值 */
#ifndef WAIT_OBJECT_0
  #define WAIT_OBJECT_0 0x00000000u
#endif
#ifndef WAIT_TIMEOUT
  #define WAIT_TIMEOUT  0x00000102u
#endif
#ifndef WAIT_FAILED
  #define WAIT_FAILED   0xFFFFFFFFu
#endif
#ifndef INFINITE
  #define INFINITE      0xFFFFFFFFu
#endif

/* Process 狀態 */
#ifndef STILL_ACTIVE
  #define STILL_ACTIVE  0x00000103u
#endif

/* CreateProcess/StartupInfo 旗標（常用子集） */
#ifndef STARTF_USESHOWWINDOW
  #define STARTF_USESHOWWINDOW   0x00000001
#endif
#ifndef STARTF_USESTDHANDLES
  #define STARTF_USESTDHANDLES   0x00000100
#endif

/* 常見錯誤碼（子集，足夠目前專案） */
#ifndef ERROR_SUCCESS
  #define ERROR_SUCCESS              0
#endif
#ifndef ERROR_FILE_NOT_FOUND
  #define ERROR_FILE_NOT_FOUND       2
#endif
#ifndef ERROR_NOT_ENOUGH_MEMORY
  #define ERROR_NOT_ENOUGH_MEMORY    8
#endif
#ifndef ERROR_INVALID_HANDLE
  #define ERROR_INVALID_HANDLE       6
#endif

/* ===== 結構 ===== */
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* Windows OVERLAPPED（我們目前不使用欄位，只為型別相容） */
typedef struct _OVERLAPPED {
  ULONG  Internal;
  ULONG  InternalHigh;
  union { struct { DWORD Offset; DWORD OffsetHigh; }; void* Pointer; };
  HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

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
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

/* 執行緒起始函式型別 */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* ===== KERNEL32 介面（我們的 shim 會提供實作）===== */
#ifdef __cplusplus
extern "C" {
#endif

/* Console / I/O */
HANDLE  WINAPI GetStdHandle(DWORD nStdHandle);
BOOL    WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                        LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped); /* 允許 NULL */
BOOL    WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                         LPDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped); /* 允許 NULL */
BOOL    WINAPI CloseHandle(HANDLE hObject);

/* Process 基本 */
BOOL    WINAPI CreateProcessA(
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
VOID    WINAPI ExitProcess(UINT uExitCode);
VOID    WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
LPCSTR  WINAPI GetCommandLineA(void);

/* 等待 / 程序狀態 */
DWORD   WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL    WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);

/* 執行緒 / 睡眠 */
HANDLE  WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                            SIZE_T dwStackSize,
                            LPTHREAD_START_ROUTINE lpStartAddress,
                            LPVOID lpParameter,
                            DWORD  dwCreationFlags,
                            LPDWORD lpThreadId);
VOID    WINAPI ExitThread(DWORD dwExitCode);
VOID    WINAPI Sleep(DWORD dwMilliseconds);

/* TLS */
DWORD   WINAPI TlsAlloc(void);
BOOL    WINAPI TlsFree(DWORD dwTlsIndex);
LPVOID  WINAPI TlsGetValue(DWORD dwTlsIndex);
BOOL    WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);

/* Error */
VOID    WINAPI SetLastError(DWORD dwErrCode);
DWORD   WINAPI GetLastError(void);

#ifdef __cplusplus
}
#endif