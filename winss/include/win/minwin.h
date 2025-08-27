#pragma once
/* Minimal Win32 types & declarations for AwA-OS (i386) */

#include <stdint.h>
#include <stddef.h>

#ifndef __i386__
#  define WINAPI
#else
#  define WINAPI __attribute__((stdcall))
#endif

/* ---- 基本型別 ---------------------------------------------------------- */
typedef int             BOOL;
typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef unsigned int    DWORD;
typedef unsigned int    UINT;
typedef long            LONG;

typedef void*           HANDLE;
typedef void*           LPVOID;
typedef const void*     LPCVOID;
typedef char*           LPSTR;
typedef const char*     LPCSTR;
typedef DWORD*          LPDWORD;

/* ---- 常數 -------------------------------------------------------------- */
#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

#define INFINITE           0xFFFFFFFFu
#define WAIT_OBJECT_0      0x00000000u
#define STILL_ACTIVE       259u

/* ---- 結構 -------------------------------------------------------------- */
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
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* 只保留我們用得到的欄位（與 Win32 對齊足夠即可） */
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

/* ---- 函式原型（由 ntshim32 提供實作） ---------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

HANDLE  WINAPI GetStdHandle(DWORD nStdHandle);
BOOL    WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD len, LPDWORD rd, LPVOID ovlp);
BOOL    WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD wr, LPVOID ovlp);
VOID    WINAPI ExitProcess(UINT code);

VOID    WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
LPCSTR  WINAPI GetCommandLineA(void);

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
  LPPROCESS_INFORMATION lpProcessInformation);

DWORD   WINAPI WaitForSingleObject(HANDLE h, DWORD ms);
BOOL    WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code);
BOOL    WINAPI CloseHandle(HANDLE h);

VOID    WINAPI SetLastError(DWORD e);
DWORD   WINAPI GetLastError(void);

/* TLS（在 ntdll32/tls.c 裡有最小實作） */
DWORD   WINAPI TlsAlloc(void);
BOOL    WINAPI TlsFree(DWORD idx);
LPVOID  WINAPI TlsGetValue(DWORD idx);
BOOL    WINAPI TlsSetValue(DWORD idx, LPVOID val);

#ifdef __cplusplus
}
#endif