// winss/include/win/minwin.h
#pragma once

#include <stdint.h>
#include <stddef.h>

/* --- calling convention -------------------------------------------------- */
#if defined(__i386__) || defined(_M_IX86)
#  define WINAPI __attribute__((stdcall))
#else
#  define WINAPI
#endif

/* --- base types ---------------------------------------------------------- */
typedef void                VOID;
typedef uint8_t             BYTE, *PBYTE, *LPBYTE;
typedef uint16_t            WORD, *PWORD, *LPWORD;
typedef uint32_t            DWORD, *PDWORD, *LPDWORD;
typedef int32_t             BOOL;
typedef uintptr_t           SIZE_T;

typedef void*               HANDLE;
typedef void*               LPVOID;
typedef const void*         LPCVOID;

typedef char*               LPSTR;
typedef const char*         LPCSTR;

typedef wchar_t             WCHAR, *PWCHAR, *LPWSTR;
typedef const wchar_t*      LPCWSTR;

#ifndef TRUE
#  define TRUE  1
#  define FALSE 0
#endif

#ifndef NULL
#  define NULL ((void*)0)
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

/* --- useful constants ---------------------------------------------------- */
#ifndef INFINITE
#  define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_FAILED
#  define WAIT_FAILED 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#  define WAIT_OBJECT_0 0x00000000u
#endif

/* standard handle ids (used by some sample code) */
#ifndef STD_INPUT_HANDLE
#  define STD_INPUT_HANDLE  ((DWORD)-10)
#  define STD_OUTPUT_HANDLE ((DWORD)-11)
#  define STD_ERROR_HANDLE  ((DWORD)-12)
#endif

/* --- structs ------------------------------------------------------------- */
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);
typedef LPTHREAD_START_ROUTINE PTHREAD_START_ROUTINE;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

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

/* --- kernel32-style APIs we reference ----------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

VOID   WINAPI ExitProcess(DWORD);
BOOL   WINAPI CloseHandle(HANDLE);
VOID   WINAPI GetStartupInfoA(LPSTARTUPINFOA);
LPCSTR WINAPI GetCommandLineA(void);

BOOL   WINAPI CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,          /* 可為 NULL */
  LPSECURITY_ATTRIBUTES lpProcessAttributes,    /* 可為 NULL */
  LPSECURITY_ATTRIBUTES lpThreadAttributes,     /* 可為 NULL */
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,          /* 可為 NULL */
  LPCSTR                lpCurrentDirectory,     /* 可為 NULL */
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

DWORD  WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL   WINAPI GetExitCodeProcess(HANDLE, LPDWORD);

/* I/O */
BOOL   WINAPI ReadFile (HANDLE, LPVOID,  DWORD, LPDWORD, LPVOID);
BOOL   WINAPI WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);

/* TLS / threads (provided by our shim) */
DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD);
LPVOID WINAPI TlsGetValue(DWORD);
BOOL   WINAPI TlsSetValue(DWORD, LPVOID);

HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T,
                           LPTHREAD_START_ROUTINE, LPVOID,
                           DWORD, LPDWORD);
VOID   WINAPI ExitThread(DWORD);
VOID   WINAPI Sleep(DWORD);

#ifdef __cplusplus
}
#endif