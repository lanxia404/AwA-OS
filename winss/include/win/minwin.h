#pragma once
/* Minimal Win32 type and API declarations used by AwA-OS userland shims. */
#include <stdint.h>
#include <stddef.h>

#ifdef __i386__
#  define WINAPI __attribute__((stdcall))
#else
#  define WINAPI
#endif

/* ---- basic Win32-style types ---- */
typedef void            VOID;
typedef uint8_t         BYTE;
typedef uint16_t        WORD;
typedef uint32_t        DWORD;
typedef int             BOOL;
typedef uint32_t        UINT;
typedef size_t          SIZE_T;

#ifndef TRUE
#  define TRUE  1
#  define FALSE 0
#endif

typedef void*           HANDLE;
typedef void*           LPVOID;
typedef const void*     LPCVOID;

typedef char*           LPSTR;
typedef const char*     LPCSTR;

typedef BYTE*           LPBYTE;
typedef DWORD*          LPDWORD;

/* security attributes (minimal) */
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* STARTUPINFOA (fields as per docs; only A-variant needed here) */
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

/* PROCESS_INFORMATION */
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

/* thread start prototype */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* ---- KERNEL32 subset we shim ---- */
/* process / startup */
VOID   WINAPI ExitProcess(UINT code);
VOID   WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
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
  LPPROCESS_INFORMATION lpProcessInformation);

/* threads & timing */
HANDLE WINAPI CreateThread(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T                dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                lpParameter,
  DWORD                 dwCreationFlags,
  LPDWORD               lpThreadId);

VOID   WINAPI ExitThread(DWORD dwExitCode);
VOID   WINAPI Sleep(DWORD dwMilliseconds);

/* io */
BOOL   WINAPI ReadFile (HANDLE h, LPVOID  buf, DWORD len, LPDWORD rd, LPVOID ovlp);
BOOL   WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD wr, LPVOID ovlp);

/* sync & process info */
DWORD  WINAPI WaitForSingleObject(HANDLE h, DWORD ms);
BOOL   WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD code);
BOOL   WINAPI CloseHandle(HANDLE hObject);

/* errors */
VOID   WINAPI SetLastError(DWORD e);
DWORD  WINAPI GetLastError(void);

/* command line */
LPCSTR WINAPI GetCommandLineA(void);

/* TLS */
DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD idx);
LPVOID WINAPI TlsGetValue(DWORD idx);
BOOL   WINAPI TlsSetValue(DWORD idx, LPVOID val);