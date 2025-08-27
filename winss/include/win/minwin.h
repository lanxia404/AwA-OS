// winss/include/win/minwin.h
#ifndef AWAOS_MINWIN_H
#define AWAOS_MINWIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- calling convention/macros ----- */
#ifndef WINAPI
# define WINAPI __attribute__((stdcall))
#endif
#ifndef CALLBACK
# define CALLBACK __attribute__((stdcall))
#endif
#ifndef __stdcall
# define __stdcall __attribute__((stdcall))
#endif

/* ----- base types ----- */
typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint32_t  DWORD;
typedef int32_t   BOOL;
typedef unsigned int UINT;
typedef void      VOID;

typedef void*     HANDLE;
typedef void*     LPVOID;
typedef const void* LPCVOID;

typedef char*     LPSTR;
typedef const char* LPCSTR;
typedef BYTE*     LPBYTE;

typedef DWORD*    LPDWORD;
typedef size_t    SIZE_T;

typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

/* ----- constants ----- */
#ifndef INFINITE
# define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
# define WAIT_OBJECT_0 0
#endif
#ifndef WAIT_TIMEOUT
# define WAIT_TIMEOUT 258
#endif
#ifndef STILL_ACTIVE
# define STILL_ACTIVE 259 /* 0x103 */
#endif

/* Standard handle ids are negative DWORDs on Win32 */
#ifndef STD_INPUT_HANDLE
# define STD_INPUT_HANDLE  ((DWORD)-10)
# define STD_OUTPUT_HANDLE ((DWORD)-11)
# define STD_ERROR_HANDLE  ((DWORD)-12)
#endif

#ifndef INVALID_HANDLE_VALUE
# define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#endif

/* ----- structs ----- */
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

/* ----- minimal KERNEL32 prototypes we implement ----- */
/* I/O */
BOOL   WINAPI WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
BOOL   WINAPI ReadFile(HANDLE,  LPVOID,  DWORD, LPDWORD, LPVOID);
HANDLE WINAPI GetStdHandle(DWORD);

/* Process / startup */
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
VOID   WINAPI ExitProcess(UINT uExitCode);
VOID   WINAPI GetStartupInfoA(LPSTARTUPINFOA psi);
LPCSTR WINAPI GetCommandLineA(void);

/* Wait / exit / handle */
DWORD  WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL   WINAPI GetExitCodeProcess(HANDLE, LPDWORD);
BOOL   WINAPI CloseHandle(HANDLE);

/* TLS */
DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD);
LPVOID WINAPI TlsGetValue(DWORD);
BOOL   WINAPI TlsSetValue(DWORD, LPVOID);

/* Threads */
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

/* Error APIs */
VOID   WINAPI SetLastError(DWORD dwErrCode);
DWORD  WINAPI GetLastError(void);

#ifdef __cplusplus
}
#endif
#endif /* AWAOS_MINWIN_H */