// winss/include/win/minwin.h
// Minimal Win32 header subset for AwA-OS shim (32-bit)
// Enough to build our ntdll/ntshim/loader components on gcc -m32.

#ifndef AWAOS_MINWIN_H
#define AWAOS_MINWIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Basic calling convention / visibility ----- */
#ifndef WINAPI
#  if defined(__i386__) || defined(__i386) || defined(_M_IX86)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI
#  endif
#endif

/* ----- Basic types ----- */
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        UINT;
typedef int                 BOOL;
typedef unsigned int        DWORD;
typedef unsigned long       ULONG;
typedef long                LONG;

typedef void                VOID;
typedef void*               PVOID;
typedef void*               LPVOID;
typedef const void*         LPCVOID;

typedef char*               LPSTR;
typedef const char*         LPCSTR;

typedef unsigned int*       LPDWORD;

/* Handles */
typedef void*               HANDLE;
typedef HANDLE*             LPHANDLE;

/* Security attributes (minimal) */
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* STARTUPINFOA (minimal) */
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
  BYTE*  lpReserved2;      /* LPBYTE */
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

/* PROCESS_INFORMATION (minimal) */
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

/* Thread proc prototype */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* Size type */
typedef unsigned long       SIZE_T;

/* ----- Win32 constants we use ----- */
/* GetStdHandle */
#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

/* Wait / timing */
#define INFINITE           (0xFFFFFFFFu)
#define WAIT_OBJECT_0      (0x00000000u)
#define WAIT_TIMEOUT       (0x00000102u)
#define WAIT_FAILED        (0xFFFFFFFFu)

/* Process state */
#define STILL_ACTIVE       (0x00000103u)

/* BOOL values */
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

/* ----- Kernel32 A subset: function prototypes ----- */
LPCSTR WINAPI GetCommandLineA(void);

VOID   WINAPI GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
VOID   WINAPI ExitProcess(UINT uExitCode);

VOID   WINAPI SetLastError(DWORD dwErrCode);
DWORD  WINAPI GetLastError(void);

HANDLE WINAPI GetStdHandle(DWORD nStdHandle);

BOOL   WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                       LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped);
BOOL   WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                        LPDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped);

HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                           SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress,
                           LPVOID lpParameter,
                           DWORD dwCreationFlags,
                           LPDWORD lpThreadId);
VOID   WINAPI   ExitThread(DWORD dwExitCode);
VOID   WINAPI   Sleep(DWORD dwMilliseconds);
DWORD  WINAPI   WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL   WINAPI   GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
BOOL   WINAPI   CloseHandle(HANDLE hObject);

#ifdef __cplusplus
}
#endif
#endif /* AWAOS_MINWIN_H */