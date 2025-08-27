#pragma once
#include <stdint.h>
#include <stddef.h>

#ifndef WINAPI
# if defined(__i386__)
#  define WINAPI __attribute__((stdcall))
# else
#  define WINAPI
# endif
#endif

typedef uint32_t DWORD; typedef int32_t BOOL; typedef uint16_t WORD; typedef unsigned char BYTE;
typedef void* HANDLE; typedef void* HMODULE; typedef void* FARPROC;
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif
#ifndef LPVOID
typedef void* LPVOID;
#endif
#ifndef LPDWORD
typedef DWORD* LPDWORD;
#endif
#ifndef LPBYTE
typedef BYTE* LPBYTE;
#endif
#ifndef LPCVOID
typedef const void* LPCVOID;
#endif
typedef char* LPSTR; typedef const char* LPCSTR;
typedef unsigned short WCHAR; typedef WCHAR* LPWSTR; typedef const WCHAR* LPCWSTR;
#ifndef SIZE_T
# define SIZE_T size_t
#endif
#ifndef UINT
typedef unsigned int UINT;
#endif

#ifndef STD_INPUT_HANDLE
# define STD_INPUT_HANDLE  ((DWORD)-10)
# define STD_OUTPUT_HANDLE ((DWORD)-11)
# define STD_ERROR_HANDLE  ((DWORD)-12)
#endif

#ifndef INFINITE
# define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
# define WAIT_OBJECT_0 0u
#endif
#ifndef WAIT_TIMEOUT
# define WAIT_TIMEOUT 0x00000102u
#endif
#ifndef WAIT_FAILED
# define WAIT_FAILED 0xFFFFFFFFu
#endif
#ifndef STILL_ACTIVE
# define STILL_ACTIVE 259u
#endif

#ifndef FILE_TYPE_UNKNOWN
# define FILE_TYPE_UNKNOWN 0x0000
# define FILE_TYPE_DISK    0x0001
# define FILE_TYPE_CHAR    0x0002
# define FILE_TYPE_PIPE    0x0003
#endif

typedef struct _STARTUPINFOA {
  DWORD cb; LPSTR lpReserved, lpDesktop, lpTitle;
  DWORD dwX, dwY, dwXSize, dwYSize;
  DWORD dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
  WORD wShowWindow, cbReserved2; LPBYTE lpReserved2;
  HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOA;

typedef struct _STARTUPINFOW {
  DWORD cb; LPWSTR lpReserved, lpDesktop, lpTitle;
  DWORD dwX, dwY, dwXSize, dwYSize;
  DWORD dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
  WORD wShowWindow, cbReserved2; LPBYTE lpReserved2;
  HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOW;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId;
} PROCESS_INFORMATION;

/* KERNEL32 */
HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
BOOL   WINAPI SetStdHandle(DWORD nStdHandle, HANDLE h);
BOOL   WINAPI ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
BOOL   WINAPI WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
__attribute__((noreturn)) void WINAPI ExitProcess(UINT);

BOOL   WINAPI WriteConsoleA(HANDLE, const char*, DWORD, LPDWORD, LPVOID);
BOOL   WINAPI ReadConsoleA (HANDLE, char*,       DWORD, LPDWORD, LPVOID);

BOOL   WINAPI FlushFileBuffers(HANDLE);
DWORD  WINAPI GetFileType(HANDLE);
BOOL   WINAPI GetConsoleMode(HANDLE, LPDWORD);
BOOL   WINAPI SetConsoleMode(HANDLE, DWORD);
void   WINAPI GetStartupInfoA(STARTUPINFOA*);
void   WINAPI GetStartupInfoW(STARTUPINFOW*);

BOOL   WINAPI CreateProcessA(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, STARTUPINFOA*, PROCESS_INFORMATION*);
BOOL   WINAPI CreateProcessW(LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR, STARTUPINFOW*, PROCESS_INFORMATION*);

DWORD  WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL   WINAPI GetExitCodeProcess(HANDLE, LPDWORD);
BOOL   WINAPI CloseHandle(HANDLE);

LPCSTR  WINAPI GetCommandLineA(void);
LPCWSTR WINAPI GetCommandLineW(void);

HMODULE WINAPI GetModuleHandleA(LPCSTR);
HMODULE WINAPI GetModuleHandleW(LPCWSTR);
FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);

/* Threads & TLS（由 ntdll32 實作） */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);
HANDLE WINAPI CreateThread(LPVOID, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
void   WINAPI ExitThread(DWORD);
DWORD  WINAPI GetCurrentThreadId(void);
void   WINAPI Sleep(DWORD);

DWORD  WINAPI TlsAlloc(void);
BOOL   WINAPI TlsFree(DWORD);
BOOL   WINAPI TlsSetValue(DWORD, LPVOID);
LPVOID WINAPI TlsGetValue(DWORD);

DWORD WINAPI GetLastError(void);
void  WINAPI SetLastError(DWORD);