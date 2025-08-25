#pragma once
#include <stdint.h>

typedef uint32_t DWORD;
typedef int32_t BOOL;
typedef void* HANDLE;
typedef uint32_t UINT;
#ifndef WINAPI
#define WINAPI __attribute__((stdcall))
#endif
#define TRUE 1
#define FALSE 0
#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)
