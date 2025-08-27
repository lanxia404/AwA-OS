// winss/ntdll32/thread.h
#pragma once
#include "../include/win/minwin.h"

#ifdef __cplusplus
extern "C" {
#endif

// 僅供內部使用的執行緒 handle 小工具，由 ntdll32/thread.c 定義
int   _nt_is_thread_handle(HANDLE h);
void  _nt_close_thread(HANDLE h);
DWORD _nt_wait_thread(HANDLE h, DWORD ms);
BOOL  _nt_get_thread_exit_code(HANDLE h, LPDWORD out);

#ifdef __cplusplus
}
#endif