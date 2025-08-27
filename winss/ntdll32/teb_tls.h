#pragma once
/* Minimal NT-style TEB/TLS declarations used by AwA-OS Win32 personality (i386)
 *
 * Implementations are在 winss/ntdll32/{teb.c,tls.c,error.c,thread.c}
 * 本標頭只提供需要對外被 loader/ntshim 使用到的宣告。
 */

#include "../include/win/minwin.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- TEB 近似結構（僅包含我們會用到的欄位） --- */
typedef struct _NT_TEB {
    void*  Self;         /* FS:[0x18] 一般會放自指针；我們只保留語義，用於自檢 */
    DWORD  LastError;    /* GetLastError / SetLastError 使用 */
    DWORD  ThreadId;     /* 目前執行緒 ID（簡化版） */
    void*  TlsSlots[64]; /* 最小 TLS 槽；真實 Windows 為 108+，此處先保留 64 */
} NT_TEB;

/* 取得目前執行緒的 TEB 指標；定義在 teb.c */
NT_TEB* __attribute__((visibility("default"))) NtCurrentTeb(void);

/* 設定目前執行緒的 TEB/FS，讓 FS: 基底正確指向 TEB；定義在 teb.c */
void __attribute__((visibility("default"))) _nt_teb_setup_for_current(void);

/* ---- Error API（error.c） ---- */
VOID  __attribute__((visibility("default"))) SetLastError(DWORD e);
DWORD __attribute__((visibility("default"))) GetLastError(void);

/* ---- TLS API（tls.c） ---- */
DWORD __attribute__((visibility("default"))) TlsAlloc(void);
BOOL  __attribute__((visibility("default"))) TlsFree(DWORD idx);
LPVOID __attribute__((visibility("default"))) TlsGetValue(DWORD idx);
BOOL   __attribute__((visibility("default"))) TlsSetValue(DWORD idx, LPVOID val);

#ifdef __cplusplus
} /* extern "C" */
#endif