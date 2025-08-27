// winss/ntdll32/teb_tls.h
#pragma once
#include "../include/nt/ntdef.h"   // 定義 TEB_MIN 與 NtCurrentTeb() 原型

#ifdef __cplusplus
extern "C" {
#endif

// 僅宣告「內部」初始化輔助函式；不要在此重宣 Windows API/TLS API
// 由 ntdll32/teb.c 提供定義
void nt_teb_setup_for_current(void);

#ifdef __cplusplus
}
#endif