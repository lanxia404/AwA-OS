#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 設定目前執行緒的 TEB/TLS（32-bit Linux: 透過 set_thread_area + %fs） */
void _nt_teb_setup_for_current(void);

/* 取得當前 TEB 基底（純除錯用途，可不一定使用） */
void* _nt_teb_base(void);

#ifdef __cplusplus
}
#endif