#pragma once
#include <stdint.h>

#ifdef __GNUC__
#define AWA_EXPORT __attribute__((visibility("default")))
#else
#define AWA_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 設定目前執行緒的 TEB/TLS（i386 Linux: set_thread_area + %fs） */
AWA_EXPORT void  _nt_teb_setup_for_current(void);
/* 取得目前 TEB 基底（除錯用） */
AWA_EXPORT void* _nt_teb_base(void);

#ifdef __cplusplus
}
#endif