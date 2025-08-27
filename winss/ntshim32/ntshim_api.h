// winss/ntshim32/ntshim_api.h
#ifndef AWAOS_NTSHIM_API_H
#define AWAOS_NTSHIM_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- TEB/TLS 初始化（由 ntshim32 實作，loader 在跳進 entry 前呼叫） ---- */
void nt_teb_setup_for_current(void);

/* ---- GetCommandLineA 背後的字串設定（由 loader 在執行目標前設定） ----
 * path: 目標 exe 路徑（Windows 視角）
 * argv: 以空白串起的引數字串；可為 NULL（表示只有 path）
 */
void nt_set_command_lineA(const char* path, const char* argv /*nullable*/);

/* ---- pe32_spawn 橋接：ntshim32 的 CreateProcessA 會呼叫 pe32_spawn ----
 * 預設走 fallback（fork+execl 以 pe_loader32 啟動子行程），
 * loader 可在啟動時註冊更高階的實作（同行程/同位址空間啟動等）。
 */
typedef int (*pe32_spawn_fn)(const char* path, const char* cmdline /*nullable*/);

/* 由 loader 註冊真正的 spawn 實作（可選） */
void nt_set_spawn_impl(pe32_spawn_fn fn);

/* 對外 pe32_spawn：ntshim32.c 會直接呼叫這個 */
int pe32_spawn(const char* path, const char* cmdline /*nullable*/);

#ifdef __cplusplus
} // extern "C"
#endif
#endif // AWAOS_NTSHIM_API_H