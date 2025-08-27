#ifndef AWAOS_NTSHIM_API_H
#define AWAOS_NTSHIM_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* 由 loader 可註冊的 CreateProcess 實作；回傳 1=成功(可視為 TRUE)、0=失敗(FALSE) */
typedef int (*pe32_spawn_fn)(const char* path, const char* cmdline /*可為 NULL*/);

/* 設定/覆寫 spawn 實作：在目前行程生命週期內有效 */
void nt_set_spawn_impl(pe32_spawn_fn fn);

/* 對外導出：ntshim32 的 CreateProcessA 會呼叫這個，
 * 若未註冊實作則使用 fallback（fork+exec loader）。 */
int  pe32_spawn(const char* path, const char* cmdline /*可為 NULL*/);

/* 設定 ANSI 版命令列（供 GetCommandLineA 使用） */
void nt_set_command_lineA(const char* path, const char* argv /*可為 NULL*/);

#ifdef __cplusplus
}
#endif
#endif /* AWAOS_NTSHIM_API_H */