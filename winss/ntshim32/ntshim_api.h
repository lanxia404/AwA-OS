#pragma once
#ifdef __cplusplus
extern "C" {
#endif

typedef int (*pe32_spawn_fn)(const char* path, const char* cmdline);

/* 由 Loader（選擇性）註冊內部 spawn 實作；若未註冊，bridge 會用 fallback 的 fork/exec。 */
void nt_set_spawn_impl(pe32_spawn_fn fn);

/* CreateProcessA 會呼叫的對外符號（實作在 bridge 裡）。 */
int  pe32_spawn(const char* path, const char* cmdline);

/* 供 Loader 設置 Win32 GetCommandLineA 所回報的字串 */
void nt_set_command_lineA(const char* path, const char* argv /*可為 NULL*/);

#ifdef __cplusplus
}
#endif
