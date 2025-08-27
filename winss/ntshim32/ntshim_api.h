#ifndef AWAOS_NTSHIM_API_H
#define AWAOS_NTSHIM_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* Loader 註冊的 spawn 實作型別與 API */
typedef int (*pe32_spawn_fn)(const char* path, const char* cmdline);
/* 設定（覆寫）spawn 實作；若未設定，bridge 會使用 fallback（fork+execl） */
void nt_set_spawn_impl(pe32_spawn_fn fn);
/* 暴露給 CreateProcessA 使用的統一入口（實際會呼叫上面註冊的 impl，否則 fallback） */
int  pe32_spawn(const char* path, const char* cmdline);

/* Loader 在進入被載入 PE 前，用來設定 ANSI 命令列（可視需要擴充為 Unicode 版本） */
void nt_set_command_lineA(const char* path, const char* argv /* 可為 NULL */);

#ifdef __cplusplus
}
#endif
#endif /* AWAOS_NTSHIM_API_H */