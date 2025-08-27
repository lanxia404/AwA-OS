// winss/ntshim32/ntshim_api.h
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// 初始化 TEB/TLS（由 ntdll32 提供）
void nt_teb_setup_for_current(void);

// 設定目前行程的命令列（Windows 風格單一字串）
// path 必填、argv 可為 NULL（若非 NULL，會接在 path 後方以單一空白分隔）
void nt_set_command_lineA(const char* path, const char* argv /*nullable*/);

// 讓 Loader 註冊「如何啟動另一個 PE」（CreateProcessA 用）
void nt_set_spawn_impl(int (*fn)(const char* path, const char* argv /*nullable*/));

// CreateProcessA 會透過此函式回到 Loader 執行另一個 PE，回傳 1=成功、0=失敗
int  pe32_spawn(const char* path, const char* argv /*nullable*/);

#ifdef __cplusplus
}
#endif
