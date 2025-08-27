#ifndef AWA_NTSHIM_API_H
#define AWA_NTSHIM_API_H

#ifdef __cplusplus
extern "C" {
#endif

void nt_set_command_lineA(const char* path, const char* argv /*可為 NULL*/);
void nt_teb_setup_for_current(void);

/* 由 loader 在進入 PE 前初始化當前執行緒的 TEB/TLS 最小狀態 */
void nt_teb_setup_for_current(void);

// 由 loader 提供的 in-proc spawn（CreateProcessA 最小實作會呼叫）
int pe32_spawn(const char* app, const char* cmdline, PROCESS_INFORMATION* pi);

#ifdef __cplusplus
}
#endif
#endif