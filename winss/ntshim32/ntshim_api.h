// winss/ntshim32/ntshim_api.h
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// 由 loader 呼叫，用來把 Win32 的命令列（ANSI版）塞給 shim。
// GetCommandLineA() 會回傳這裡保存的內容。
void nt_set_command_lineA(const char* s);

#ifdef __cplusplus
}
#endif