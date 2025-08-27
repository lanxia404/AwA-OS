#pragma once
#include "../include/win/minwin.h"

/* Loader 會把自己的 spawn 實作註冊進來 */
typedef int (*pe32_spawn_fn)(const char* path, const char* cmdline /*可為NULL*/);

/* 設定目前行程的「Windows」命令列（供 GetCommandLineA 使用） */
void nt_set_command_lineA(const char* s);

/* Loader 註冊用：把 pe32_spawn 的實作塞進來 */
void nt_set_spawn_impl(pe32_spawn_fn fn);

/* 供 ntshim32 呼叫，用來建立子 PE32 行程 */
int  pe32_spawn(const char* path, const char* cmdline /*可為NULL*/);

/* 供 Loader 設定 TEB/TLS（你既有實作）*/
void nt_teb_setup_for_current(void);