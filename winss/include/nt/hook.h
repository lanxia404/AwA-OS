#pragma once
/* 與 loader / ntshim32 共用的 Hook 介面 */
struct Hook { const char* dll; const char* name; void* fn; };
extern struct Hook NT_HOOKS[];