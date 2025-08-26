#pragma once
#include <stdint.h>
#include "../win/minwin.h"

typedef long NTSTATUS;

/* 簡化 NT_TIB / TEB / PEB（先放必要欄位） */
typedef struct _NT_TIB {
  void* ExceptionList;
  void* StackBase;
  void* StackLimit;
  void* SubSystemTib;
  void* FiberData;
  void* ArbitraryUserPointer;
  struct _NT_TIB* Self;
} NT_TIB;

typedef struct _TEB_MIN {
  NT_TIB NtTib;
  void*  EnvironmentPointer;
  DWORD  ClientId_UniqueProcess;
  DWORD  ClientId_UniqueThread;
  void*  ActiveRpcHandle;
  void*  ThreadLocalStoragePointer;   /* -> void** TLS 動態槽陣列 */
  DWORD  LastErrorValue;              /* Get/SetLastError 讀寫此欄 */
} TEB_MIN;

typedef struct _PEB_MIN {
  uint8_t BeingDebugged;
  void*   ImageBaseAddress;
} PEB_MIN;

/* 介面 */
TEB_MIN* NtCurrentTeb(void);
PEB_MIN* RtlGetCurrentPeb(void);
