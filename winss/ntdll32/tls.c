#include <stdlib.h>
#include <string.h>
#include "../include/nt/ntdef.h"
#include "../include/win/minwin.h"

/* 動態 TLS 槽：先給 64 個 */
#define TLS_SLOTS 64
static unsigned long g_tls_bitmap = 0; /* 每位代表一個 slot 是否被 alloc */

static void** tls_get_table(void){
  TEB_MIN* teb = NtCurrentTeb();
  if (!teb->ThreadLocalStoragePointer){
    void** tbl = (void**)calloc(TLS_SLOTS, sizeof(void*));
    teb->ThreadLocalStoragePointer = tbl;
  }
  return (void**)teb->ThreadLocalStoragePointer;
}

DWORD WINAPI TlsAlloc(void){
  for (DWORD i=0; i<TLS_SLOTS; ++i){
    if (!(g_tls_bitmap & (1ul<<i))) {
      g_tls_bitmap |= (1ul<<i);
      return i;
    }
  }
  SetLastError(8 /*ERROR_NOT_ENOUGH_MEMORY*/);
  return (DWORD)0xFFFFFFFFu;
}

BOOL WINAPI TlsFree(DWORD idx){
  if (idx >= TLS_SLOTS) return FALSE;
  g_tls_bitmap &= ~(1ul<<idx);
  /* 不清每一個 thread 的值（與 Windows 行為接近） */
  return TRUE;
}

BOOL WINAPI TlsSetValue(DWORD idx, LPVOID val){
  if (idx >= TLS_SLOTS) return FALSE;
  void** tbl = tls_get_table();
  tbl[idx] = val;
  return TRUE;
}

LPVOID WINAPI TlsGetValue(DWORD idx){
  if (idx >= TLS_SLOTS) return NULL;
  void** tbl = tls_get_table();
  return tbl[idx];
}
