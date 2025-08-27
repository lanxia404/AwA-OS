// winss/ntdll32/tls.c
// Minimal TLS for AwA-OS (i386) using pthreads
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/win/minwin.h"

#ifndef WINAPI
#  if defined(__i386__) || defined(__i386) || defined(i386)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI
#  endif
#endif

/* Windows 常量 */
#ifndef TLS_OUT_OF_INDEXES
#define TLS_OUT_OF_INDEXES 0xFFFFFFFFu
#endif

/* 全域管理：最多 64 個 TLS 索引 */
#define TLS_SLOTS 64
static uint64_t g_tls_bitmap = 0;        /* 1 表示已使用 */
static pthread_mutex_t g_tls_mu = PTHREAD_MUTEX_INITIALIZER;

/* 每執行緒：一塊 TLS_SLOTS 大小的 void* 陣列 */
static pthread_key_t g_tls_key;
static int g_tls_key_init = 0;
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;

static void tls_array_dtor(void* p){ if(p) free(p); }

static void tls_once_init(void){
  pthread_key_create(&g_tls_key, tls_array_dtor);
  g_tls_key_init = 1;
}

static void** tls_get_array(void){
  pthread_once(&g_tls_once, tls_once_init);
  void** arr = (void**)pthread_getspecific(g_tls_key);
  if (!arr){
    arr = (void**)calloc(TLS_SLOTS, sizeof(void*));
    if (!arr){ SetLastError(8 /*ERROR_NOT_ENOUGH_MEMORY*/); return NULL; }
    pthread_setspecific(g_tls_key, arr);
  }
  return arr;
}

DWORD WINAPI TlsAlloc(void){
  pthread_mutex_lock(&g_tls_mu);
  for (DWORD i=0;i<TLS_SLOTS;++i){
    if (!(g_tls_bitmap & (1ull<<i))){
      g_tls_bitmap |= (1ull<<i);
      pthread_mutex_unlock(&g_tls_mu);
      return i;
    }
  }
  pthread_mutex_unlock(&g_tls_mu);
  SetLastError(8 /*ERROR_NOT_ENOUGH_MEMORY*/);
  return TLS_OUT_OF_INDEXES;
}

BOOL WINAPI TlsFree(DWORD idx){
  if (idx >= TLS_SLOTS){ SetLastError(87 /*ERROR_INVALID_PARAMETER*/); return FALSE; }
  pthread_mutex_lock(&g_tls_mu);
  g_tls_bitmap &= ~(1ull<<idx);
  pthread_mutex_unlock(&g_tls_mu);

  /* 清掉所有執行緒的值：我們只能影響當前執行緒的快取，其他執行緒會在下次存取前仍保留。 */
  void** arr = tls_get_array();
  if (arr) arr[idx] = NULL;
  return TRUE;
}

LPVOID WINAPI TlsGetValue(DWORD idx){
  if (idx >= TLS_SLOTS) { SetLastError(87); return NULL; }
  void** arr = tls_get_array();
  if (!arr) return NULL;
  return arr[idx];
}

BOOL WINAPI TlsSetValue(DWORD idx, LPVOID val){
  if (idx >= TLS_SLOTS) { SetLastError(87); return FALSE; }
  void** arr = tls_get_array();
  if (!arr) return FALSE;
  arr[idx] = val;
  return TRUE;
}