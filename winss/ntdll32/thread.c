#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "../include/win/minwin.h"

/* 最小 thread 物件 */
typedef struct _AWA_THREAD {
  pthread_t pt;
  DWORD     exit_code;
  DWORD     tid;
} AWA_THREAD;

typedef struct _AWA_THREAD_CTX {
  LPTHREAD_START_ROUTINE start;
  LPVOID                 param;
  AWA_THREAD*            ht;
} AWA_THREAD_CTX;

static DWORD g_tid_seq = 1000;          /* 簡單遞增的 TID */
static __thread AWA_THREAD* tls_self = NULL;  /* 當前執行緒的 AWA_THREAD 指標（用於 ExitThread） */

static void* awa_pthread_tramp(void* arg){
  AWA_THREAD_CTX* ctx = (AWA_THREAD_CTX*)arg;
  tls_self = ctx->ht;
  DWORD rc = 0;
  if(ctx->start){
    rc = ctx->start(ctx->param);
  }
  ctx->ht->exit_code = rc;
  free(ctx);
  return NULL;
}

/* 符合 minwin.h 宣告的定義（注意第一個參數型別要用 LPSECURITY_ATTRIBUTES） */
HANDLE WINAPI CreateThread(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T                dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                lpParameter,
  DWORD                 dwCreationFlags,
  LPDWORD               lpThreadId)
{
  (void)lpThreadAttributes;

  AWA_THREAD* ht = (AWA_THREAD*)calloc(1, sizeof(AWA_THREAD));
  if(!ht){
    SetLastError(8 /*ERROR_NOT_ENOUGH_MEMORY*/);
    return NULL;
  }

  AWA_THREAD_CTX* ctx = (AWA_THREAD_CTX*)calloc(1, sizeof(AWA_THREAD_CTX));
  if(!ctx){
    free(ht);
    SetLastError(8);
    return NULL;
  }
  ctx->start = lpStartAddress;
  ctx->param = lpParameter;
  ctx->ht    = ht;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  if(dwStackSize && dwStackSize >= (SIZE_T)(64*1024)){   /* 給個下限以免太小 */
    pthread_attr_setstacksize(&attr, (size_t)dwStackSize);
  }

  int rc = pthread_create(&ht->pt, &attr, awa_pthread_tramp, ctx);
  pthread_attr_destroy(&attr);

  if(rc != 0){
    free(ctx);
    free(ht);
    SetLastError(0x00000057 /*ERROR_INVALID_PARAMETER*/);
    return NULL;
  }

  ht->tid = ++g_tid_seq;
  if(lpThreadId) *lpThreadId = ht->tid;

  /* 目前不支援 CREATE_SUSPENDED 等旗標，需時再加 */
  (void)dwCreationFlags;
  return (HANDLE)ht;
}

VOID WINAPI ExitThread(DWORD dwExitCode){
  if(tls_self){
    tls_self->exit_code = dwExitCode;
  }
  /* 直接結束 pthread */
  pthread_exit(NULL);
  /* not reached */
}

VOID WINAPI Sleep(DWORD dwMilliseconds){
  /* usleep 參數是微秒 */
  usleep((useconds_t)dwMilliseconds * 1000u);
}

DWORD WINAPI GetCurrentThreadId(void){
  if(tls_self && tls_self->tid) return tls_self->tid;
  /* fallback：以 pthread_self 的位元做個簡單 id */
  return (DWORD)((uintptr_t)pthread_self() & 0xFFFFFFFFu);
}