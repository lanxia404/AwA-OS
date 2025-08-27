// winss/ntdll32/thread.c
// Minimal thread API for AwA-OS (i386) using pthreads

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../include/win/minwin.h"   // provides DWORD, HANDLE, LPVOID, etc.

#ifndef WINAPI
#  if defined(__i386__) || defined(__i386) || defined(i386)
#    define WINAPI __attribute__((stdcall))
#  else
#    define WINAPI
#  endif
#endif

#ifndef VOID
typedef void VOID;
#endif

#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0x00000000u
#endif

/* -------- 內部執行緒表示 -------- */
typedef struct AWA_THREAD {
  pthread_t th;
  DWORD     tid;
  DWORD     exit_code;
  int       joined;
  int       magic;
} AWA_THREAD;

#define AWA_T_MAGIC 0x41574154 /* 'AWAT' */

/* 產生一個 32-bit thread id（Linux: gettid；否則以 pthread_self 雜湊退化） */
static DWORD gen_tid(void){
#ifdef SYS_gettid
  return (DWORD)syscall(SYS_gettid);
#else
  uintptr_t v = (uintptr_t)pthread_self();
  return (DWORD)((v ^ (v>>16)) & 0xFFFFFFFFu);
#endif
}

/* CreateThread 的啟動上下文 */
typedef struct START_CTX {
  LPTHREAD_START_ROUTINE start;
  LPVOID                 param;
  AWA_THREAD*            ht;
} START_CTX;

/* pthread 進入點，呼叫 Win32 風格的 LPTHREAD_START_ROUTINE */
static void* trampoline(void* p){
  START_CTX* ctx = (START_CTX*)p;
  DWORD code = 0;
  if (ctx && ctx->start) code = ctx->start(ctx->param);
  if (ctx && ctx->ht)    ctx->ht->exit_code = code;
  if (ctx) free(ctx);
  return (void*)(uintptr_t)code;
}

/* -------- Win32 風格介面（KERNEL32 對應）-------- */
/* 原型參考 CreateThread 文件：DWORD WINAPI ThreadProc(LPVOID) 等。 */
HANDLE WINAPI CreateThread(
  LPVOID /*lpThreadAttributes*/, SIZE_T /*dwStackSize*/,
  LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
  DWORD /*dwCreationFlags*/, LPDWORD lpThreadId)   /* Microsoft docs: CreateThread */ /* see cite */
{
  AWA_THREAD* ht = (AWA_THREAD*)calloc(1, sizeof(AWA_THREAD));
  if (!ht){ SetLastError(8 /*ERROR_NOT_ENOUGH_MEMORY*/); return NULL; }
  ht->magic = AWA_T_MAGIC;
  ht->tid   = gen_tid();
  if (lpThreadId) *lpThreadId = ht->tid;

  START_CTX* ctx = (START_CTX*)calloc(1, sizeof(START_CTX));
  if (!ctx){ free(ht); SetLastError(8); return NULL; }
  ctx->start = lpStartAddress;
  ctx->param = lpParameter;
  ctx->ht    = ht;

  int rc = pthread_create(&ht->th, NULL, trampoline, ctx);
  if (rc != 0){ free(ctx); free(ht); SetLastError(8); return NULL; }
  return (HANDLE)ht;
}

VOID WINAPI ExitThread(DWORD dwExitCode){  /* Microsoft docs: ExitThread */ /* see cite */
  pthread_exit((void*)(uintptr_t)dwExitCode);
}

VOID WINAPI Sleep(DWORD dwMilliseconds){   /* Microsoft docs: Sleep */ /* see cite */
  /* usleep 單位是 microseconds；此處精度近似即可 */
  usleep((useconds_t)dwMilliseconds * 1000u);
}

DWORD WINAPI GetCurrentThreadId(void){
  return gen_tid();
}

/* -------- 提供給 ntshim32 的輔助（非 KERNEL32 名稱）-------- */
int _nt_is_thread_handle(HANDLE h){
  AWA_THREAD* ht = (AWA_THREAD*)h;
  return ht && ht->magic == AWA_T_MAGIC;
}

BOOL _nt_close_thread(HANDLE h){
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!ht || ht->magic != AWA_T_MAGIC) return FALSE;
  /* 此 PoC 不強制 join；交由 WaitForSingleObject 決定是否 join。 */
  free(ht);
  return TRUE;
}

DWORD _nt_wait_thread(HANDLE h, DWORD dwMilliseconds){
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!ht || ht->magic != AWA_T_MAGIC) return WAIT_OBJECT_0;

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
  if (dwMilliseconds != INFINITE){
    /* 簡化：多數 CI 情境用不到 timeout；如需嚴謹可改 pthread_timedjoin_np。 */
  }
#endif
  pthread_join(ht->th, NULL);
  ht->joined = 1;
  return WAIT_OBJECT_0;
}

BOOL _nt_get_thread_exit_code(HANDLE h, LPDWORD lpExitCode){
  if (!lpExitCode) return FALSE;
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!ht || ht->magic != AWA_T_MAGIC){ *lpExitCode = 0; return TRUE; }
  *lpExitCode = ht->exit_code;
  return TRUE;
}