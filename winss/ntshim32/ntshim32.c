// winss/ntdll32/thread.c
// Minimal thread API for AwA-OS (i386) using pthreads
// 修正：以「handle 註冊表」避免對假 handle 解參考造成 SIGSEGV。

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../include/win/minwin.h"   // DWORD, HANDLE, LPVOID, etc.

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
  struct AWA_THREAD* _next; /* for registry */
} AWA_THREAD;

#define AWA_T_MAGIC 0x41574154 /* 'AWAT' */

/* 簡單的 handle 註冊表（單向串列 + 互斥） */
static pthread_mutex_t g_thr_mu = PTHREAD_MUTEX_INITIALIZER;
static AWA_THREAD*     g_thr_head = NULL;

static void reg_add(AWA_THREAD* ht){
  pthread_mutex_lock(&g_thr_mu);
  ht->_next = g_thr_head;
  g_thr_head = ht;
  pthread_mutex_unlock(&g_thr_mu);
}
static void reg_del(AWA_THREAD* ht){
  pthread_mutex_lock(&g_thr_mu);
  AWA_THREAD **pp=&g_thr_head, *p=g_thr_head;
  while (p){
    if (p == ht){ *pp = p->_next; break; }
    pp = &p->_next; p = p->_next;
  }
  pthread_mutex_unlock(&g_thr_mu);
}
static int reg_has(AWA_THREAD* ht){
  int found = 0;
  pthread_mutex_lock(&g_thr_mu);
  for (AWA_THREAD* p=g_thr_head; p; p=p->_next){
    if (p == ht){ found = 1; break; }
  }
  pthread_mutex_unlock(&g_thr_mu);
  return found;
}

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
/* 參考：CreateThread/ExitThread/Sleep/GetCurrentThreadId 官方文件。 */
// CreateThread: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
HANDLE WINAPI CreateThread(
  LPVOID /*lpThreadAttributes*/, SIZE_T /*dwStackSize*/,
  LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
  DWORD /*dwCreationFlags*/, LPDWORD lpThreadId)
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

  reg_add(ht);
  return (HANDLE)ht;
}

// ExitThread: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread
VOID WINAPI ExitThread(DWORD dwExitCode){
  pthread_exit((void*)(uintptr_t)dwExitCode);
}

// Sleep: https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-sleep
VOID WINAPI Sleep(DWORD dwMilliseconds){
  usleep((useconds_t)dwMilliseconds * 1000u);
}

// GetCurrentThreadId: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid
DWORD WINAPI GetCurrentThreadId(void){
  return gen_tid();
}

/* -------- 提供給 ntshim32 的輔助（避免解參考隨機指標）-------- */
int _nt_is_thread_handle(HANDLE h){
  /* 只用「是否在註冊表」判斷，不解參考 h 指向內容 */
  AWA_THREAD* ht = (AWA_THREAD*)h;
  return reg_has(ht);
}

BOOL _nt_close_thread(HANDLE h){
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!reg_has(ht)) return TRUE;  /* 不是 thread handle：按 Windows 慣例，這裡可視作成功或失敗，PoC 採成功 */
  reg_del(ht);
  free(ht);
  return TRUE;
}

// WaitForSingleObject: https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
DWORD _nt_wait_thread(HANDLE h, DWORD dwMilliseconds){
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!reg_has(ht)) return WAIT_OBJECT_0; /* 非 thread handle：直接視為已 signaled */

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
  /* PoC 不處理逾時：可用 pthread_timedjoin_np 改進 */
  (void)dwMilliseconds;
#endif
  pthread_join(ht->th, NULL);
  ht->joined = 1;
  return WAIT_OBJECT_0;
}

BOOL _nt_get_thread_exit_code(HANDLE h, LPDWORD lpExitCode){
  if (!lpExitCode) return FALSE;
  AWA_THREAD* ht = (AWA_THREAD*)h;
  if (!reg_has(ht)){ *lpExitCode = 0; return TRUE; }
  *lpExitCode = ht->exit_code;
  return TRUE;
}