#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nt/ntdef.h"
#include "../include/win/minwin.h"

DWORD WINAPI GetLastError(void);
void  WINAPI SetLastError(DWORD e);

#define MAGIC_THR 0x54485244u /* 'THRD' */

typedef struct ThreadObj {
  unsigned magic;
  pthread_t th;
  int efd;             /* eventfd: thread 結束時寫入喚醒等待者 */
  DWORD tid;
  DWORD exit_code;
} ThreadObj;

typedef struct StartCtx {
  LPTHREAD_START_ROUTINE proc;
  LPVOID param;
  ThreadObj* self;
} StartCtx;

static void* th_main(void* p){
  StartCtx* ctx = (StartCtx*)p;
  NtCurrentTeb(); /* 初始化 TEB 給子執行緒 */
  DWORD rc = 0;
  if (ctx->proc) rc = ctx->proc(ctx->param);
  ctx->self->exit_code = rc;
  uint64_t one = 1;
  write(ctx->self->efd, &one, 8);
  free(ctx);
  return NULL;
}

HANDLE WINAPI CreateThread(
  LPVOID lpThreadAttributes, SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
  DWORD dwCreationFlags, LPDWORD lpThreadId)
{
  (void)lpThreadAttributes; (void)dwStackSize; (void)dwCreationFlags;
  ThreadObj* o = (ThreadObj*)calloc(1, sizeof(ThreadObj));
  if (!o) { SetLastError(8); return NULL; }
  o->magic = MAGIC_THR;
  o->efd = eventfd(0, 0);
  if (o->efd < 0) { free(o); SetLastError(8); return NULL; }

  StartCtx* ctx = (StartCtx*)malloc(sizeof(StartCtx));
  if (!ctx){ close(o->efd); free(o); SetLastError(8); return NULL; }
  ctx->proc = lpStartAddress;
  ctx->param = lpParameter;
  ctx->self = o;

  if (pthread_create(&o->th, NULL, th_main, ctx) != 0){
    free(ctx); close(o->efd); free(o); SetLastError(87 /*ERROR_INVALID_PARAMETER*/); return NULL;
  }
  o->tid = (DWORD)((uintptr_t)o->th); /* 簡化 */

  if (lpThreadId) *lpThreadId = o->tid;
  return (HANDLE)o;
}

void WINAPI ExitThread(DWORD code){
  ThreadObj* dummy = NULL; (void)dummy;
  /* 直接結束；事件已在 thread wrapper 觸發 */
  pthread_exit((void*)(uintptr_t)code);
}

DWORD WINAPI GetCurrentThreadId(void){
  return (DWORD)((uintptr_t)pthread_self());
}

void WINAPI Sleep(DWORD ms){
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/* 供 WaitForSingleObject 使用：判斷/等待 thread handle */
int _nt_is_thread_handle(HANDLE h){
  ThreadObj* o = (ThreadObj*)h;
  return (o && o->magic == MAGIC_THR);
}

int _nt_wait_thread(HANDLE h, DWORD ms){
  ThreadObj* o = (ThreadObj*)h;
  if (!o || o->magic != MAGIC_THR) return -1;
  if (ms == INFINITE){
    uint64_t v; if (read(o->efd, &v, 8) < 0) return -1;
    return 0;
  } else {
    struct pollfd p = { .fd = o->efd, .events = POLLIN };
    int r = poll(&p, 1, (int)ms);
    if (r > 0) { uint64_t v; read(o->efd,&v,8); return 0; }
    if (r == 0) return 1; /* timeout */
    return -1;
  }
}

DWORD _nt_get_thread_exit_code(HANDLE h){
  ThreadObj* o = (ThreadObj*)h;
  return o ? o->exit_code : (DWORD)-1;
}

BOOL _nt_close_thread(HANDLE h){
  ThreadObj* o = (ThreadObj*)h;
  if (!o || o->magic != MAGIC_THR) return FALSE;
  /* 不強制 join；避免阻塞。若需要可加 detach */
  close(o->efd);
  o->magic = 0;
  free(o);
  return TRUE;
}
