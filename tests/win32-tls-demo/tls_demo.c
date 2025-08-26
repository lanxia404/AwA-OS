#include <windows.h>

void __main(void){}

static DWORD WINAPI worker(LPVOID p){
  DWORD idx = *(DWORD*)p;
  TlsSetValue(idx, (LPVOID)1);
  if ((DWORD)(uintptr_t)TlsGetValue(idx) == 1) {
    HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w=0; WriteFile(h,"ok\n",3,&w,0);
  }
  return 0;
}

void WINAPI main(void){
  DWORD idx = TlsAlloc();
  if (idx == 0xFFFFFFFFu) ExitProcess(1);

  HANDLE th = CreateThread(NULL,0, worker, &idx, 0, NULL);
  WaitForSingleObject(th, INFINITE);
  TlsFree(idx);
  ExitProcess(0);
}
