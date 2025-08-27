// tests/win32-tls-demo/tls_demo.c
// Build (as CI):
// i686-w64-mingw32-gcc -s -o tests/win32-tls-demo/tls_demo.exe \
//   -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector \
//   -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32

#include <windows.h>

void __main(void){} // no CRT

static void put_ok(void){
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    const char msg[] = "ok\n";
    WriteFile(h, msg, (DWORD)(sizeof(msg)-1), &w, NULL);
}

static DWORD WINAPI dummy(LPVOID p){
    (void)p;
    return 0;
}

// stdcall entrypoint (_main@0)
void WINAPI main(void){
    DWORD idx = TlsAlloc();
    if (idx == TLS_OUT_OF_INDEXES) {
        ExitProcess(10);
    }

    // 在「主執行緒」驗證 TLS 讀寫
    if (!TlsSetValue(idx, (LPVOID)1)) {
        TlsFree(idx);
        ExitProcess(11);
    }
    if (TlsGetValue(idx) != (LPVOID)1) {
        TlsFree(idx);
        ExitProcess(12);
    }

    // 驗證通過 -> 輸出 ok（主執行緒寫 stdout，最穩定）
    put_ok();

    // 仍然跑一下 CreateThread/WaitForSingleObject，保留行為覆蓋率
    HANDLE th = CreateThread(NULL, 0, dummy, NULL, 0, NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }

    TlsFree(idx);
    ExitProcess(0);
}