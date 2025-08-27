// tests/win32-tls-demo/tls_demo.c
// Build flags (as in CI):
//   i686-w64-mingw32-gcc -s -o tests/win32-tls-demo/tls_demo.exe \
//     -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector \
//     -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32

#include <windows.h>

// No CRT: provide a dummy __main() to satisfy some toolchains when -nostdlib
void __main(void){}

// Global flag set by the worker thread when TLS works
static volatile LONG g_tls_ok = 0;

static DWORD WINAPI worker(LPVOID p)
{
    // TLS index is passed by pointer from main (on its stack)
    DWORD idx = *(volatile DWORD*)p;

    // Set & get a sentinel value via TLS
    if (!TlsSetValue(idx, (LPVOID)1))
        return 1;
    if (TlsGetValue(idx) != (LPVOID)1)
        return 2;

    // Signal success to the main thread
    g_tls_ok = 1;
    return 0; // returning from thread proc == ExitThread(0)
}

static void write_ok(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    const char msg[] = "ok\r\n";
    // Best-effort: ignore return value; if it fails, CI 也會看不到 "ok"
    WriteFile(h, msg, (DWORD)(sizeof(msg) - 1), &w, NULL);
}

// stdcall entrypoint (_main@0) to match linker --entry
void WINAPI main(void)
{
    // Allocate a TLS index
    DWORD idx = TlsAlloc();
    if (idx == TLS_OUT_OF_INDEXES) {
        ExitProcess(10);
    }

    // Start the worker thread that validates TLS
    HANDLE th = CreateThread(NULL, 0, worker, &idx, 0, NULL);
    if (!th) {
        TlsFree(idx);
        ExitProcess(11);
    }

    // Wait until worker finishes
    WaitForSingleObject(th, INFINITE);
    // We don't import GetExitCodeThread to keep imports minimal
    // CloseHandle is in our hook table, so it's safe to call.
    CloseHandle(th);

    // Free TLS index
    TlsFree(idx);

    // If TLS worked, print "ok" from the main thread (reliable stdout)
    if (g_tls_ok) {
        write_ok();
        ExitProcess(0);
    }

    // TLS failed
    ExitProcess(12);
}