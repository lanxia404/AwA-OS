#include <windows.h>

int main(void){
    const char *msg = "Hello from PE32 via AwA-OS WinSS!\n";
    DWORD w = 0;
    DWORD len = 0;
    while (msg[len] != '\0') len++;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, msg, len, &w, NULL);
    ExitProcess(0);
    return 0;
}
