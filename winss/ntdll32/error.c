#include "../include/nt/ntdef.h"
#include "../include/win/minwin.h"

void WINAPI SetLastError(DWORD e){ NtCurrentTeb()->LastErrorValue = e; }
DWORD WINAPI GetLastError(void){ return NtCurrentTeb()->LastErrorValue; }
