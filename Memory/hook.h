#include <Windows.h>
#include <cstdint>
BOOL HookRemoteGetTickCount(HANDLE hProcess);
BOOL x64Hook(HANDLE hProcess);
BOOL x64Unhook(HANDLE hProcess);
void x64Hook();
DWORD WINAPI HookedGetTickCount();
