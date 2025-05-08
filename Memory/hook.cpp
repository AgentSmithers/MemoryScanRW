///////////////////////////////////////////////////////// Hooking
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <TlHelp32.h>
BYTE originalBytes[5];  // Store the original bytes
DWORD oldProtect;
FARPROC originalFunc;

// Store original 14 bytes for potential unhook
BYTE g_OriginalBytes[14];
DWORD g_OldProtect = 0;

// A small x64 shellcode that returns 123456 (0x1E240).
// In pure x64 assembly, that might look like:
//   mov eax, 123456
//   ret
// But we also often must manage stack alignment if the real function
// is more complex. For a simple demonstration, just do MOV + RET.
static const BYTE g_Shellcode[] =
{
    0xB8, 0x40, 0xE2, 0x01, 0x00, // mov  eax, 0x1E240 (123456 in decimal)
    0xC3                          // ret
};

static const SIZE_T MAX_FUNC_SIZE = 16;

extern DWORD WINAPI HookedGetTickCount();
__declspec(noinline) DWORD WINAPI HookedGetTickCount()
{
    // A very simple function that returns a constant
    return 9999999;
}

//-----------------------------------------------------------------------------
// Utility: Find base address of 'kernel32.dll' (or 'kernelbase.dll') in a remote process.
LPVOID GetRemoteModuleBase(DWORD pid, const wchar_t* moduleName)
{
    LPVOID moduleBase = nullptr;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W modEntry = { 0 };
        modEntry.dwSize = sizeof(modEntry);

        if (Module32FirstW(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, moduleName))
                {
                    moduleBase = modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
    }
    return moduleBase;
}

SIZE_T CopyFunctionBytes(LPVOID funcPtr, BYTE* buffer, SIZE_T maxSize)
{
    // In reality, you might disassemble or have a labeled end
    // For demonstration, just copy `maxSize` blindly.
    memcpy(buffer, funcPtr, maxSize);
    return maxSize;
}

BOOL HookRemoteGetTickCount(HANDLE hProcess)
{
    // 1) Find local addresses
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLocalFunc = GetProcAddress(hLocalKernel32, "GetTickCount");
    if (!pLocalFunc) {
        std::cerr << "[!] Failed to get local GetTickCount address.\n";
        return FALSE;
    }

    // Compute offset from local kernel32 base
    ptrdiff_t offset = reinterpret_cast<BYTE*>(pLocalFunc) - reinterpret_cast<BYTE*>(hLocalKernel32);

    // 2) Find remote kernel32 base
    DWORD pid = GetProcessId(hProcess);
    LPVOID remoteKernel32Base = GetRemoteModuleBase(pid, L"kernel32.dll");
    if (!remoteKernel32Base) {
        std::cerr << "[!] Failed to find remote kernel32.dll base.\n";
        return FALSE;
    }

    // The remote GetTickCount address
    LPVOID remoteGetTickCount = reinterpret_cast<BYTE*>(remoteKernel32Base) + offset;

    // 3) Read original 14 bytes
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, remoteGetTickCount, g_OriginalBytes, 14, &bytesRead) || bytesRead < 14) {
        std::cerr << "[!] Failed to read original bytes at remote GetTickCount.\n";
        return FALSE;
    }

    // 4) Copy our local HookedGetTickCount function into a buffer
    BYTE localFuncBytes[MAX_FUNC_SIZE] = { 0 };
    
    SIZE_T funcSize = CopyFunctionBytes(
        reinterpret_cast<LPVOID>(HookedGetTickCount),
        localFuncBytes,
        MAX_FUNC_SIZE
    );
    // For a trivial function that returns a constant, it's likely < 100 bytes in Release mode

    // 5) Allocate memory in the remote process for the copied function
    LPVOID remoteFuncAddr = VirtualAllocEx(
        hProcess,
        NULL,
        funcSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteFuncAddr) {
        std::cerr << "[!] VirtualAllocEx failed.\n";
        return FALSE;
    }

    // 6) Write the function bytes to the remote process
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteFuncAddr, localFuncBytes, funcSize, &bytesWritten) ||
        bytesWritten < funcSize)
    {
        std::cerr << "[!] WriteProcessMemory for HookedGetTickCount failed.\n";
        VirtualFreeEx(hProcess, remoteFuncAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // 7) Build the 14-byte patch (absolute jump in x64)
    //    48 B8 <8-byte addr>    mov rax, <remoteFuncAddr>
    //    FF E0                  jmp rax
    //    90 90                  nop, nop
    BYTE patch[14] = { 0 };
    patch[0] = 0x48;
    patch[1] = 0xB8; // mov rax, imm64
    *reinterpret_cast<uint64_t*>(&patch[2]) = reinterpret_cast<uint64_t>(remoteFuncAddr);
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    patch[12] = 0x90; // nop
    patch[13] = 0x90; // nop

    // 8) Change protection so we can write to the remote function start
    if (!VirtualProtectEx(hProcess, remoteGetTickCount, 14, PAGE_EXECUTE_READWRITE, &g_OldProtect)) {
        std::cerr << "[!] VirtualProtectEx failed.\n";
        return FALSE;
    }

    // 9) Overwrite the first 14 bytes of GetTickCount with our jump
    if (!WriteProcessMemory(hProcess, remoteGetTickCount, patch, 14, &bytesWritten) || bytesWritten < 14) {
        std::cerr << "[!] WriteProcessMemory for patch failed.\n";
        // Attempt to restore old protection
        VirtualProtectEx(hProcess, remoteGetTickCount, 14, g_OldProtect, &g_OldProtect);
        return FALSE;
    }

    // 10) Restore protection
    DWORD tempProtect = 0;
    VirtualProtectEx(hProcess, remoteGetTickCount, 14, g_OldProtect, &tempProtect);

    std::cout << "[+] Successfully hooked remote GetTickCount to our HookedGetTickCount.\n";
    return TRUE;
}

//-----------------------------------------------------------------------------
// x64Hook: Hook GetTickCount in the specified process (by handle).
// 1) Finds remote address of GetTickCount.
// 2) Allocates shellcode that returns 123456.
// 3) Writes a 14-byte jump patch in the remote function to jump to our shellcode.
BOOL x64Hook(HANDLE hProcess)
{
    // Step 1: Find local addresses
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLocalFunc = GetProcAddress(hLocalKernel32, "GetTickCount");
    if (!pLocalFunc)
    {
        std::cerr << "[!] Failed to get local GetTickCount address.\n";
        return FALSE;
    }

    // (Optional) Some Windows versions forward GetTickCount to kernelbase.dll.
    // You might actually want:
    //   HMODULE hLocalKernelbase = GetModuleHandleW(L"kernelbase.dll");
    //   pLocalFunc = GetProcAddress(hLocalKernelbase, "GetTickCount");

    // Compute offset from local kernel32 base
    ptrdiff_t offset = (BYTE*)pLocalFunc - (BYTE*)hLocalKernel32;

    // Step 2: Find remote kernel32 base
    // (If hooking kernelbase, get that base instead)
    DWORD pid = GetProcessId(hProcess);
    LPVOID remoteKernel32Base = GetRemoteModuleBase(pid, L"kernel32.dll");
    if (!remoteKernel32Base)
    {
        std::cerr << "[!] Failed to find remote kernel32.dll base.\n";
        return FALSE;
    }

    // The remote GetTickCount address
    LPVOID remoteGetTickCount = (BYTE*)remoteKernel32Base + offset;

    // Step 3: Read the original 14 bytes from the remote function
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, remoteGetTickCount, g_OriginalBytes, 14, &bytesRead) || bytesRead < 14)
    {
        std::cerr << "[!] Failed to read original bytes at remote GetTickCount.\n";
        return FALSE;
    }

    // Step 4: Allocate memory for the shellcode in the remote process
    LPVOID remoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(g_Shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteShellcode)
    {
        std::cerr << "[!] VirtualAllocEx failed.\n";
        return FALSE;
    }

    // Step 5: Write our shellcode (which returns 123456) into the remote process
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteShellcode, g_Shellcode, sizeof(g_Shellcode), &bytesWritten) ||
        bytesWritten < sizeof(g_Shellcode))
    {
        std::cerr << "[!] WriteProcessMemory for shellcode failed.\n";
        return FALSE;
    }

    // Step 6: Build the 14-byte patch:
    //   48 B8 <8-byte-addr>   ; mov rax, <remoteShellcode>
    //   FF E0                 ; jmp rax
    //   90 90                 ; (nop, nop if needed)
    BYTE patch[14] = { 0 };
    patch[0] = 0x48;  // REX.W
    patch[1] = 0xB8;  // MOV RAX, imm64
    *reinterpret_cast<uint64_t*>(&patch[2]) = reinterpret_cast<uint64_t>(remoteShellcode);
    patch[10] = 0xFF;  // JMP [RAX]
    patch[11] = 0xE0;  // 
    patch[12] = 0x90;  // NOP
    patch[13] = 0x90;  // NOP

    // Step 7: Change protection of remote GetTickCount to allow writing
    if (!VirtualProtectEx(hProcess, remoteGetTickCount, 14, PAGE_EXECUTE_READWRITE, &g_OldProtect))
    {
        std::cerr << "[!] VirtualProtectEx failed.\n";
        return FALSE;
    }

    // Step 8: Write the patch
    if (!WriteProcessMemory(hProcess, remoteGetTickCount, patch, 14, &bytesWritten) || bytesWritten < 14)
    {
        std::cerr << "[!] WriteProcessMemory for patch failed.\n";
        // Attempt to restore old protection
        VirtualProtectEx(hProcess, remoteGetTickCount, 14, g_OldProtect, &g_OldProtect);
        return FALSE;
    }

    // Step 9: Restore old protection
    DWORD tempProtect = 0;
    VirtualProtectEx(hProcess, remoteGetTickCount, 14, g_OldProtect, &tempProtect);

    std::cout << "[+] Successfully hooked GetTickCount in remote process.\n";
    return TRUE;
}

//-----------------------------------------------------------------------------
// x64Unhook: restore the original 14 bytes so calls go back to normal
BOOL x64Unhook(HANDLE hProcess)
{
    // You must know the same remoteGetTickCount address as used in x64Hook
    // or recompute it the same way.

    // For demonstration, let's do that again:
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLocalFunc = GetProcAddress(hLocalKernel32, "GetTickCount");
    ptrdiff_t offset = (BYTE*)pLocalFunc - (BYTE*)hLocalKernel32;

    DWORD pid = GetProcessId(hProcess);
    LPVOID remoteKernel32Base = GetRemoteModuleBase(pid, L"kernel32.dll");
    LPVOID remoteGetTickCount = (BYTE*)remoteKernel32Base + offset;

    // Restore original bytes
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteGetTickCount, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "[!] VirtualProtectEx (unhook) failed.\n";
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteGetTickCount, g_OriginalBytes, 14, &bytesWritten) || bytesWritten < 14)
    {
        std::cerr << "[!] WriteProcessMemory (unhook) failed.\n";
        // attempt to restore old protection
        VirtualProtectEx(hProcess, remoteGetTickCount, 14, oldProtect, &oldProtect);
        return FALSE;
    }

    VirtualProtectEx(hProcess, remoteGetTickCount, 14, oldProtect, &oldProtect);
    std::cout << "[+] Successfully unhooked.\n";
    return TRUE;
}

void x64Hook()
{
    // On modern Windows x64, GetTickCount may be forwarded to kernelbase.dll
    // for demonstration, we'll still grab the address from kernel32.dll:
    originalFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
    // If that doesn't work, try kernelbase.dll instead:
    // originalFunc = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "GetTickCount");

    // 1. Save the original 14 bytes:
    memcpy(originalBytes, originalFunc, 14);

    // 2. Change protection to allow writing
    VirtualProtect(originalFunc, 14, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 3. Build a 14-byte patch:
    //
    //    48 B8 xx xx xx xx xx xx xx xx   mov rax, <HookedGetTickCount>
    //    FF E0                           jmp rax
    //    90 90                           nop, nop (filler if needed)
    //
    // This loads the full 64-bit address into RAX, then jumps there.
    // That’s 12 bytes (10 for mov, 2 for jmp), plus 2 optional NOPs.
    BYTE patch[14] = { 0 };

    // mov rax, <64-bit-addr>
    patch[0] = 0x48;       // REX.W prefix
    patch[1] = 0xB8;       // MOV RAX, imm64 opcode
    *reinterpret_cast<uint64_t*>(&patch[2]) = reinterpret_cast<uint64_t>(HookedGetTickCount);

    // jmp rax
    patch[10] = 0xFF;      // JMP [register] opcode
    patch[11] = 0xE0;      // E0 = rax

    // optional NOPs if the function is longer
    patch[12] = 0x90;
    patch[13] = 0x90;

    // 4. Overwrite the beginning of the target function
    memcpy(originalFunc, patch, 14);

    // 5. Restore the old protection
    VirtualProtect(originalFunc, 14, oldProtect, &oldProtect);
}

void x86Hook() {
    originalFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");

    // Save the original bytes
    memcpy(originalBytes, originalFunc, 5);

    // Make the memory writable
    VirtualProtect((LPVOID)originalFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Write the jump instruction
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)HookedGetTickCount - (DWORD)originalFunc - 5;
    memcpy((LPVOID)originalFunc, jmp, 5);

    VirtualProtect((LPVOID)originalFunc, 5, oldProtect, &oldProtect);
}

void Unhook() {
    VirtualProtect((LPVOID)originalFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((LPVOID)originalFunc, originalBytes, 5);
    VirtualProtect((LPVOID)originalFunc, 5, oldProtect, &oldProtect);
}