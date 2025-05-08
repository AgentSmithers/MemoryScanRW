// Memory.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <sstream>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#define NOMINMAX // <--- Add this BEFORE including windows.h
#include <Windows.h>
#include <TlHelp32.h>
#include <cstddef>
#include <bitset>
#include <iomanip>
#include <psapi.h>
#include <stdio.h>
#include <tchar.h>
#include <thread>
#include <chrono>
#include <limits>       // For std::numeric_limits
#include <cstdint>      // For int8_t, int16_t, int32_t, int64_t
#include <algorithm>    // For std::find_if
#include <cctype>       // For std::isspace
#include "hook.h"
#include <set>

#pragma comment(lib, "advapi32.lib")

//const wchar_t* ProcName = L"notepad.exe";
const wchar_t* ProcName = L"Exodus-Win64-Shipping.exe"; //Matches ProcessName var?
DWORD processId = 0; // GetProcId(ProcName);
HANDLE hProcess = 0; // OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

class MemoryModule {
public:
    std::string ModuleName;
    DWORD Address;
    MemoryModule(DWORD Addr, std::string val) : ModuleName(val), Address(Addr) {
        //std::cout << "MemoryEntry Addr (" << Addr << ") = " << "0x" << std::hex << val << std::endl;
    }
};

class MemoryEntry {
public:
    int value = 0; //Used for Single byte checks
    //byte ByteArray[4];
    VOID * Address = NULL;
    VOID * Bytevalue = NULL; //Used for Arrays of values
    size_t sizeInBytes;

    MemoryEntry(VOID * Addr, int val) : value(val), Address(Addr) {
        sizeInBytes = sizeof(val);
        //std::cout << "MemoryEntry Addr (" << Addr << ") = " << "0x" << std::hex << val << std::endl;
    }
    MemoryEntry(VOID* Addr, byte val[], int length){
        Address = Addr;
        value = length;
        for (int i = 0; i < length; i++)
        {
            
        }
        Bytevalue = malloc(length);
        memcpy(Bytevalue, val, length);
        sizeInBytes = length;
    }
    MemoryEntry(VOID* Addr, byte val[], size_t size) {
        Address = Addr;
        sizeInBytes = size;
    }
    
    /*
    * ~MemoryEntry()
    {
        if (Bytevalue)
        {
            free(&Bytevalue);
        }
    }
    */
    
};

//std::unordered_map<std::string, std::vector<MemoryEntry>> GMemoryMap;
//std::unordered_map<MemoryModule, std::vector<MemoryEntry>> GMemoryMap;
std::unordered_map<VOID *, std::vector<MemoryEntry>> GMemoryMap;

DWORD GetProcId(const wchar_t* procName);
uintptr_t GetModuleBaseAddress(DWORD procID, const wchar_t* modName);
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets);

BOOL SetPrivilege(HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


std::vector<std::pair<HMODULE, DWORD>> GetModules(HANDLE hProcess) {
    std::vector<std::pair<HMODULE, DWORD>> modules;

    if (hProcess != NULL) {
        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                MODULEINFO mi;
                GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi));
                modules.push_back(std::make_pair(hMods[i], mi.SizeOfImage));
            }
        }
        else {
            std::cerr << "EnumProcessModules failed. Error code: " << GetLastError() << std::endl;
        }
    }

    return modules;
}

long TotalSizeOfMemory = 0;
long TotalADDRFound = 0;

#include <vector>
#include <iostream>
#include <windows.h>
#include <utility> // For std::pair
#include <map>     // For GMemoryMap type
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <algorithm> // For std::min
#include <cstdint>   // For uintptr_t

// --- Assume these exist ---
typedef unsigned char byte;
// struct MemoryEntry { /* ... constructors ... */ };
// std::map<VOID*, std::vector<MemoryEntry>> GMemoryMap; // Use VOID* or uintptr_t as key for general regions
// DWORD TotalSizeOfMemory = 0;
// DWORD TotalADDRFound = 0;
// --- End Assumptions ---


// Function to check if memory protection flags allow reading
bool isReadable(DWORD protect) {
    return (protect & PAGE_READONLY ||
        protect & PAGE_READWRITE ||
        protect & PAGE_EXECUTE_READ ||
        protect & PAGE_EXECUTE_READWRITE ||
        protect & PAGE_WRITECOPY ||        // Often readable
        protect & PAGE_EXECUTE_WRITECOPY); // Often readable
}

// --- New function to scan ALL committed, readable memory regions ---
int ScanAllProcessMemory(DWORD processId, HANDLE hProcess, byte BytePattern[], int Bytelength)
{
    if (hProcess == NULL) {
        std::cerr << "ScanAllProcessMemory Error: Invalid process handle." << std::endl;
        return 1;
    }
    if (BytePattern == nullptr || Bytelength <= 0) {
        std::cerr << "ScanAllProcessMemory Error: Invalid byte pattern or length." << std::endl;
        return 1;
    }

    TotalADDRFound = 0;
    TotalSizeOfMemory = 0;
    GMemoryMap.clear(); // Clear previous results if needed

    MEMORY_BASIC_INFORMATION mbi;
    // Use unsigned pointer type for address arithmetic
    unsigned char* currentAddress = nullptr; // Start querying from address 0

    std::cout << "Starting full memory scan..." << std::endl;

    // Loop through memory regions using VirtualQueryEx
    while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // Check if the region is committed memory and readable
        // Also check against guard pages and inaccessible pages
        if (mbi.State == MEM_COMMIT && isReadable(mbi.Protect) && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS))
        {
            std::cout << "Scanning Region Base: " << mbi.BaseAddress << " Size: " << mbi.RegionSize << " Protect: 0x" << std::hex << mbi.Protect << std::dec << std::endl;

            // Allocate buffer for this region
            // Be careful with VERY large regions - consider reading in chunks
            // For simplicity here, read the whole region if feasible
            if (mbi.RegionSize > 0) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                    if (bytesRead > 0) {
                        // Adjust buffer size if partial read (unlikely for whole region reads unless protection changed)
                        if (bytesRead < buffer.size()) {
                            buffer.resize(bytesRead);
                            std::cerr << "Warning: Partial read (" << bytesRead << "/" << mbi.RegionSize << ") from region " << mbi.BaseAddress << std::endl;
                        }

                        TotalSizeOfMemory += buffer.size();

                        // *** Use your existing pattern scanning logic here ***
                        for (size_t i = 0; i + Bytelength <= buffer.size(); ++i) {
                            bool match = true;
                            for (int ii = 0; ii < Bytelength; ++ii) {
                                if (BytePattern[ii] != buffer[i + ii]) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                // Calculate the absolute address found
                                VOID* foundAddress = static_cast<char*>(mbi.BaseAddress) + i;

                                // Store the result - Use BaseAddress as the key maybe?
                                // Or just a single global list if region doesn't matter.
                                // Using BaseAddress as key:
                                if (Bytelength == 1) {
                                    MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern[0]);
                                    GMemoryMap[mbi.BaseAddress].push_back(MemoryEntryToAdd);
                                }
                                else {
                                    MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern, Bytelength);
                                    GMemoryMap[mbi.BaseAddress].push_back(MemoryEntryToAdd);
                                }
                                TotalADDRFound++;
                            }
                        } // End pattern scan loop
                    } // End if bytesRead > 0
                }
                else {
                    DWORD lastError = GetLastError();
                    // ERROR_PARTIAL_COPY is less likely here, report others
                    std::cerr << "Failed to read memory region " << mbi.BaseAddress << ". Error code: " << lastError << std::endl;
                }
            } // End if RegionSize > 0

        } // End if region is suitable

        // Move to the next region
        currentAddress = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;

        // Basic check for wrapping around address space (might need adjustment for 32/64 bit limits)
        if (currentAddress < static_cast<unsigned char*>(mbi.BaseAddress)) {
            break; // Address wrapped around, stop scanning
        }

    } // End VirtualQueryEx loop

    std::cout << "Full Scan Complete. Total Addresses Found: " << std::dec << TotalADDRFound << std::endl;
    std::cout << "Total Memory Scanned: " << (TotalSizeOfMemory / 1024) << " KB" << std::endl;
    return 0; // Indicate success
}

int ScanHeapAndStackMemory(DWORD processId, HANDLE hProcess, byte BytePattern[], int Bytelength)
{
    // Validate inputs
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        std::cerr << "ScanHeapAndStackMemory Error: Invalid process handle provided." << std::endl;
        return 1; // Indicate failure
    }
    if (BytePattern == nullptr || Bytelength <= 0) {
        std::cerr << "ScanHeapAndStackMemory Error: Invalid byte pattern or length provided." << std::endl;
        return 1; // Indicate failure
    }

    // Reset counters and clear previous results map
    TotalADDRFound = 0;
    TotalSizeOfMemory = 0;
    GMemoryMap.clear();

    MEMORY_BASIC_INFORMATION mbi;
    // Start querying from the beginning of the process's address space
    unsigned char* currentAddress = nullptr;

    std::cout << "Starting Heap and Stack memory scan (scanning MEM_PRIVATE regions)..." << std::endl;

    // Loop through all memory regions using VirtualQueryEx
    while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // --- Filter for likely Heap/Stack Regions ---
        // Conditions:
        // 1. Memory must be committed (not just reserved or free).
        // 2. Memory type must be PRIVATE (excludes MEM_IMAGE and MEM_MAPPED).
        // 3. Memory must be readable.
        // 4. Memory must not be a guard page (reading triggers exception).
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE && // <<< KEY CHANGE: Only include Private memory
            isReadable(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS))
        {
            // This region is likely heap, stack, or other private allocation. Scan it.
            std::cout << "Scanning Private Region Base: 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                << " Size: " << std::dec << mbi.RegionSize
                << " Protect: 0x" << std::hex << mbi.Protect << std::dec << std::endl;

            // Proceed only if region has a valid size
            if (mbi.RegionSize > 0) {
                std::vector<BYTE> buffer;
                // Resize cautiously to avoid massive allocations for unexpected RegionSize values
                try {
                    buffer.resize(mbi.RegionSize);
                }
                catch (const std::bad_alloc& ex) {
                    std::cerr << "Warning: Failed to allocate buffer of size " << mbi.RegionSize
                        << " for region 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                        << ". Skipping region. Error: " << ex.what() << std::dec << std::endl;
                    // Move to the next region address
                    currentAddress = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
                    // Check for address wrap around before continuing loop
                    if (currentAddress < static_cast<unsigned char*>(mbi.BaseAddress)) break;
                    continue; // Skip to next VirtualQueryEx call
                }

                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                    if (bytesRead > 0) {
                        // Adjust buffer size if partial read occurred
                        if (bytesRead < buffer.size()) {
                            buffer.resize(bytesRead);
                            std::cerr << "Warning: Partial read (" << bytesRead << "/" << mbi.RegionSize << ") from private region 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << std::dec << std::endl;
                        }

                        TotalSizeOfMemory += buffer.size();

                        // Scan the buffer for the specified byte pattern
                        for (size_t i = 0; i + Bytelength <= buffer.size(); ++i) {
                            bool match = true;
                            for (int ii = 0; ii < Bytelength; ++ii) {
                                if (BytePattern[ii] != buffer[i + ii]) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                VOID* foundAddress = static_cast<char*>(mbi.BaseAddress) + i;
                                // Store result (using BaseAddress as key groups findings by region)
                                // Ensure MemoryEntry constructor matches your definition
                                if (Bytelength == 1) {
                                    MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern[0]);
                                    GMemoryMap[mbi.BaseAddress].push_back(MemoryEntryToAdd);
                                }
                                else {
                                    MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern, Bytelength);
                                    GMemoryMap[mbi.BaseAddress].push_back(MemoryEntryToAdd);
                                }
                                TotalADDRFound++;
                            }
                        } // End pattern scan loop
                    } // End if bytesRead > 0
                }
                else {
                    DWORD lastError = GetLastError();
                    // Don't necessarily treat ERROR_PARTIAL_COPY (299) as fatal if some bytes were read (handled above)
                    // but report other errors preventing reading the region.
                    if (lastError != ERROR_PARTIAL_COPY || bytesRead == 0) {
                        std::cerr << "Failed to read private memory region 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << ". Error code: " << lastError << std::dec << std::endl;
                    }
                }
            } // End if RegionSize > 0

        } // End if region matches criteria

        // Move pointer to the beginning of the next region for the next query
        // Important: Perform calculation using uintptr_t to avoid pointer overflow issues
        uintptr_t nextAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        // Check for address space wrap around - if next address is lower than base, we're done.
        if (nextAddress < reinterpret_cast<uintptr_t>(mbi.BaseAddress)) {
            break;
        }
        // Update currentAddress for the next VirtualQueryEx call
        currentAddress = reinterpret_cast<unsigned char*>(nextAddress);

    } // End VirtualQueryEx loop

    std::cout << "Heap/Stack Scan Complete. Total Addresses Found: " << std::dec << TotalADDRFound << std::endl;
    std::cout << "Total Private Memory Scanned: " << (TotalSizeOfMemory / 1024) << " KB" << std::endl;
    return 0; // Indicate success
}

int ReadAllProcModules(DWORD processId, HANDLE hProcess, byte BytePattern[], int Bytelength)
{
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
        return 1;
    }
    if (BytePattern == nullptr || Bytelength <= 0) {
        std::cerr << "ReadAllProcModules Error: Invalid byte pattern or length." << std::endl;
        return 1; // Indicate failure
    }

    // Get all modules in the target process
    std::vector<std::pair<HMODULE, DWORD>> modules = GetModules(hProcess);
    if (modules.empty()) {
        std::cerr << "ReadAllProcModules Warning: No modules found or failed to get modules for process ID " << processId << "." << std::endl;
        // May not be an error, could be permissions or the process has no modules loaded in a standard way
    }

    // Loop through each module and read memory
    for (const auto& module : modules) {
        if (!module.first || module.second == 0) {
            std::cerr << "ReadAllProcModules Warning: Skipping invalid module entry (Address: " << module.first << ", Size: " << module.second << ")" << std::endl;
            continue; // Skip null module handles or zero size
        }
        // Allocate buffer to store module's memory
        std::vector<BYTE> buffer(module.second);

        // Read memory from the module's base address
        //HANDLE ModuleAddress = module.first;

        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, module.first, buffer.data(), buffer.size(), &bytesRead)) {
            if (bytesRead == 0) {
                // Read success but zero bytes? Maybe module size reported incorrectly or page protection changed.
                std::cerr << "ReadAllProcModules Warning: Read 0 bytes from module " << module.first << " despite reported size " << module.second << std::endl;
                continue;
            }
            if (bytesRead < buffer.size()) {
                // Partially successful read - resize buffer to actual bytes read
                std::cerr << "ReadAllProcModules Warning: Read only " << bytesRead << " bytes from module " << module.first << " (expected " << module.second << ")" << std::endl;
                buffer.resize(bytesRead); // VERY IMPORTANT: adjust buffer size to what was actually read
            }



            TotalSizeOfMemory += buffer.size();
            // Process the read data here (e.g., print or manipulate)
            // For demonstration, let's print the first few bytes of each module
            std::cout << "Module Base Address: " << module.first << " Module Size: " << buffer.size() << std::endl;
            /*
            std::cout << "First 16 bytes of module:" << std::endl;
            for (size_t i = 0; i < std::min<size_t>(16, buffer.size()); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
            }
            */

            for (size_t i = 0; i < buffer.size(); i++) {
                /*
                if (Bytelength == 1) //This will not work with a pointer
                {
                    if (BytePattern[0] == buffer[i])
                    {

                        //MemoryModule MemoryRegionKey = MemoryModule(DWORD(module.first), "Module");
                        VOID* test = module.first;
                        VOID* test2 = module.first + 1;
                        VOID* test3 = ((char*)module.first) + i;

                        MemoryEntry MemoryEntryToAdd = MemoryEntry(((char*)module.first) + i, BytePattern[0]);
                        GMemoryMap[module.first].push_back(MemoryEntryToAdd);
                        TotalADDRFound += 1;
                    }
                }
                else
                {
                    int lenth = sizeof(BytePattern);
                    bool match = true;
                    for (size_t ii = 0; ii < Bytelength; ii++)
                    {    
                        if (BytePattern[ii] != buffer[i + ii])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        MemoryEntry MemoryEntryToAdd = MemoryEntry(((char*)module.first) + i, BytePattern, Bytelength);
                        GMemoryMap[module.first].push_back(MemoryEntryToAdd);
                        TotalADDRFound += 1;
                    }
                }
                */

                bool match = true; // Assume match initially
                // Compare the pattern byte-by-byte
                for (int ii = 0; ii < Bytelength; ++ii) {
                    if (BytePattern[ii] != buffer[i + ii]) {
                        match = false;
                        break; // Mismatch found, break inner loop
                    }
                }

                // If the entire pattern matched
                if (match) {
                    // Calculate the actual address in the target process's memory space
                    void * foundAddress = (module.first) + i;

                    // Use the appropriate constructor for MemoryEntry
                    if (Bytelength == 1) {
                        MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern[0]);
                        GMemoryMap[module.first].push_back(MemoryEntryToAdd);
                    }
                    else {
                        MemoryEntry MemoryEntryToAdd = MemoryEntry(foundAddress, BytePattern, Bytelength);
                        GMemoryMap[module.first].push_back(MemoryEntryToAdd);
                    }

                    TotalADDRFound++;
                    // Optional: Add a small delay or yield if scanning is too CPU intensive
                    // Sleep(0); // Yield execution
                }
            }
        }
        else {
            DWORD lastError = GetLastError();// Only report error if it wasn't expected (e.g., ERROR_PARTIAL_COPY might be okay if buffer resized)
            if (lastError != ERROR_PARTIAL_COPY || bytesRead == 0) { // Report error if it's not just a partial copy
                std::cerr << "Failed to read memory from module " << module.first << ". Error code: " << lastError << std::endl;
            }
        }

        //std::cout << "Total Memorysize: " << std::dec << (TotalSizeOfMemory / 1024 / 1024) << "(MBs)" << std::endl;
        
    }
    std::cout << "Scan Complete. Total Addresses Found: " << std::dec << TotalADDRFound << std::endl;
    std::cout << "Total Memory Scanned: " << (TotalSizeOfMemory / 1024) << " KB" << std::endl;
    return 0; // Indicate success
}

void ReadSpecificAddress(DWORD processId, HANDLE hProcess)
{
    //Getmodulebaseaddress
    uintptr_t moduleBase = GetModuleBaseAddress(processId, ProcName);

    //Resolve base address of the pointer chain
    uintptr_t dynamicPtrBaseAddr = moduleBase + 0x10f4f4;

    std::cout << "DynamicPtrBaseAddr = " << "0x" << std::hex << dynamicPtrBaseAddr << std::endl;

    //Resolve our ammo pointer chain
    std::vector<unsigned int> ammoOffsets = { 0x374, 0x14, 0x0 };
    uintptr_t ammoAddr = FindDMAAddy(hProcess, dynamicPtrBaseAddr, ammoOffsets);

    std::cout << "ammoAddr = " << "0x" << std::hex << ammoAddr << std::endl;

    //Read Ammo value
    int ammoValue = 0;

    ReadProcessMemory(hProcess, (BYTE*)ammoAddr, &ammoValue, sizeof(ammoValue), nullptr);
    //std::cout << "Current ammo = " << std::dec << ammoValue << std::endl;

    //Write to it
    int newAmmo = 1338;
    WriteProcessMemory(hProcess, (BYTE*)ammoAddr, &newAmmo, sizeof(newAmmo), nullptr);

    //Read out again
    ReadProcessMemory(hProcess, (BYTE*)ammoAddr, &ammoValue, sizeof(ammoValue), nullptr);

    //std::cout << "New ammo = " << std::dec << ammoValue << std::endl;
}

void CheckChanged(DWORD processId, HANDLE hProcess, std::unordered_map<VOID*, std::vector<MemoryEntry>>& LMemoryMap, bool RemoveIfChangedInsteadOfKeep)
{
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        std::cerr << "CheckChanged Error: Invalid process handle." << std::endl;
        return; // Cannot proceed
    }

    long totalAddressesBefore = 0;
    for (const auto& pair : LMemoryMap) {
        totalAddressesBefore += pair.second.size();
    }
    if (totalAddressesBefore == 0) {
        std::cout << "CheckChanged: No addresses in map to check." << std::endl;
        return;
    }
    std::cout << "Checking changes for " << totalAddressesBefore << " addresses..." << std::endl;

    // List to store keys whose vectors become empty
    std::vector<VOID*> keysToRemove;

    // Iterate through the map (Module/Region Base -> Vector of MemoryEntry)
    // Use iterator loop to potentially allow direct erase later, though storing keys is safer
    // Sticking with range-based for now and collecting keys afterward for safety.
    for (auto& pair : LMemoryMap) {
        VOID* key = pair.first;                     // Module/Region base address
        std::vector<MemoryEntry>& entryVector = pair.second; // Get reference to the vector

        // --- Process the vector for this key ---
        // Iterate backwards through the vector to allow safe element removal within the vector
        for (int i = static_cast<int>(entryVector.size()) - 1; i >= 0; --i)
        {
            // Check index validity just in case (shouldn't be needed with correct loop)
            if (i >= static_cast<int>(entryVector.size())) continue;

            MemoryEntry currentEntry = entryVector[i]; // Make a copy to safely access original value
            VOID* entryAddr = currentEntry.Address;    // Address of the specific byte

            // Buffer to read the current value from memory (1 byte only)
            byte currentMemValueBuffer[1] = { 0 };
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, entryAddr, currentMemValueBuffer, 1, &bytesRead) && bytesRead == 1)
            {
                byte currentMemValue = currentMemValueBuffer[0];
                // Assumes MemoryEntry.value correctly stores the single previous byte
                byte previousValue = currentEntry.value;

                bool valueChanged = (currentMemValue != previousValue);

                // Determine if the current entry should be removed from the vector
                bool shouldRemoveFromVector = false;
                if (RemoveIfChangedInsteadOfKeep) { // Mode: Remove if CHANGED
                    shouldRemoveFromVector = valueChanged;
                }
                else { // Mode: Remove if SAME (Keep if Changed)
                    shouldRemoveFromVector = !valueChanged;
                }

                // Perform removal from vector or update the value
                if (shouldRemoveFromVector) {
                    entryVector.erase(entryVector.begin() + i);
                }
                else {
                    // If we are keeping CHANGED entries (!RemoveIfChangedInsteadOfKeep)
                    // and the value actually changed, update the stored value.
                    if (!RemoveIfChangedInsteadOfKeep && valueChanged) {
                        // *** Update the value IN the vector ***
                        entryVector[i].value = currentMemValue;

                        // Optional logging
                        if (totalAddressesBefore < 20) { // More verbose logging for small sets
                            std::cout << "Change Kept: Address: 0x" << std::hex << reinterpret_cast<uintptr_t>(entryAddr)
                                << " Before: 0x" << (int)previousValue
                                << " Now: 0x" << (int)currentMemValue << std::dec << std::endl;
                        }
                    }
                    // If keeping SAME values (RemoveIfChangedInsteadOfKeep == true && !valueChanged), do nothing.
                }
            }
            else // ReadProcessMemory failed for this specific address
            {
                DWORD lastError = GetLastError();
                std::cerr << "Warning: Unable to read from address 0x" << std::hex << reinterpret_cast<uintptr_t>(entryAddr)
                    << ". Error: " << lastError << ". Removing entry from list." << std::dec << std::endl;
                // Remove entry from vector if memory becomes unreadable
                entryVector.erase(entryVector.begin() + i);
            }
        } // End inner loop (vector iteration)

        // --- Check if the vector for this key is now empty ---
        if (entryVector.empty()) {
            keysToRemove.push_back(key); // Mark this map key for removal
        }

    } // End outer loop (map iteration)


    // --- Remove map entries whose vectors became empty ---
    if (!keysToRemove.empty()) {
        std::cout << "Removing " << keysToRemove.size() << " empty region entries from the map..." << std::endl;
        for (VOID* key : keysToRemove) {
            LMemoryMap.erase(key); // Erase the key-value pair from the map
            // Optional feedback
            // std::cout << "Removed empty entry for base: 0x" << std::hex << reinterpret_cast<uintptr_t>(key) << std::dec << std::endl;
        }
    }

    // --- Update final counts / feedback ---
    long totalAddressesAfter = 0;
    for (const auto& pair : LMemoryMap) {
        totalAddressesAfter += pair.second.size();
    }
    // If TotalADDRFound is meant to reflect the live count in the map:
    // TotalADDRFound = totalAddressesAfter;

    std::cout << "CheckChanged complete. " << totalAddressesAfter << " addresses remaining in "
        << LMemoryMap.size() << " regions." << std::endl;
}


void PrintBytesHex(const byte* data, size_t size, std::ostream& os = std::cout) {
    std::ios_base::fmtflags original_flags = os.flags(); // Save original formatting flags
    os << std::hex << std::setfill('0');
    for (size_t k = 0; k < size; ++k) {
        os << std::setw(2) << static_cast<int>(data[k]);
    }
    os.flags(original_flags); // Restore original formatting flags
}

void CheckAllRegisters(DWORD processId, HANDLE hProcess, std::unordered_map<VOID*, std::vector<MemoryEntry>>& LMemoryMap, byte Pattern[])
{
    // Buffer for reading memory. Max size for a 64-bit value is 8 bytes.
    byte currentMemoryValueBuffer[8];

    long TotalAddresses = 0;
    for (auto& pair : LMemoryMap) {
        TotalAddresses += pair.second.size();
    }

    // Iterate over each key (e.g., module base address) in the map
    for (auto& mapPair : LMemoryMap) {
        VOID* key = mapPair.first;
        std::vector<MemoryEntry>& entriesInVector = mapPair.second; // Use a reference

        // Iterate backwards through the vector to allow safe removal of elements
        for (int i = static_cast<int>(entriesInVector.size()) - 1; i >= 0; --i)
        {
            // Get a copy of the current entry. If MemoryEntry is large, consider using a reference
            // up to the point of potential erasure, but a copy is safer if its fields are modified locally.
            MemoryEntry currentEntry = entriesInVector.at(i);
            VOID* entryAddress = currentEntry.Address;
            size_t valueSizeInBytes = currentEntry.sizeInBytes; // This field MUST exist in your MemoryEntry struct

            // Validate the size to prevent buffer overflows and nonsensical reads
            if (valueSizeInBytes == 0 || valueSizeInBytes > sizeof(currentMemoryValueBuffer)) {
                // Optionally, print a warning or error for invalid sizes
                // std::cerr << "Warning: Invalid sizeInBytes (" << valueSizeInBytes
                //           << ") for MemoryEntry at address " << entryAddress << ". Skipping." << std::endl;
                // Depending on policy, you might want to remove such an entry:
                // entriesInVector.erase(entriesInVector.begin() + i);
                // TotalADDRFound -= 1; // If removed
                continue; // Skip this entry
            }

            SIZE_T bytesActuallyRead = 0; // Variable to store the number of bytes read by ReadProcessMemory
            if (ReadProcessMemory(hProcess, entryAddress, currentMemoryValueBuffer, valueSizeInBytes, &bytesActuallyRead))
            {
                if (bytesActuallyRead == valueSizeInBytes) {
                    // Successfully read the expected number of bytes. Now compare with the Pattern.
                    // memcmp returns 0 if the contents are equal.
                    if (memcmp(currentMemoryValueBuffer, Pattern, valueSizeInBytes) != 0)
                    {
                        // Values do not match the pattern, so remove the entry.
                        entriesInVector.erase(entriesInVector.begin() + i);
                        TotalADDRFound -= 1; // Decrement the global/member count of "found" addresses.

                        // Conditional logging, similar to the original code.
                        if (TotalADDRFound % 10000 == 0 || TotalAddresses < 20)
                        {
                            std::cout << "Removing ModuleAddress: 0x" << std::hex << key
                                << " Address: " << entryAddress
                                << " - BeforeValue: 0x" << currentEntry.value // Assumes 'value' holds a printable original value
                                << " NowValue: 0x";
                            PrintBytesHex(currentMemoryValueBuffer, valueSizeInBytes, std::cout);
                            std::cout << " Compared to (Pattern): 0x";
                            PrintBytesHex(Pattern, valueSizeInBytes, std::cout);
                            std::cout << "\n";
                            // Updated status line for clarity
                            std::cout << "LMemoryMap - Entries in current vector: " << std::dec << entriesInVector.size()
                                << ". Total valid entries globally: " << TotalADDRFound << std::endl;
                        }
                    }
                    else
                    {
                        // Values match the pattern, keep the entry.
                        // Optional: log that the entry was kept.
                        // if (TotalADDRFound % 10000 == 0 || TotalAddresses < 20) { // Or some other condition
                        //     std::cout << "Keeping ModuleAddress: 0x" << std::hex << key << " Address: " << entryAddress << " - Value matches pattern.\n";
                        // }
                    }
                }
                else {
                    // ReadProcessMemory succeeded but did not read the expected number of bytes.
                    // This is an unusual situation and might indicate an issue.
                    // std::cerr << "Error: ReadProcessMemory at " << entryAddress
                    //           << " read " << bytesActuallyRead << " bytes, expected " << valueSizeInBytes << " bytes. Removing entry." << std::endl;
                    entriesInVector.erase(entriesInVector.begin() + i); // Remove problematic entry
                    TotalADDRFound -= 1;
                }
            }
            else
            {
                // ReadProcessMemory failed.
                // std::cerr << "Error: Unable to read memory at " << entryAddress << " (Error code: " << GetLastError() << "). Removing entry." << std::endl;
                entriesInVector.erase(entriesInVector.begin() + i); // Remove entry that couldn't be read
                TotalADDRFound -= 1;

                // Conditional logging for read failures.
                if (TotalADDRFound % 10000 == 0 || TotalAddresses < 20)
                {
                    std::cout << "Unable to read from Address: " << entryAddress << " (Error: " << GetLastError() << "). Removing entry." << std::endl;
                    std::cout << "LMemoryMap - Entries in current vector: " << std::dec << entriesInVector.size()
                        << ". Total valid entries globally: " << TotalADDRFound << std::endl;
                }
            }
        }
        // If entriesInVector becomes empty, you could consider removing mapPair.first from LMemoryMap.
        // However, that requires careful handling of map iterators if LMemoryMap itself is being modified
        // while iterating it. The current structure iterates copies of keys or references to values,
        // so modifying the vector is fine, but modifying the map itself within this loop is more complex.
    }
}

void DumpMemory()
{
    std::cout << "\r\nElements in GMemoryMap:\n";
    long ItemCount = 0;
    long PageCount = 0;
    for (const auto& pair : GMemoryMap) {
        PageCount++;
        //MemoryModule key = pair.first;
        VOID* key = pair.first;
        std::vector<MemoryEntry> obj = pair.second;
        /*
            for (const auto& obj : GMemoryMap["key1"]) {
                std::cout << obj.value << "\n";
            }
        */
        for (const auto& myobj : obj) 
        {
                //MemoryEntry Obj = pair.second.at(i);
                VOID* ObjAddr = myobj.Address;
                

                if (myobj.Bytevalue == NULL)
                {
                    char buffer[1] = { 0 };
                    if (!ReadProcessMemory(hProcess, ObjAddr, &buffer, 1, nullptr))
                    {
                        //Unable to get mem
                    }
                    std::cout << "ModuleAddress: 0x" << std::hex << key << " Address: " << myobj.Address << " - InCache:" << std::dec << myobj.value << " InMem: " << int(buffer[0]) << "\n";
                }
                else
                {
                    unsigned char * buffer = (unsigned char *)(malloc(myobj.value));
                    if (!ReadProcessMemory(hProcess, ObjAddr, buffer, myobj.value, nullptr))
                    {
                        //Unable to get mem
                    }
                    std::cout << "ModuleAddress: 0x" << std::hex << key << " Address: " << myobj.Address << " - ByteLen:" << std::dec << myobj.value << "\n";
                    unsigned char * bytePtr = static_cast<unsigned char*>(myobj.Bytevalue);

                    std::cout << "InCache: ";
                    for (size_t i = 0; i < std::min<size_t>(16, myobj.value); i++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytePtr[i]) << " ";
                    }
                    std::cout << std::endl;

                    std::cout << "InMem  : ";

                    for (size_t i = 0; i < std::min<size_t>(16, myobj.value); i++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
                    }
                    std::cout << std::endl;

                    /*
                    if (!WriteProcessMemory(hProcess, myobj.Bytevalue, (void *)buffer, 1, nullptr)) {
                        std::cerr << "Failed to write memory at address: " << myobj.Bytevalue << std::endl;
                    }
                    else {
                        std::cout << "Successfully updated " << myobj.value << " bytes from address " << ObjAddr << " to " << myobj.Bytevalue << std::endl;
                    }
                    */
                    free(buffer);
                }
                ItemCount++;
        }
    }

    //std::vector<MemoryEntry> Memory = GMemoryMap[1];

    std::cout << std::endl << "LMemoryMap - PageCount:" << std::dec << PageCount << " ItemCount" << ItemCount << std::endl;
}

DWORD GetProcId(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {

            do
            {
                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procID, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}

int PrintModules(DWORD processID, HANDLE hProcess)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf("\nProcess ID: %u\n", processID);

    // Get a list of all the modules in this process.

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }

    return 0;
}

void ResumeProcess(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread != NULL) {
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        CloseHandle(hSnapshot);
    }
}

void SuspendProcess(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread != NULL) {
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        CloseHandle(hSnapshot);
    }
}

/*
std::ostream& operator<<(std::ostream& os, int b)
{
    return os << std::bitset<8>(int(b));
}
*/

void DisplayHelp()
{
    // Using C++11 Raw String Literal for easier multi-line formatting
    std::cout << R"(
Available commands:

--- Process Targeting ---
  ProcessName     Set the process image name (e.g., notepad.exe).
  clear           Clear the cached memory list from previous scans.
  suspend         Suspend the target process.
  resume          Resume the target process.

--- Scanning (Populates Memory Cache) ---
  scanstring      Scan for a specified string (ASCII).
  scan8           Scan for a specified int8 value (-128 to 127).
  scan16          Scan for a specified int16 value (-32768 to 32767).
  scan32          Scan for a specified int32 value.
  scan64          Scan for a specified int64 value.

--- Refinement (Filters Memory Cache) ---
  same            (NYI) Filter cache for addresses whose values haven't changed.
  changed         (NYI) Filter cache for addresses whose values have changed.

--- Writing (Requires Address Selection) ---
  wint8           Write an int8 value to cached address(es).
                  Select target by index [1-N] if <=10 addresses cached,
                  or specify single target address if >10 addresses cached.
  wint16          Write an int16 value to cached address(es). (Select by index or specify address).
  wint32          Write an int32 value to cached address(es). (Select by index or specify address).
  wint64          Write an int64 value to cached address(es). (Select by index or specify address).
  writeunistring  (NYI) Write a Unicode string to a specified address.
  writestring     (NYI) Write an ASCII string to a specified address.
  scanandoverwrite (NYI) Scan for a pattern and overwrite it.

--- Monitoring & Info ---
  watch           (NYI) Start monitoring cached memory for changes.
  stopwatch       (NYI) Stop monitoring memory for changes.
  dump            (NYI) Print information about loaded modules or memory regions.
  recentlyremoved (NYI) Display recently removed memory addresses.

--- General ---
  help            Display this help message.
  version         Display version information.
  exit / quit     Exit the program.
)" << std::endl;
    // NYI = Not Yet Implemented (assumed for some commands based on context)
}

void DisplayVersion()
{
    std::cout << R"(1.0)" << std::endl;
}

bool stopFlag = false;

void threadFunction() {
    while (true)
    {
        if (stopFlag) { break; }
        byte Buffer[1] = { 0 };
        for (auto& pair : GMemoryMap) {
            if (stopFlag) { break; }
            VOID* key = pair.first;
            std::vector<MemoryEntry>& Tempobj = pair.second;

            for (int i = pair.second.size() - 1; i >= 0; i--)
            {
                if (stopFlag) { break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                MemoryEntry & Obj = pair.second.at(i);
                VOID* ObjAddr = Obj.Address;
                if (ReadProcessMemory(hProcess, ObjAddr, &Buffer, 1, nullptr))
                {
                    char a = Buffer[0];
                    char b = Obj.value;
                    if (a != b)
                    {
                        //std::cout << "ModuleAddress: 0x" << std::hex << key << " Address: " << ObjAddr << " - Value: 0x" << std::hex << Obj.value << " Compared to: 0x" << (int)(Buffer[0]) << "\n";
                        //Tempobj.erase(Tempobj.begin() + i);

                        std::cout << "Watch found a value change @ ModuleAddress: 0x" << std::hex << key << " Address: " << ObjAddr << " - BeforeValue: 0x" << std::hex << Obj.value << " NowValue: 0x" << std::hex << (int)(Buffer[0]) << "\n";
                        Obj.value = Buffer[0];

                        //TotalADDRFound -= 1;
                    }
                    else
                    {
                        //std::cout << "Keeping ModuleAddress: 0x" << std::hex << key << " Address: " << ObjAddr << " - BeforeValue: 0x" << std::hex << Obj.value << " NowValue: 0x" << std::hex << (int)(Buffer[0]) << " Compared to: 0x" << int(Pattern[0]) << "\n";
                    }
                }
                else
                {
                    std::cout << "Unable to read from: " << Obj.Address << "\n";
                }
            }
        }
        if (stopFlag) { break; }
    }
    
}

// Parses input like "1,3,5" or "2-4" or "1, 3-5, 9" into a set of 0-based indices
// Returns false if parsing fails or an index is out of bounds.
bool ParseIndices(const std::string& input, size_t maxValidIndex, std::set<size_t>& selectedIndices) {
    selectedIndices.clear();
    std::stringstream ss(input);
    std::string segment;

    while (std::getline(ss, segment, ',')) { // Split by comma
        segment.erase(segment.begin(), std::find_if(segment.begin(), segment.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        segment.erase(std::find_if(segment.rbegin(), segment.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), segment.end());

        if (segment.empty()) continue;

        size_t hyphenPos = segment.find('-');
        if (hyphenPos == std::string::npos) { // Single index
            try {
                long long index_ll = std::stoll(segment);
                if (index_ll < 1 || (unsigned long long)index_ll > maxValidIndex + 1) {
                    std::cerr << "Error: Index " << index_ll << " is out of range (1-" << maxValidIndex + 1 << ")." << std::endl;
                    return false;
                }
                selectedIndices.insert(static_cast<size_t>(index_ll - 1));
            }
            catch (...) {
                std::cerr << "Error: Invalid index format '" << segment << "'." << std::endl;
                return false;
            }
        }
        else { // Range
            std::string startStr = segment.substr(0, hyphenPos);
            std::string endStr = segment.substr(hyphenPos + 1);
            startStr.erase(startStr.begin(), std::find_if(startStr.begin(), startStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            startStr.erase(std::find_if(startStr.rbegin(), startStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), startStr.end());
            endStr.erase(endStr.begin(), std::find_if(endStr.begin(), endStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            endStr.erase(std::find_if(endStr.rbegin(), endStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), endStr.end());

            try {
                long long start_ll = std::stoll(startStr);
                long long end_ll = std::stoll(endStr);
                if (start_ll < 1 || (unsigned long long)start_ll > maxValidIndex + 1 ||
                    end_ll < 1 || (unsigned long long)end_ll > maxValidIndex + 1 ||
                    start_ll > end_ll) {
                    std::cerr << "Error: Invalid range '" << segment << "'. Indices out of range (1-" << maxValidIndex + 1 << ") or start > end." << std::endl;
                    return false;
                }
                for (long long i = start_ll; i <= end_ll; ++i) {
                    selectedIndices.insert(static_cast<size_t>(i - 1));
                }
            }
            catch (...) {
                std::cerr << "Error: Invalid range format '" << segment << "'." << std::endl;
                return false;
            }
        }
    }
    return !selectedIndices.empty();
}

std::thread t;

void menu(const std::string& userInput)
{


    /*
    std::vector<std::pair<std::intptr_t, std::vector<byte[]>>> MyArrayListOfAddresses;
    std::map<std::intptr_t, std::vector<byte[]>> MyDictionaryOfAddresses;
    std::map < std::intptr_t, std::pair < std::vector < byte[] >, std::vector<byte[] >> > MyArrayListOfAddressesRecentlyRemoved;
    */

    std::intptr_t MyProcessId = 0; // Initialize with an appropriate value

    std::string ValueToSearchFor;
    std::string IntValue;
    int Scans = 1;

    std::wstring wProcessName; // Target wide string

    if (userInput == "ProcessName") {
        std::string ProcessName;
        std::cout << "Process Image Name (ex. notepad.exe): ";

        std::getline(std::cin, ProcessName);
        //processId = GetProcId((const * wchar_t)ProcessName);
        ProcessName.erase(ProcessName.begin(), std::find_if(ProcessName.begin(), ProcessName.end(), [](unsigned char ch) {
            // Find the first character that is NOT whitespace
            return !std::isspace(ch);
            }));

        int procNameLen = ProcessName.length();
        if (procNameLen > 0) {
            // Determine required size for the wide string buffer
            int wideCharLen = MultiByteToWideChar(
                CP_ACP,       // Code Page (ANSI Code Page) - or CP_UTF8 if input is UTF-8
                0,            // Flags
                ProcessName.c_str(), // Source char string
                procNameLen,  // Length of source string (excluding null)
                NULL,         // Output buffer (NULL to get size)
                0             // Output buffer size (0 to get size)
            );

            if (wideCharLen > 0) {
                // Allocate buffer (use std::wstring directly)
                wProcessName.resize(wideCharLen);

                // Perform the conversion
                MultiByteToWideChar(
                    CP_ACP,       // Code Page (must match above)
                    0,            // Flags
                    ProcessName.c_str(), // Source char string
                    procNameLen,  // Length of source string
                    &wProcessName[0], // Pointer to the buffer of std::wstring
                    wideCharLen   // Size of the buffer
                );

                // Now wProcessName holds the wide char version
                // Assuming GetProcId takes const wchar_t*
                processId = GetProcId(wProcessName.c_str());

            }
            else {
                // MultiByteToWideChar failed to calculate size
                std::cerr << "Error calculating wide string size for process name." << std::endl;
                processId = 0; // Ensure processId is zeroed
            }
        }
        else {
            // ProcessName was empty after trimming
            std::cerr << "Process name is empty." << std::endl;
            processId = 0; // Ensure processId is zeroed
        }

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);
        //MyArrayListOfAddresses.clear();
    }
    else if (userInput == "hook")
    {
        std::cout << "Original GetTickCount: " << GetTickCount() << std::endl;

        //x64Hook();  // Apply hook
        //x64Hook(GetCurrentProcess());
        HookRemoteGetTickCount(GetCurrentProcess());

        std::cout << "Hooked GetTickCount: " << GetTickCount() << std::endl;
    }

    else if (userInput == "scanstring") 
    {
        std::cout << "string: ";
        std::getline(std::cin >> std::ws, ValueToSearchFor);
        //cin.getline(input, sizeof(input));
         //std::cin >> ValueToSearchFor;
        try {
            std::vector<char> bytes(ValueToSearchFor.begin(), ValueToSearchFor.end());
            bytes.push_back('\0');
            char* c = &bytes[0];
            int size = bytes.size();
            ReadAllProcModules(processId, hProcess, (byte*)c, bytes.size() - 1);
        }
        catch (const std::invalid_argument& ex) {
            std::cerr << "Invalid input: " << ex.what() << std::endl;
        }
        catch (const std::out_of_range& ex) {
            std::cerr << "Out of range error: " << ex.what() << std::endl;
        }
    }
    /*
    else if (userInput == "scan8") {
        std::string param;
        std::cout << "int8: ";
        std::cin >> param;

        if (GMemoryMap.size() == 0)
        {
            try {
                int decimalValue = std::stoi(param);
                ReadAllProcModules(processId, hProcess, new byte[]{ (unsigned char)decimalValue }, 1);
            }
            catch (const std::invalid_argument& ex) {
                std::cerr << "Invalid input: " << ex.what() << std::endl;
            }
            catch (const std::out_of_range& ex) {
                std::cerr << "Out of range error: " << ex.what() << std::endl;
            }
        }
        else
        {
            try {
                int decimalValue = std::stoi(param);
                CheckAllRegisters(processId, hProcess, GMemoryMap, new byte[]{ (unsigned char)decimalValue });
            }
            catch (const std::invalid_argument& ex) {
                std::cerr << "Invalid input: " << ex.what() << std::endl;
            }
            catch (const std::out_of_range& ex) {
                std::cerr << "Out of range error: " << ex.what() << std::endl;
            }
        }
    }
    */
    else if (userInput == "scan8") {
        std::string param;
        std::cout << "int8 (-128 to 127): "; // Clarify range
        std::getline(std::cin, param); // Use getline for full line

        // Trim whitespace
        param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

        if (param.empty()) {
            std::cerr << "Input cannot be empty." << std::endl;
            // continue; // Or return, depending on context
        }
        else {
            if (GMemoryMap.empty()) { // Use .empty()
                std::cout << "Performing initial scan..." << std::endl;
                try {
                    long long parsedValue = std::stoll(param); // Parse wider first
                    int8_t decimalValue = static_cast<int8_t>(parsedValue);

                    // Create pattern on stack (safer than 'new' without 'delete')
                    byte pattern[1];
                    pattern[0] = static_cast<byte>(decimalValue); // Cast to byte (unsigned char)

                    ScanAllProcessMemory(processId, hProcess, pattern, 1);
                    ReadAllProcModules(processId, hProcess, pattern, 1); // Pass pattern and length 1
                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error: " << ex.what() << std::endl;
                }
            }
            else { // Refinement Scan
                std::cout << "Performing refinement scan..." << std::endl;
                try {
                    long long parsedValue = std::stoll(param);
                    int8_t decimalValue = static_cast<int8_t>(parsedValue);

                    byte pattern[1];
                    pattern[0] = static_cast<byte>(decimalValue);

                    // Call CheckAllRegisters correctly with pattern AND length
                    CheckAllRegisters(processId, hProcess, GMemoryMap, pattern);
                    std::cout << "Refinement scan function call placeholder for int8." << std::endl;

                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error: " << ex.what() << std::endl;
                }
            }
        }
        }
    else if (userInput == "scan16") {
            std::string param;
            std::cout << "int16 (-32768 to 32767): "; // Clarify range
            std::getline(std::cin, param); // Use getline

            // Trim whitespace
            param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

            if (param.empty()) {
                std::cerr << "Input cannot be empty." << std::endl;
                // continue; // Or return
            }
            else {
                if (GMemoryMap.empty()) {
                    std::cout << "Performing initial scan..." << std::endl;
                    try {
                        long long parsedValue = std::stoll(param); // Parse wider first
                        int16_t decimalValue = static_cast<int16_t>(parsedValue);

                        // Create 2-byte pattern (assuming little-endian)
                        byte pattern[2];
                        pattern[0] = static_cast<byte>(decimalValue & 0xFF);         // Low byte
                        pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF); // High byte

                        ScanAllProcessMemory(processId, hProcess, pattern, 2);
                        //ReadAllProcModules(processId, hProcess, pattern, 2); // Pass pattern and length 2
                    }
                    catch (const std::invalid_argument& ex) {
                        std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                    }
                    catch (const std::out_of_range& ex) {
                        std::cerr << "Out of range error: " << ex.what() << std::endl;
                    }
                }
                else { // Refinement Scan
                    std::cout << "Performing refinement scan..." << std::endl;
                    try {
                        long long parsedValue = std::stoll(param);
                        int16_t decimalValue = static_cast<int16_t>(parsedValue);

                        byte pattern[2];
                        pattern[0] = static_cast<byte>(decimalValue & 0xFF);
                        pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF);

                        // Call CheckAllRegisters correctly with pattern AND length
                        CheckAllRegisters(processId, hProcess, GMemoryMap, pattern);
                        std::cout << "Refinement scan function call placeholder for int16." << std::endl;

                    }
                    catch (const std::invalid_argument& ex) {
                        std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                    }
                    catch (const std::out_of_range& ex) {
                        std::cerr << "Out of range error: " << ex.what() << std::endl;
                    }
                }
            }
            }
    else if (userInput == "scan32") 
    {
        std::string param;
        std::cout << "int32 (-2147483648 to 2147483647): "; // Clarify range
        std::getline(std::cin, param); // Use getline

        // Trim whitespace
        param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

        if (param.empty()) {
            std::cerr << "Input cannot be empty." << std::endl;
            // continue; // Or return
        }
        else {
            if (GMemoryMap.empty()) {
                std::cout << "Performing initial scan..." << std::endl;
                try {
                    long long parsedValue = std::stoll(param); // Parse wider first
                    int32_t decimalValue = static_cast<int32_t>(parsedValue);

                    // Create 4-byte pattern (assuming little-endian)
                    byte pattern[4];
                    pattern[0] = static_cast<byte>(decimalValue & 0xFF);          // Byte 0 (Least Significant)
                    pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF);   // Byte 1
                    pattern[2] = static_cast<byte>((decimalValue >> 16) & 0xFF);  // Byte 2
                    pattern[3] = static_cast<byte>((decimalValue >> 24) & 0xFF);  // Byte 3 (Most Significant)

                    ScanAllProcessMemory(processId, hProcess, pattern, 4);
                    //ReadAllProcModules(processId, hProcess, pattern, 4); // Pass pattern and length 4
                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error: " << ex.what() << std::endl;
                }
            }
            else { // Refinement Scan
                std::cout << "Performing refinement scan..." << std::endl;
                try {
                    long long parsedValue = std::stoll(param);
                    int32_t decimalValue = static_cast<int32_t>(parsedValue);

                    byte pattern[4];
                    pattern[0] = static_cast<byte>(decimalValue & 0xFF);
                    pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF);
                    pattern[2] = static_cast<byte>((decimalValue >> 16) & 0xFF);
                    pattern[3] = static_cast<byte>((decimalValue >> 24) & 0xFF);

                    // Call CheckAllRegisters correctly with pattern AND length
                    CheckAllRegisters(processId, hProcess, GMemoryMap, pattern);
                    std::cout << "Refinement scan function call placeholder for int32." << std::endl;

                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error: " << ex.what() << std::endl;
                }
            }
        }
    }
    else if (userInput == "scan64") 
    {
        std::string param;
        // Get min/max for prompt clarity --- ADD PARENTHESES ---
        long long min_val = 0;
        std::int64_t max_val = 0xFFFFFFFFFFFFFFFF;
        std::cout << "int64 (" << min_val << " to " << max_val << "): ";
        std::getline(std::cin, param); // Use getline

        // Trim whitespace
        param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

        if (param.empty()) {
            std::cerr << "Input cannot be empty." << std::endl;
            // Depending on your loop structure, you might 'continue' here
        }
        else {
            // Assuming GMemoryMap holds results from previous scans if not empty
            if (GMemoryMap.empty()) { // Use .empty()
                std::cout << "Performing initial scan..." << std::endl;
                try {
                    // std::stoll parses into long long (typically int64_t)
                    // It throws std::out_of_range if the value is outside the representable range of long long.
                    long long parsedValue = std::stoll(param);
                    // Explicitly use int64_t type for clarity
                    int64_t decimalValue = static_cast<int64_t>(parsedValue);

                    // Create 8-byte pattern (assuming little-endian)
                    byte pattern[8];
                    pattern[0] = static_cast<byte>(decimalValue & 0xFF);          // Byte 0 (Least Significant)
                    pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF);   // Byte 1
                    pattern[2] = static_cast<byte>((decimalValue >> 16) & 0xFF);  // Byte 2
                    pattern[3] = static_cast<byte>((decimalValue >> 24) & 0xFF);  // Byte 3
                    pattern[4] = static_cast<byte>((decimalValue >> 32) & 0xFF);  // Byte 4
                    pattern[5] = static_cast<byte>((decimalValue >> 40) & 0xFF);  // Byte 5
                    pattern[6] = static_cast<byte>((decimalValue >> 48) & 0xFF);  // Byte 6
                    pattern[7] = static_cast<byte>((decimalValue >> 56) & 0xFF);  // Byte 7 (Most Significant)

                    ScanAllProcessMemory(processId, hProcess, pattern, 8);
                    //ReadAllProcModules(processId, hProcess, pattern, 8); // Pass pattern and length 8

                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    // Catches values outside the range of long long (int64_t) during parsing
                    std::cerr << "Out of range error: Input value out of 64-bit integer range. " << ex.what() << std::endl;
                }
            }
            else { // Refinement Scan
                std::cout << "Performing refinement scan..." << std::endl;
                try {
                    long long parsedValue = std::stoll(param);
                    int64_t decimalValue = static_cast<int64_t>(parsedValue);

                    byte pattern[8];
                    pattern[0] = static_cast<byte>(decimalValue & 0xFF);
                    pattern[1] = static_cast<byte>((decimalValue >> 8) & 0xFF);
                    pattern[2] = static_cast<byte>((decimalValue >> 16) & 0xFF);
                    pattern[3] = static_cast<byte>((decimalValue >> 24) & 0xFF);
                    pattern[4] = static_cast<byte>((decimalValue >> 32) & 0xFF);
                    pattern[5] = static_cast<byte>((decimalValue >> 40) & 0xFF);
                    pattern[6] = static_cast<byte>((decimalValue >> 48) & 0xFF);
                    pattern[7] = static_cast<byte>((decimalValue >> 56) & 0xFF);

                    // Call CheckAllRegisters correctly with pattern AND length
                    // Make sure CheckAllRegisters is prepared to handle length 8
                    CheckAllRegisters(processId, hProcess, GMemoryMap, pattern);
                    std::cout << "Refinement scan function call placeholder for int64." << std::endl;

                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error: Input value out of 64-bit integer range. " << ex.what() << std::endl;
                }
            }
        }
    }
    else if (userInput.rfind("shscan", 0) == 0 && userInput.length() > 6) {
        std::string sizeSuffix = userInput.substr(6);
        int bitSize = 0;
        int scanSize = 0;
        std::string typeName;
        long long min_val = 0;
        long long max_val = 0;
        bool commandValid = false; // Flag to track if setup is valid

        try {
            bitSize = std::stoi(sizeSuffix);
            // Validate bitSize and set parameters
            switch (bitSize) {
            case 8:
                scanSize = 1; typeName = "int8";
                min_val = std::numeric_limits<int8_t>::min();
                max_val = std::numeric_limits<int8_t>::max();
                commandValid = true;
                break;
            case 16:
                scanSize = 2; typeName = "int16";
                min_val = std::numeric_limits<int16_t>::min();
                max_val = std::numeric_limits<int16_t>::max();
                commandValid = true;
                break;
            case 32:
                scanSize = 4; typeName = "int32";
                min_val = std::numeric_limits<int32_t>::min();
                max_val = std::numeric_limits<int32_t>::max();
                commandValid = true;
                break;
            case 64:
                scanSize = 8; typeName = "int64";
                min_val = std::numeric_limits<int64_t>::min();
                max_val = std::numeric_limits<int64_t>::max();
                commandValid = true;
                break;
            default:
                std::cerr << "Invalid bit size specified (" << bitSize << "). Use 8, 16, 32, or 64." << std::endl;
                // commandValid remains false
            }
        }
        catch (const std::invalid_argument&) {
            std::cerr << "Invalid command format. Expected shscan8, shscan16, shscan32, or shscan64 (Could not parse size suffix '" << sizeSuffix << "')." << std::endl;
            // commandValid remains false
        }
        catch (const std::out_of_range&) {
            std::cerr << "Invalid command format. Size suffix '" << sizeSuffix << "' out of range for integer parsing." << std::endl;
            // commandValid remains false
        }
        catch (...) { // Catch any other potential exceptions from stoi
            std::cerr << "Unknown error parsing command size suffix '" << sizeSuffix << "'." << std::endl;
            // commandValid remains false
        }


        // --- Proceed only if the command and size were valid ---
        if (commandValid) {
            std::string param;
            std::cout << typeName << " (" << min_val << " to " << max_val << "): ";
            std::getline(std::cin >> std::ws, param);

            // Trim whitespace
            param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

            if (param.empty()) {
                std::cerr << "Input value cannot be empty." << std::endl;
            }
            else {
                bool isInitialScan = GMemoryMap.empty();
                if (isInitialScan) {
                    std::cout << "Performing initial Heap/Stack scan for " << typeName << "..." << std::endl;
                }
                else {
                    std::cout << "Performing refinement scan for " << typeName << "..." << std::endl;
                }

                try {
                    long long parsedValue = std::stoll(param);
                    if (parsedValue < min_val || parsedValue > max_val) {
                        throw std::out_of_range("Value out of range for " + typeName + " type.");
                    }

                    byte pattern[8];
                    uint64_t value_to_scan = static_cast<uint64_t>(parsedValue);
                    memcpy(pattern, &value_to_scan, scanSize);

                    if (isInitialScan) {
                        ScanHeapAndStackMemory(processId, hProcess, pattern, scanSize);
                    }
                    else {
                        // *** Ensure CheckAllRegisters takes scanSize ***
                        CheckAllRegisters(processId, hProcess, GMemoryMap, pattern);
                    }
                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid input value: Not an integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Out of range error for input value: " << ex.what() << std::endl;
                }
            } // end if !param.empty()
        } // end if commandValid

    } // End combined shscan block
    else if (userInput == "same") {
        CheckChanged(processId, hProcess, GMemoryMap, true);
    }
    else if (userInput == "changed") {
        CheckChanged(processId, hProcess, GMemoryMap, false);
    }
    else if (userInput == "watch") {
        stopFlag = false;
        t = std::thread(threadFunction);
    }
    else if (userInput == "stopwatch")
    {
        stopFlag = true;
    }
    else if (userInput == "dump") 
    {
        PrintModules(processId, hProcess);
        DumpMemory();
    }
    else if (userInput == "recentlyremoved") {
        /*
        for (const auto& entry : MyArrayListOfAddressesRecentlyRemoved) {
            //std::cout << std::hex << entry.first << std::endl;
            std::cout << "BEFORE: ";
            
            
            for (const auto& byteValue : entry.second.first) {
                //std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteValue) << " ";
            }
            std::cout << std::endl;
            std::cout << "AFTER: ";
            for (const auto& byteValue : entry.second.second) {
                //std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteValue) << " ";
            }
            
            std::cout << std::endl << std::endl;
        }
        */
    }
    else if (userInput == "clear") {
        std::cout << "Memory list cleared" << std::endl;
        GMemoryMap.clear();
    }
    else if (userInput == "suspend") {
        SuspendProcess(processId);
    }
    else if (userInput == "resume") {
        ResumeProcess(processId);
    }
    else if (userInput == "writeunistring") {
        // DotNetMemoryScan find_aob;
        std::string param;
        std::cout << "Overwrite unistring: ";
        //std::getline(std::cin, param);
        //int decimalValue = std::stoi(param);
        //std::cin >> param;

        /*
        
        for (const auto& MyAddress : MyArrayListOfAddresses) {
            if (MyAddress.first > 0) {
                //std::cout << "[scan_all 1] result 0x" << std::hex << std::setw(16) << std::setfill('0') << MyAddress.first << std::endl;
                // std::cout << "Bytes written: " << find_aob.write_mem(MyProcess, MyAddress.first, ValueToWrite) << std::endl;
            }
        }
        */
    }
    else if (userInput == "writestring") {
        // DotNetMemoryScan find_aob;
        std::string ValueToWrite;
        std::cout << "Overwrite Asciistring: ";
        std::getline(std::cin >> std::ws, ValueToSearchFor);
        try {
            int Lengthofbuffer = ValueToSearchFor.length();
            void * buffer = malloc(ValueToSearchFor.length());
            for (const auto& pair : GMemoryMap) {
                //MemoryModule key = pair.first;
                VOID* key = pair.first;
                std::vector<MemoryEntry> obj = pair.second;

                for (const auto& myobj : obj)
                {

                    VOID* ObjAddr = myobj.Address;
                    
                    if (!ReadProcessMemory(hProcess, ObjAddr, buffer, Lengthofbuffer, nullptr))
                    {

                    }
                    
                    SIZE_T bytesWritten = 0;
                    if (!WriteProcessMemory(hProcess, ObjAddr, ValueToWrite.c_str(), ValueToWrite.size(), &bytesWritten)) {
                        std::cerr << "Failed to write memory at address: " << ObjAddr << std::endl;
                    }
                    else {
                        std::cout << "Successfully wrote " << bytesWritten << " bytes to address: " << ObjAddr << std::endl;
                    }
                    std::cout << "Written ModuleAddress: 0x" << std::hex << key << " Address: " << myobj.Address << " - InCache:" << std::dec << myobj.value << " beforeInMem: " << (char *)buffer << " nowInMem: " << ValueToSearchFor << "\n";
                    for (size_t i = 0; i < Lengthofbuffer; ++i) {
                        //std::cout << static_cast<int>(buffer[i]) << " ";
                    }
                }
            }
            free(buffer);
        }
        catch (const std::invalid_argument& ex) {
            std::cerr << "Invalid input: " << ex.what() << std::endl;
        }
        catch (const std::out_of_range& ex) {
            std::cerr << "Out of range error: " << ex.what() << std::endl;
        }
        catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
        }
    }
    else if (userInput == "wint") 
    {
        std::string param;
        std::cout << "value to write: ";
        std::cin >> param;
        //std::getline(std::cin, param);
        int decimalValue = std::stoi(param);

        char buffer[1] = { 0 };
        char bufferToWrite[1] = { decimalValue };
        for (const auto& pair : GMemoryMap) {
            //MemoryModule key = pair.first;
            VOID* key = pair.first;
            std::vector<MemoryEntry> obj = pair.second;

            for (const auto& myobj : obj)
            {

                VOID* ObjAddr = myobj.Address;
                if (!ReadProcessMemory(hProcess, ObjAddr, &buffer, 1, nullptr))
                {
                }
                if (!WriteProcessMemory(hProcess, ObjAddr, &bufferToWrite, 1, nullptr))
                {
                    //Unable to get mem
                }
                std::cout << "Written ModuleAddress: 0x" << std::hex << key << " Address: " << myobj.Address << " - InCache:" << std::dec << myobj.value << " beforeInMem: " << int(buffer[0]) << " nowInMem: " << decimalValue << "\n";
            }
        }    
    }
    else if (userInput == "wint8" || userInput == "wint16" || userInput == "wint32" || userInput == "wint64")
    {
        // This 'valueToWriteString' must be populated by your main command parsing logic
        // based on the user's full input line (e.g., "wint32 200000").
        // If it's not passed in or set before this block, you'd need to parse it
        // from a fuller input string here. For now, assume it's available.
        // For example, if your main loop does:
        //   string cmd, val_str;
        //   iss >> cmd >> val_str;
        // Then here: userInput = cmd; string localValueStr = val_str;

        // Assuming 'valueToWriteString' is already correctly populated with the value part of the command.
        std::string valueToWriteString;
        std::cin >> valueToWriteString;
        if (valueToWriteString.empty()) {
            std::cerr << "Error: No value specified for " << userInput << " command. Usage: " << userInput << " <value>" << std::endl;
            // return; // Or continue in your main loop
        }
        else {
            // --- 1. Determine Type and Parse/Validate Value from Command Line ---
            std::string param = valueToWriteString; // Use the value from the command input
            long long min_val = 0, max_val = 0;
            int writeSize = 0;
            std::string typeName;
            long long parsedValueLL = 0;
            byte pattern[8]; // Max size for int64

            if (userInput == "wint8") {
                writeSize = 1; typeName = "int8";
                min_val = std::numeric_limits<int8_t>::min();
                max_val = std::numeric_limits<int8_t>::max();
            }
            else if (userInput == "wint16") {
                writeSize = 2; typeName = "int16";
                min_val = std::numeric_limits<int16_t>::min();
                max_val = std::numeric_limits<int16_t>::max();
            }
            else if (userInput == "wint32") {
                writeSize = 4; typeName = "int32";
                min_val = std::numeric_limits<int32_t>::min();
                max_val = std::numeric_limits<int32_t>::max();
            }
            else if (userInput == "wint64") {
                writeSize = 8; typeName = "int64";
                min_val = std::numeric_limits<int64_t>::min();
                max_val = std::numeric_limits<int64_t>::max();
            }

            // Trim whitespace from param
            param.erase(param.begin(), std::find_if(param.begin(), param.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            param.erase(std::find_if(param.rbegin(), param.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), param.end());

            if (param.empty() || writeSize == 0) { // Should have been caught by valueToWriteString.empty() but good to double check
                std::cerr << "Error: Value is empty or type is invalid for write operation." << std::endl;
                // return or continue;
            }
            else {
                try {
                    parsedValueLL = std::stoll(param);
                    if (parsedValueLL < min_val || parsedValueLL > max_val) {
                        throw std::out_of_range("Value " + param + " is out of range for " + typeName + " type (" + std::to_string(min_val) + " to " + std::to_string(max_val) + ").");
                    }
                    uint64_t temp_val_for_memcpy = static_cast<uint64_t>(parsedValueLL);
                    memcpy(pattern, &temp_val_for_memcpy, writeSize);

                    std::cout << "Preparing to write " << typeName << " value: " << parsedValueLL
                        << " (0x" << std::hex << static_cast<uint64_t>(parsedValueLL) << std::dec << ")"
                        << ". Range: " << min_val << " to " << max_val << "." << std::endl;

                    // --- 2. Consolidate addresses and check count ---
                    std::vector<MemoryEntry> flatEntryList;
                    for (const auto& pair_map_entry : GMemoryMap) {
                        flatEntryList.insert(flatEntryList.end(), pair_map_entry.second.begin(), pair_map_entry.second.end());
                    }
                    size_t totalFound = flatEntryList.size();

                    if (totalFound == 0) {
                        std::cerr << "No addresses found in memory map. Perform a scan first." << std::endl;
                    }
                    else {
                        std::cout << "Total matching addresses found in last scan: " << totalFound << std::endl;
                        std::vector<VOID*> targetAddresses;
                        bool targetsSelected = false;

                        // --- 3. Get Target Address(es) ---
                        if (totalFound <= 10) { // Or some other threshold for listing
                            std::cout << "Select addresses to write to by index:" << std::endl;
                            for (size_t i = 0; i < totalFound; ++i) {
                                std::cout << "[" << (i + 1) << "] 0x" << std::hex << reinterpret_cast<uintptr_t>(flatEntryList[i].Address) << std::dec << std::endl;
                            }
                            std::cout << "Enter index/indices (e.g., 1,3,5 or 2-4): "; // Prompt for indices ONLY
                            std::string indexInput;
                            std::getline(std::cin >> std::ws, indexInput);

                            std::set<size_t> selectedIndices;
                            if (ParseIndices(indexInput, totalFound, selectedIndices)) { // 'totalFound' likely used by ParseIndices to validate 1-based input "1" against max "1"
                                // The loop variable should reflect that it's holding 0-based indices from selectedIndices
                                for (size_t zero_based_index_from_set : selectedIndices) {
                                    // Check if the 0-based index is within the valid range for flatEntryList
                                    // Valid 0-based indices are from 0 to flatEntryList.size() - 1
                                    if (zero_based_index_from_set < flatEntryList.size()) {
                                        targetAddresses.push_back(flatEntryList[zero_based_index_from_set].Address); // Use the 0-based index directly
                                    }
                                    else {
                                        // This case should ideally not happen if ParseIndices validates correctly against totalFound
                                        std::cerr << "Warning: Index " << zero_based_index_from_set
                                            << " obtained from ParseIndices is out of range for available addresses (count: "
                                            << flatEntryList.size() << ")." << std::endl;
                                    }
                                }
                                targetsSelected = !targetAddresses.empty();
                                if (!targetsSelected && !indexInput.empty()) {
                                    // This message now implies that ParseIndices succeeded but yielded indices
                                    // that were not usable (e.g., empty set, or all out of bounds after the loop's own check).
                                    std::cerr << "No valid targets were ultimately selected from input: " << indexInput << std::endl;
                                }
                            }
                            else {
                                // This 'else' corresponds to ParseIndices returning false (parsing failed)
                                if (!indexInput.empty()) { // Only print error if there was an input to parse
                                    std::cerr << "Failed to parse indices or input out of range: " << indexInput << std::endl;
                                }
                                // targetsSelected remains false or is already false
                            }
                        }
                        else { // More than 10 entries (or threshold)
                            std::cout << "More than 10 addresses found. Specify exact address to write to, or 'all' to write to all " << totalFound << " addresses." << std::endl;

                            // Corrected line for prompting with an example address:
                            std::cout << "Enter target address (e.g., 0x"; // Output the prefix part

                            if (flatEntryList.empty() || flatEntryList[0].Address == nullptr) { // Check if list is empty or first address is null
                                std::cout << "ADDRESS"; // Output placeholder if no valid example address
                            }
                            else {
                                std::cout << std::hex << reinterpret_cast<uintptr_t>(flatEntryList[0].Address); // Output std::hex, then the address
                            }

                            std::cout << std::dec << ") or 'all': "; // Output std::dec to reset, then the suffix part

                            std::string addrInput;

                            std::getline(std::cin >> std::ws, addrInput);
                            // Trim addrInput
                            addrInput.erase(addrInput.begin(), std::find_if(addrInput.begin(), addrInput.end(), [](unsigned char ch) { return !std::isspace(ch); }));
                            addrInput.erase(std::find_if(addrInput.rbegin(), addrInput.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), addrInput.end());


                            if (addrInput == "all") {
                                for (const auto& entry : flatEntryList) {
                                    targetAddresses.push_back(entry.Address);
                                }
                                targetsSelected = !targetAddresses.empty();
                            }
                            else if (!addrInput.empty()) {
                                try {
                                    uintptr_t parsedAddr = std::stoull(addrInput, nullptr, 0); // base 0 for 0x
                                    targetAddresses.push_back(reinterpret_cast<VOID*>(parsedAddr));
                                    targetsSelected = true;
                                }
                                catch (const std::exception& ex) {
                                    std::cerr << "Invalid address format entered: " << addrInput << " (" << ex.what() << ")" << std::endl;
                                }
                            }
                            else {
                                std::cerr << "No address input provided." << std::endl;
                            }
                        }

                        // --- 4. Write to Memory ---
                        if (targetsSelected) {
                            SIZE_T bytesWritten = 0;
                            int successCount = 0;
                            std::vector<uintptr_t> successfulAddresses;


                            if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
                                std::cerr << "Error: Cannot write memory. Invalid process handle." << std::endl;
                            }
                            else {
                                for (VOID* targetAddr : targetAddresses) {
                                    if (targetAddr == nullptr) {
                                        std::cerr << "Warning: Skipping null target address." << std::endl;
                                        continue;
                                    }
                                    if (WriteProcessMemory(hProcess, targetAddr, pattern, static_cast<SIZE_T>(writeSize), &bytesWritten)) {
                                        if (bytesWritten == static_cast<SIZE_T>(writeSize)) {
                                            // Don't print per success yet, accumulate for combined message if desired
                                            successfulAddresses.push_back(reinterpret_cast<uintptr_t>(targetAddr));
                                            successCount++;
                                        }
                                        else {
                                            std::cerr << "Error: Wrote partial data (" << bytesWritten << "/" << writeSize << " bytes) to address 0x" << std::hex << reinterpret_cast<uintptr_t>(targetAddr) << std::dec << std::endl;
                                        }
                                    }
                                    else {
                                        DWORD lastError = GetLastError();
                                        std::cerr << "Error: Failed to write to address 0x" << std::hex << reinterpret_cast<uintptr_t>(targetAddr) << ". Error code: " << lastError << std::dec << std::endl;
                                    }
                                }
                            }

                            if (successCount > 0) {
                                std::cout << "Successfully wrote " << parsedValueLL
                                    << " (0x" << std::hex << static_cast<uint64_t>(parsedValueLL) << std::dec << ")"
                                    << " (" << writeSize * 8 << "-bit) to " << successCount << " address(es): ";
                                for (size_t k = 0; k < successfulAddresses.size(); ++k) {
                                    std::cout << "0x" << std::hex << successfulAddresses[k] << std::dec << (k == successfulAddresses.size() - 1 ? "" : ", ");
                                }
                                std::cout << std::endl;
                            }
                            std::cout << "Write operation complete. Attempted to write to " << targetAddresses.size() << " selected addresses. Successfully wrote to " << successCount << "." << std::endl;

                        }
                        else {
                            std::cout << "No target addresses were selected for writing." << std::endl;
                        }
                    } // end else (totalFound > 0)
                }
                catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid value input: '" << param << "' is not a valid integer. " << ex.what() << std::endl;
                }
                catch (const std::out_of_range& ex) {
                    std::cerr << "Value input error: " << ex.what() << std::endl;
                }
            } // end else (param not empty and writeSize > 0)
        } // end else (valueToWriteString not empty)
        } // End wintX block
    else if (userInput == "scanandoverwrite") {
        std::string OverwriteString;
        std::cout << "Overwrite string: ";
        std::getline(std::cin, OverwriteString);
        // OverwriteAllBytePattens(MyProcess.ProcessName, ConvertStringToUniByteString(OverwriteString), ConvertStringToUniByteString(ValueToSearchFor));
    }
    else if (userInput == "help") {
        DisplayHelp();
    }
    else if (userInput == "version") {
        DisplayVersion();
    }
    else if (userInput == "exit" || userInput == "quit") {
        exit(0);
    }
    else {
        std::cout << "Unrecognized command. Type 'help' for available commands." << std::endl;
    }
}

int main()
{
    std::cout << "Starting!\nEnter 'help' for commands\r\n";
    HANDLE currentToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentToken);
    if (!SetPrivilege(currentToken, SE_DEBUG_NAME, TRUE))
    {
        std::cout << "Unable to adjust privileges" << std::endl;
    }    

    //HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    processId = GetProcId(ProcName);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

    std::string input;
    while (true)
    {
        std::cout << ">";
        std::cin >> input;
        menu(input);
    }
    
    /*
    std::cout << "Press Any Key to continue:\n";
    getchar();
    */

    // Close the process handle
    CloseHandle(hProcess);

    return 0;
}