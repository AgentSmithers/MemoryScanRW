# AgentSmithers MemoryScanRW: C++ Process Memory Scanner & Editor

AgentSmithers MemoryScanRW is a command-line utility for Windows, written in C++, designed for advanced users to inspect, scan, and modify the memory of running processes. It provides a range of features from process targeting and memory scanning to value writing and experimental process manipulation.

## Features

* **Process Interaction:**
    * Target processes by executable name (e.g., `notepad.exe`).
    * Automatically obtains Process ID and opens a process handle with comprehensive access rights.
    * Attempts to elevate privileges (`SE_DEBUG_NAME`) for enhanced memory access capabilities.
    * Suspend and resume all threads within the target process.
* **Memory Scanning:**
    * Scan for various data types: 8-bit, 16-bit, 32-bit, and 64-bit integers, as well as ASCII strings.
    * **Initial Scans:** Populate a list of memory addresses where the specified value/pattern is found.
        * `scan<bits> <value>` (e.g., `scan32 100`): Scans all committed, readable memory regions and loaded modules.
        * `shscan<bits> <value>` (e.g., `shscan32 100`): Scans only Heap & Stack (`MEM_PRIVATE`) memory regions.
        * `scanstring <text>`: Scans memory within loaded modules for the given ASCII string.
    * **Refinement Scans:** If a list of addresses is already cached from a previous scan, the `scan<bits>` and `shscan<bits>` commands will filter this existing list, keeping only addresses where the memory now matches the new value.
* **Results Management & Filtering:**
    * Found memory locations are stored and categorized (typically by module base address or memory region base).
    * `clear`: Clears the cached list of found memory addresses.
    * `dump`: Displays information about loaded modules in the target process and lists all currently cached memory addresses with their (cached) original and current in-memory values.
    * `same`: Filters the cached list, keeping only addresses where the (1-byte) value has *not* changed.
    * `changed`: Filters the cached list, keeping only addresses where the (1-byte) value *has* changed. The cached value is updated to the new in-memory value.
* **Memory Modification:**
    * `wint<bits> <value_to_write>` (e.g., `wint32 200000`): Writes the specified integer value to selected memory addresses.
        * **Address Selection:**
            * If 10 or fewer addresses are in the cache: Addresses are listed by index. You'll be prompted to enter indices (e.g., `1`, `3-5`, `1,2,6`).
            * If more than 10 addresses are cached: You'll be prompted to enter a specific hexadecimal address to write to, or type `all` to write to all cached addresses.
    * `writestring <text_to_write>`: (Partially Implemented) Attempts to write the given ASCII string to all currently cached memory addresses.
* **Memory Monitoring:**
    * `watch`: Starts a background thread that continuously monitors all cached 1-byte values. If a change is detected, it's reported, and the cached value is updated.
    * `stopwatch`: Stops the memory monitoring thread.
* **Advanced Capabilities:**
    * DMA/Pointer Chain Resolution: Includes a function (`FindDMAAddy`) for resolving multi-level pointers (demonstrated in `ReadSpecificAddress` which is not a direct command).
    * Module Enumeration: Lists loaded modules and their base addresses/sizes.
    * Hooking (Experimental): Contains infrastructure for function hooking (`hook.h`, `HookRemoteGetTickCount` example via `hook` command).
* **User Interface:**
    * Interactive command-line interface (CLI).
    * `help` command lists all available commands and their basic usage.
    * `version` command displays the program's version.

## Prerequisites

* **Operating System:** Windows (XP or later, due to extensive use of Windows API).
* **Privileges:** It is highly recommended to run this program with **Administrator privileges**. The tool attempts to set `SE_DEBUG_NAME` privilege, which is necessary for full access to other processes' memory.
* **Architecture:** While the code uses types like `uintptr_t`, it has been observed targeting 64-bit processes (e.g., `Exodus-Win64-Shipping.exe`). Ensure compatibility if targeting 32-bit processes.

## How to Build

1.  **Compiler:** You'll need a C++ compiler that supports C++11 or later (e.g., Visual Studio with the "Desktop development with C++" workload).
2.  **Windows SDK:** Ensure the Windows SDK is installed and accessible by your compiler.
3.  **Dependencies:**
    * The code links with `advapi32.lib` (handled by `#pragma comment`).
    * An external header `hook.h` is included. You will need to provide this file and its corresponding implementation (`hook.cpp`, if any) or remove/comment out the hooking-related features.
4.  **Compilation:**
    * Create a new C++ project in your IDE (like Visual Studio).
    * Add `Memory.cpp` (and `hook.cpp`/`hook.h` if used) to the project.
    * Build the project (typically produces a `.exe` file).

## How to Run

1.  Open a Command Prompt (cmd.exe) or PowerShell **as Administrator**.
2.  Navigate to the directory where you compiled `Memory.exe`.
3.  Run the executable: `.\Memory.exe`
4.  The program will start, and you'll see a `>` prompt.
5.  Type `help` to see the list of available commands.

## Command Reference

### Process Targeting & Control
* `ProcessName <name.exe>`: Sets the target process (e.g., `ProcessName notepad.exe`). The tool will then try to attach to this process.
* `clear`: Clears the internal list of found memory addresses from previous scans.
* `suspend`: Suspends the target process.
* `resume`: Resumes the target process.

### Memory Scanning (Populates/Refines Address List)
*These commands will perform an initial scan if the address list is empty, or a refinement scan on existing results.*
* `scanstring <text>`: Scan for an ASCII string (currently scans within loaded modules).
* `scan8 <value>`: Scan for an 8-bit integer (e.g., `scan8 100`).
* `scan16 <value>`: Scan for a 16-bit integer (e.g., `scan16 1500`).
* `scan32 <value>`: Scan for a 32-bit integer (e.g., `scan32 123456`).
* `scan64 <value>`: Scan for a 64-bit integer.
* `shscan8 <value>`, `shscan16 <value>`, `shscan32 <value>`, `shscan64 <value>`: Similar to `scanX` but specifically scans Heap & Stack memory regions (`MEM_PRIVATE`).

### Result Filtering
* `same`: Filters the cached address list, keeping only addresses where the (1-byte) value has *not* changed since the last check.
* `changed`: Filters the cached address list, keeping only addresses where the (1-byte) value *has* changed. Updates the stored value to the new one.

### Memory Writing
* `wint8 <value>`: Prompts to select target(s) from the cached address list, then writes the 8-bit `<value>`.
* `wint16 <value>`: Prompts to select target(s), then writes the 16-bit `<value>`.
* `wint32 <value>`: Prompts to select target(s), then writes the 32-bit `<value>`.
* `wint64 <value>`: Prompts to select target(s), then writes the 64-bit `<value>`.
    * *Address Selection for `wintX`*: If 10 or fewer addresses are cached, select by 1-based index (e.g., `1`, `2-4`, `1,5`). If more, provide a specific hex address or `all`.
* `writestring <text>`: Attempts to write an ASCII string to all cached addresses. (Use with caution).
* `writeunistring`: (Not Yet Implemented)
* `scanandoverwrite`: (Not Yet Implemented)

### Monitoring & Information
* `watch`: Starts a background thread to monitor cached 1-byte values for changes. Reports and updates on change.
* `stopwatch`: Stops the `watch` thread.
* `dump`: Prints loaded modules of the target process and dumps the currently cached memory addresses with their values.
* `recentlyremoved`: (Not Yet Implemented)

### Hooking (Experimental)
* `hook`: Attempts an experimental hook on `GetTickCount` within the tool's own process.

### General
* `help`: Displays the command help list.
* `version`: Shows the program version.
* `exit` / `quit`: Exits the program.

## Disclaimer

This tool is provided for educational purposes, to facilitate learning about Windows process memory, API interactions, and system-level programming.

⚠️ **Use Responsibly:** Modifying the memory of arbitrary processes can lead to instability, crashes, or unintended behavior in those processes or the system.
* Only use this tool on processes for which you have explicit authorization.
* Be aware of the terms of service for any software you interact with, especially games, as using such tools may be a violation.
* The author(s) are not responsible for any damage or misuse caused by this software.
