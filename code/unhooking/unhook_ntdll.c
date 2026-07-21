/*
 * UnhookNtdll — Overwrite the hooked .text section of in-memory ntdll
 * with a clean copy mapped from disk.
 *
 * Procedure:
 *   1. Map a fresh copy of ntdll.dll from disk with SEC_IMAGE.
 *   2. Locate the in-memory .text section of the loaded (hooked) ntdll.
 *   3. VirtualProtect the region to writable.
 *   4. memcpy the fresh .text over the hooked one.
 *   5. Restore original page protection.
 *   6. FlushInstructionCache.
 *
 * OPSEC: Modifying the .text section of ntdll can be detected by a
 * sensor that compares the in-memory image to the on-disk file.
 * Unhooking should be performed once, early in the process lifecycle.
 */

#include <windows.h>

void UnhookNtdll() {
    HANDLE hFile    = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
                                   GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMappingW(hFile, NULL,
                                          PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID pMap     = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    HMODULE hNtdll  = GetModuleHandleW(L"ntdll.dll");
    // Walk PE headers, find .text, VirtualProtect + memcpy + restore + flush.
    // ... (elided for brevity)
}
