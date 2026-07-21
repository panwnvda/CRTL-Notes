/*
 * Postex Loader Entry Point — Crystal Palace
 *
 * The custom post-exploitation reflective loader shares ~99% of its
 * implementation with the Beacon loader. Key differences:
 *   - Entry receives loader_arguments (user-supplied args)
 *   - DLL entry is invoked twice:
 *       1. DLL_PROCESS_ATTACH
 *       2. 0x4 with loader base + user args
 *   - Applies to execute-assembly, mimikatz, powerpick, and
 *     operator-authored post-exploitation DLLs
 */

#include <windows.h>

void go(void *loader_arguments) {
    /* ... same setup as Beacon loader:
       unmask, allocate, load DLL, resolve imports, fix protections ... */

    /* first: DLL_PROCESS_ATTACH */
    entry_point((HINSTANCE)dll_dst, DLL_PROCESS_ATTACH, NULL);

    /* second: 0x4 with loader base + user args
       (so postex can free the loader if post-ex.cleanup) */
    entry_point((HINSTANCE)(char *)go, 0x4, loader_arguments);
}
