/*
 * Object Callback — ObRegisterCallbacks Pre-Operation Example
 *
 * Object callbacks are registered per object type and stored in a
 * doubly-linked CallbackList attached to the OBJECT_TYPE structure.
 * Pre-operation callbacks receive the requested ACCESS_MASK and may
 * remove access rights before the handle is returned to the caller.
 *
 * This example strips PROCESS_VM_READ from handle open requests,
 * which is the mechanism used by EDR products to prevent handles
 * to lsass.exe from being opened with read access.
 *
 * Disabling: Set the Active member of the CALLBACK_ENTRY_ITEM to
 * zero, or unlink the node from the doubly-linked list.
 */

#include <ntddk.h>

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION Info)
{
    ACCESS_MASK requested = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    if (requested & PROCESS_VM_READ) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
    }
    return OB_PREOP_SUCCESS;
}
