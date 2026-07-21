; Direct Syscall Stub — NtOpenProcess
; Issues the syscall instruction directly from this stub,
; bypassing ntdll entirely and avoiding any user-mode hooks.
;
; WARNING: The SSN (0x26) is build-specific. Resolve at runtime
; via Hell's/Halo's/Tartarus' Gate for portability.
;
; Detection: The call stack will lack the expected ntdll frame,
; which is a strong indicator to any sensor performing stack unwinding.

.code
NtOpenProcess proc
    mov r10, rcx
    mov eax, 26h        ; SSN for NtOpenProcess on this Windows build
    syscall
    ret
NtOpenProcess endp
end
