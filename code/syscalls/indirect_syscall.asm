; Indirect Syscall Stub — NtOpenProcess
; Sets up registers in this stub but transfers control to the
; syscall instruction inside the real ntdll module. The resulting
; call stack contains a legitimate ntdll!NtOpenProcess+0x12 frame,
; which is indistinguishable from a normal API invocation.
;
; The ntOpenProcessSyscall variable must be populated at runtime
; with the address of the syscall instruction inside ntdll.

EXTERN ntOpenProcessSyscall:QWORD

.code
NtOpenProcess proc
    mov r10, rcx
    mov eax, 26h
    jmp QWORD PTR [ntOpenProcessSyscall]   ; jmp to syscall inside ntdll
NtOpenProcess endp
end
