.code

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetRandomSyscallAddress: PROC

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 013820F15h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 013820F15h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 047544DC7h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 047544DC7h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 045C94F4Bh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 045C94F4Bh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtProtectVirtualMemory ENDP

NtQueueApcThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 09D3FC600h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 09D3FC600h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueueApcThread ENDP

NtResumeThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0BA927AC9h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0BA927AC9h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtResumeThread ENDP

end