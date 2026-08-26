; Copyright (c) 2026 渟雲. All rights reserved.
.data
table_initialized db 0
crc64_table dq 256 dup(0)

.code
CalculateRequestsChecksum proc
    push rbx
    push rdi
    mov r9, rcx
    test rcx, rcx
    jnz loc_continue
    xor eax, eax
    jmp loc_exit

loc_continue:
    cmp table_initialized, 0
    lea rdi, crc64_table
    jne loc_calculate_crc
    mov rcx, 0
    mov rdx, rdi
    mov r11d, 100h

loc_init_table_outer:
    mov rax, rcx
    mov r10d, 8

loc_init_table_inner:
    test al, 1
    jz loc_shift_only
    mov rbx, 85E1C3D753D46D27h
    xor rax, rbx

loc_shift_only:
    shr rax, 1
    sub r10, 1
    jnz loc_init_table_inner
    mov [rdx], rax
    inc rcx
    add rdx, 8
    sub r11, 1
    jnz loc_init_table_outer
    mov table_initialized, 1

loc_calculate_crc:
    mov rax, 0FFFFFFFFFFFFFFFFh
    xor r8, r8

loc_crc_loop:
    movzx ecx, byte ptr [r9+r8]
    inc r8
    xor rax, rcx
    movzx edx, al
    shr rax, 8
    xor rax, [rdi+rdx*8]
    cmp r8, 0B8h
    jb loc_crc_loop
    not rax

loc_exit:
    pop rdi
    pop rbx
    ret
CalculateRequestsChecksum endp

ResolveRelativeAddress proc
xor     eax, eax
test    rcx, rcx
jz      short loc_fin
mov     eax, edx
movsxd  rdx, dword ptr [rax+rcx]
add     rax, 4
add     rax, rdx
add     rax, rcx

loc_fin:
ret
ResolveRelativeAddress endp

END
