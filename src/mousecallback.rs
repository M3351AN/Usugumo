// Copyright (c) 2026 渟雲. All rights reserved.

use core::arch::global_asm;

global_asm!(
    ".text
.global MouseClassReadCopyDataMeme
MouseClassReadCopyDataMeme:
    mov r11, rsp
    mov qword ptr [r11+0x8], rbx
    mov qword ptr [r11+0x10], rbp
    mov qword ptr [r11+0x18], rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x50
    inc dword ptr [rcx+0xa8]
    mov rsi, rdx
    mov eax, dword ptr [rcx+0x54]
    mov rdi, rcx
    mov r13, qword ptr [rdx+0xb8]
    lea ebp, [rax+rax*2]
    mov ebx, dword ptr [r13+0x8]
    shl ebp, 0x3
    mov edx, dword ptr [rdi+0x88]
    cmp ebp, ebx
    cmovae ebp, ebx
    sub edx, dword ptr [rdi+0x78]
    add edx, dword ptr [rdi+0x68]
    mov r12d, ebp
    cmp ebp, edx
    cmovae r12d, edx
    mov r14, qword ptr [rsi+0x18]
    mov rdx, qword ptr [rdi+0x78]
    mov rcx, r14
    mov r8d, r12d
    mov r15d, r12d
    call kmemmove
    add r14, r15
    mov ebx, ebp
    sub ebx, r12d
    je 1f
    mov rdx, qword ptr [rdi+0x68]
    mov r8, rbx
    mov rcx, r14
    call kmemmove
    mov rcx, qword ptr [rdi+0x68]
    add rcx, rbx
    mov qword ptr [rdi+0x78], rcx
    jmp 2f
1:
    add qword ptr [rdi+0x78], r15
2:
    mov ebx, ebp
    mov rax, 0x0aaaaaaaaaaaaaaab
    mul rbx
    shr rdx, 0x4
    sub dword ptr [rdi+0x54], edx
    jne 3f
    mov byte ptr [rdi+0x42], 0x1
3:
    mov qword ptr [rsi+0x38], rbx
    lea r11, [rsp+0x50]
    mov rbx, qword ptr [r11+0x30]
    xor eax, eax
    mov rsi, qword ptr [r11+0x40]
    mov dword ptr [r13+0x8], ebp
    mov rbp, qword ptr [r11+0x38]
    mov rsp, r11
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    ret

.global MouseClassDequeueReadMeme
MouseClassDequeueReadMeme:
    xor edx, edx
    lea r8, [rcx+0x98]
1:
    mov rcx, qword ptr [r8]
    cmp rcx, r8
    je 2f
    cmp qword ptr [rcx+0x8], r8
    jne 3f
    mov rax, qword ptr [rcx]
    cmp qword ptr [rax+0x8], rcx
    jne 3f
    mov qword ptr [r8], rax
    lea rdx, [rcx-0xa8]
    mov qword ptr [rax+0x8], r8
    xor eax, eax
    xchg qword ptr [rdx+0x68], rax
    test rax, rax
    jne 4f
    mov qword ptr [rcx+0x8], rcx
    xor edx, edx
    mov qword ptr [rcx], rcx
4:
    test rdx, rdx
    je 1b
2:
    mov rax, rdx
    ret
    int 0x3
3:
    mov ecx, 0x3
    int 0x29

.global MouseClassServiceCallbackMeme
MouseClassServiceCallbackMeme:
    mov rax, rsp
    mov qword ptr [rax+0x8], rbx
    mov qword ptr [rax+0x10], rsi
    mov qword ptr [rax+0x18], rdi
    mov qword ptr [rax+0x20], r9
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbp, rsp
    sub rsp, 0x70
    mov r13, r9
    mov rbx, r8
    mov r14, rdx
    mov r15, rcx
    lea rax, [rip + WPP_RECORDER_INITIALIZED]
    xor esi, esi
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rax
    jne 1f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 1f
    mov rcx, qword ptr [rcx+0x40]
    lea r9d, [rsi+0x32]
    lea r8d, [rsi+0x3]
    mov dl, 0x5
    call WPP_RECORDER_SFMeme
1:
    mov rdi, qword ptr [r15+0x40]
    sub ebx, r14d
    mov r12d, esi
    mov dword ptr [r13+0x0], esi
    lea rcx, [rdi+0x90]
    call qword ptr [rip + _KeAcquireSpinLockAtDpcLevel]
    nop dword ptr [rax+rax*1+0x0]
    lea rax, [rbp-0x10]
    mov rcx, rdi
    mov qword ptr [rbp-0x8], rax
    lea rax, [rbp-0x10]
    mov qword ptr [rbp-0x10], rax
    call MouseClassDequeueReadMeme
    mov rsi, rax
    xor r9d, r9d
    mov rax, 0x0aaaaaaaaaaaaaaab
    test rsi, rsi
    je 6f
    mov r13, qword ptr [rsi+0xb8]
    mov r12d, ebx
    mov r8d, dword ptr [r13+0x8]
    cmp ebx, r8d
    cmovae r12d, r8d
    mul r12
    mov rax, qword ptr [rbp+0x48]
    shr rdx, 0x4
    add dword ptr [rax], edx
    lea rax, [rip + WPP_RECORDER_INITIALIZED]
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rax
    jne 5f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], r9w
    je 5f
    mov rax, qword ptr [rsi+0x18]
    mov rcx, qword ptr [rcx+0x40]
    mov qword ptr [rsp+0x50], rax
    mov qword ptr [rsp+0x48], r14
    mov dword ptr [rsp+0x40], r8d
    mov dword ptr [rsp+0x38], ebx
    mov qword ptr [rsp+0x30], rsi
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
5:
    mov rax, 0xfffff78000000014
    mov rax, qword ptr [rax]
    lea rdx, [rip + WPP_RECORDER_INITIALIZED]
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rdx
    jne 7f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    mov dword ptr [rsp+0x40], r12d
    mov qword ptr [rsp+0x38], rax
    mov qword ptr [rsp+0x30], rsi
    mov rcx, qword ptr [rcx+0x40]
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
7:
    mov rcx, qword ptr [rsi+0x18]
    mov r8, r12
    mov rdx, r14
    call kmemmove
    mov qword ptr [rsi+0x38], r12
    lea rcx, [rbp-0x10]
    xor r8d, r8d
    mov dword ptr [rsi+0x30], r8d
    add rsi, 0xa8
    mov dword ptr [r13+0x8], r12d
    mov rax, qword ptr [rbp-0x8]
    cmp qword ptr [rax], rcx
    jne 8f
    mov r13, qword ptr [rbp+0x48]
    lea rcx, [rbp-0x10]
    mov qword ptr [rsi], rcx
    mov qword ptr [rsi+0x8], rax
    mov qword ptr [rax], rsi
    mov qword ptr [rbp-0x8], rsi
6:
    mov eax, r12d
    add r14, rax
    sub ebx, r12d
    lea r12, [rip + WPP_RECORDER_INITIALIZED]
    xor esi, esi
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], r12
    jne 9f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 9f
    mov rcx, qword ptr [rcx+0x40]
    mov dword ptr [rsp+0x30], ebx
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
9:
    test ebx, ebx
    je 10f
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], r12
    jne 11f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 11f
    mov eax, dword ptr [rdi+0x54]
    mov r9d, 0x36
    mov rcx, qword ptr [rcx+0x40]
    mov dword ptr [rsp+0x38], ebx
    lea edx, [rax+rax*2]
    mov eax, dword ptr [rdi+0x88]
    shl edx, 0x3
    sub eax, edx
    mov dword ptr [rsp+0x30], eax
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
11:
    mov ecx, dword ptr [rdi+0x88]
    cmp ecx, ebx
    mov r12d, ecx
    cmovae r12d, ebx
    sub ecx, dword ptr [rdi+0x70]
    mov ebx, dword ptr [rdi+0x68]
    add ebx, ecx
    lea rax, [rip + WPP_RECORDER_INITIALIZED]
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rax
    jne 12f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 12f
    mov rcx, qword ptr [rcx+0x40]
    mov r9d, 0x38
    mov dword ptr [rsp+0x38], ebx
    mov dword ptr [rsp+0x30], r12d
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
    lea rax, [rip + WPP_RECORDER_INITIALIZED]
12:
    cmp r12d, ebx
    mov esi, r12d
    cmovae esi, ebx
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rax
    jne 13f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    xor eax, eax
    cmp word ptr [rcx+0x48], ax
    je 13f
    mov rcx, qword ptr [rcx+0x40]
    lea r9d, [rax+0x39]
    mov rax, qword ptr [rdi+0x70]
    mov qword ptr [rsp+0x40], rax
    mov qword ptr [rsp+0x38], r14
    mov dword ptr [rsp+0x30], esi
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
13:
    mov rcx, qword ptr [rdi+0x70]
    mov rdx, r14
    mov r8d, esi
    mov ebx, esi
    call kmemmove
    add qword ptr [rdi+0x70], rbx
    add r14, rbx
    mov rdx, qword ptr [rdi+0x68]
    mov eax, dword ptr [rdi+0x88]
    mov rcx, qword ptr [rdi+0x70]
    add rax, rdx
    cmp rcx, rax
    jb 14f
    mov qword ptr [rdi+0x70], rdx
    mov rcx, rdx
14:
    mov ebx, r12d
    sub ebx, esi
    je 15f
    lea rdx, [rip + WPP_RECORDER_INITIALIZED]
    mov rax, rcx
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], rdx
    jne 16f
    mov rdx, qword ptr [rip + WPP_GLOBAL_Control]
    xor r8d, r8d
    cmp word ptr [rdx+0x48], r8w
    je 16f
    mov qword ptr [rsp+0x40], rcx
    lea r9d, [r8+0x3a]
    mov rcx, qword ptr [rdx+0x40]
    mov qword ptr [rsp+0x38], r14
    mov dword ptr [rsp+0x30], ebx
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
    mov rax, qword ptr [rdi+0x70]
16:
    mov r8, rbx
    mov rdx, r14
    mov rcx, rax
    call kmemmove
    add qword ptr [rdi+0x70], rbx
15:
    mov ecx, r12d
    mov rax, 0x0aaaaaaaaaaaaaaab
    mul rcx
    shr rdx, 0x4
    add dword ptr [rdi+0x54], edx
    mov ecx, dword ptr [r13+0x0]
    add ecx, edx
    mov eax, ecx
    mov dword ptr [r13+0x0], ecx
    lea r12, [rip + WPP_RECORDER_INITIALIZED]
    xor esi, esi
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], r12
    jne 10f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 10f
    mov rcx, qword ptr [rcx+0x40]
    mov dword ptr [rsp+0x48], eax
    mov rax, qword ptr [rdi+0x78]
    mov qword ptr [rsp+0x40], rax
    mov rax, qword ptr [rdi+0x70]
    mov qword ptr [rsp+0x38], rax
    mov eax, dword ptr [rdi+0x54]
    mov dword ptr [rsp+0x30], eax
    mov qword ptr [rsp+0x28], r15
    call WPP_RECORDER_SFMeme
    jmp 10f
17:
    mov rcx, rdi
    call MouseClassDequeueReadMeme
    mov rbx, rax
    test rax, rax
    je 18f
    mov rdx, rax
    mov rcx, rdi
    call MouseClassReadCopyDataMeme
    mov dword ptr [rbx+0x30], eax
    lea rcx, [rbp-0x10]
    mov rdx, qword ptr [rbp-0x8]
    lea rax, [rbx+0xa8]
    cmp qword ptr [rdx], rcx
    jne 8f
    mov qword ptr [rax+0x8], rdx
    lea rcx, [rbp-0x10]
    mov qword ptr [rax], rcx
    mov qword ptr [rdx], rax
    mov qword ptr [rbp-0x8], rax
10:
    cmp dword ptr [rdi+0x54], esi
    ja 17b
18:
    lea rcx, [rdi+0x90]
    call qword ptr [rip + _KeReleaseSpinLockFromDpcLevel]
    nop dword ptr [rax+rax*1+0x0]
19:
    mov rbx, qword ptr [rbp-0x10]
    lea rax, [rbp-0x10]
    cmp rbx, rax
    je 20f
    lea rax, [rbp-0x10]
    cmp qword ptr [rbx+0x8], rax
    jne 8f
    mov rax, qword ptr [rbx]
    cmp qword ptr [rax+0x8], rbx
    jne 8f
    lea rcx, [rbp-0x10]
    mov qword ptr [rbp-0x10], rax
    mov qword ptr [rax+0x8], rcx
    mov dl, 0x6
    lea rcx, [rbx-0xa8]
    call qword ptr [rip + _IofCompleteRequest]
    nop dword ptr [rax+rax*1+0x0]
    lea rcx, [rdi+0x20]
    mov r8d, 0x20
    lea rdx, [rbx-0xa8]
    call qword ptr [rip + _IoReleaseRemoveLockEx]
    nop dword ptr [rax+rax*1+0x0]
    jmp 19b
8:
    mov ecx, 0x3
    int 0x29
20:
    cmp qword ptr [rip + WPP_RECORDER_INITIALIZED], r12
    jne 21f
    mov rcx, qword ptr [rip + WPP_GLOBAL_Control]
    cmp word ptr [rcx+0x48], si
    je 21f
    mov rcx, qword ptr [rcx+0x40]
    mov r9d, 0x3c
    mov dl, 0x5
    lea r8d, [r9-0x39]
    call WPP_RECORDER_SFMeme
21:
    lea r11, [rsp+0x70]
    mov rbx, qword ptr [r11+0x30]
    mov rsi, qword ptr [r11+0x38]
    mov rdi, qword ptr [r11+0x40]
    mov rsp, r11
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret"
);
