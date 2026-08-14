; Copyright (c) 2026 渟雲. All rights reserved.
.code

RtlImageNtHeaderMeme proc
xor     r8d, r8d
lea     rax, [rcx-1]
cmp     rax, 0FFFFFFFFFFFFFFFDh
ja      short loc_14043D71B
mov     eax, 5A4Dh
cmp     [rcx], ax
jnz     short loc_14043D71B
mov     eax, [rcx+3Ch]
add     rax, rcx
cmp     rax, rcx
jb      short loc_14043D71B
mov     rdx, 7FFFFFFEFFFFh
cmp     rcx, rdx
jbe     short loc_14043D720

loc_14043D711:
cmp     dword ptr [rax], 4550h
cmovz   r8, rax

loc_14043D71B:
mov     rax, r8
ret
align 10h

loc_14043D720:
lea     rcx, [rax+107h]
cmp     rcx, rax
jb      short loc_14043D71B
cmp     rcx, rdx
jbe     short loc_14043D711
jmp     short loc_14043D71B
RtlImageNtHeaderMeme endp

RtlCompareMemoryMeme proc
push    rsi
push    rdi
push    rbx
push    rbp
mov     rsi, rcx
mov     rdi, rdx
mov     rbx, r8
xor     edx, ecx
and     edx, 7
jnz     short loc_1406AADB2
cmp     rbx, 8
jb      short loc_1406AADB2
mov     r9, rdi
neg     ecx
and     ecx, 7
jz      short loc_1406AAD76
sub     rbx, rcx
repe cmpsb
jnz     short loc_1406AADA6

loc_1406AAD76:
mov     rcx, rbx
and     rcx, 0FFFFFFFFFFFFFFF8h
jz      short loc_1406AAD9A
sub     rbx, rcx
shr     rcx, 3
repe cmpsq
jz      short loc_1406AAD9A
inc     rcx
sub     rsi, 8
sub     rdi, 8
shl     rcx, 3

loc_1406AAD9A:
add     rbx, rcx
jz      short loc_1406AADA9
mov     rcx, rbx
repe cmpsb
jz      short loc_1406AADA9

loc_1406AADA6:
dec     rdi

loc_1406AADA9:
sub     rdi, r9
mov     rax, rdi
pop     rbp
pop     rbx
pop     rdi
pop     rsi
ret

loc_1406AADB2:
test    rbx, rbx
jz      short loc_1406AADC4
mov     rcx, rbx
repe cmpsb
jz      short loc_1406AADC4
inc     rcx
sub     rbx, rcx

loc_1406AADC4:
mov     rax, rbx
pop     rbp
pop     rbx
pop     rdi
pop     rsi
ret
RtlCompareMemoryMeme endp

END
