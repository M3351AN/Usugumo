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

END
