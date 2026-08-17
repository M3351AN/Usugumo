; Copyright (c) 2026 渟雲. All rights reserved.
EXTERNDEF Sha256Compress:PROC
EXTERNDEF kmemmove:PROC
EXTERNDEF kmemset:PROC

.CODE

; void __fastcall Sha256(const void *rcx, unsigned __int64 rdx, unsigned __int8 *r8)

Sha256 proc

state= -60h
last= -40h

push    rbp
push    rbx
push    rsi
push    rdi
push    r12
push    r14
push    r15
mov     rbp, rsp
sub     rsp, 80h
mov     rbx, rdx
mov     dword ptr [rbp+state], 6A09E667h
mov     rdi, rdx
shr     rbx, 6
mov     r15d, 3Fh ; '?'
mov     dword ptr [rbp+state+4], 0BB67AE85h
and     rdi, r15
mov     dword ptr [rbp+state+8], 3C6EF372h
mov     dword ptr [rbp+state+0Ch], 0A54FF53Ah
mov     r12, r8
mov     dword ptr [rbp+state+10h], 510E527Fh
mov     r14, rdx
mov     dword ptr [rbp+state+14h], 9B05688Ch
mov     rsi, rcx
mov     dword ptr [rbp+state+18h], 1F83D9ABh
mov     dword ptr [rbp+state+1Ch], 5BE0CD19h
test    rbx, rbx
jz      short loc_140003E06

loc_140003DEE:          ; state
lea     rdx, [rbp+state]
mov     rcx, rsi       ; block
call    Sha256Compress
db      3Eh, 3Eh
add     rsi, 40h ; '@'
sub     rbx, 1
jnz     short loc_140003DEE

loc_140003E06:
xor     ebx, ebx
test    rdi, rdi
jz      short loc_140003E59
test    r14b, 30h
jz      short loc_140003E59
lea     rcx, [rdi-1]
mov     ecx, ecx
lea     rdx, [rbp+last]
lea     rax, [rcx+rsi]
cmp     rdx, rax
ja      short loc_140003E32
lea     rax, [rbp+last]
add     rax, rcx
cmp     rax, rsi
jnb     short loc_140003E59

loc_140003E32:          ; Size
db      3Eh, 3Eh, 3Eh, 3Eh
mov     r8, rdi
lea     rcx, [rbp+last] ; void *
mov     rdx, rsi     ; Src
call    kmemmove

loc_140003E45:
inc     ebx
mov     eax, ebx
cmp     rax, rdi
jb      short loc_140003E45
jmp     short loc_140003E59

loc_140003E50:
mov     al, [rsi+rbx]
mov     [rbp+rbx+last], al
inc     ebx

loc_140003E59:
db      3Eh, 3Eh, 3Eh, 3Eh, 3Eh
mov     eax, ebx
cmp     rax, rdi
jb      short loc_140003E50
lea     ecx, [rbx+1]
mov     dword ptr [rbp+rbx+last], 80h
lea     rdi, [r14*8]
cmp     ecx, 38h ; '8'
jbe     short loc_140003EBC
cmp     ecx, 40h ; '@'
jnb     short loc_140003E95
mov     eax, ecx
sub     r15d, ebx
lea     rcx, [rbp+last]
mov     r8d, r15d       ; Size
add     rcx, rax       ; void *
xor     edx, edx        ; Val
call    kmemset

loc_140003E95:          ; state
db      3Eh, 3Eh, 3Eh
lea     rdx, [rbp+state]
lea     rcx, [rbp+last] ; block
call    Sha256Compress
xorps   xmm0, xmm0
xor     eax, eax
mov     qword ptr [rbp+last+30h], rax
movups  xmmword ptr [rbp+last], xmm0
movups  xmmword ptr [rbp+last+10h], xmm0
movups  xmmword ptr [rbp+last+20h], xmm0
jmp     short loc_140003ED7

loc_140003EBC:
jnb     short loc_140003ED7
mov     eax, ecx
mov     r8d, 37h ; '7'
lea     rcx, [rbp+last]
sub     r8d, ebx        ; Size
add     rcx, rax       ; void *
xor     edx, edx        ; Val
call    kmemset

loc_140003ED7:
xor     r8d, r8d

loc_140003EDA:
lea     eax, [r8*8]
mov     ecx, 38h ; '8'
sub     ecx, eax
mov     rdx, rdi
shr     rdx, cl
mov     [rbp+r8+last+38h], dl
inc     r8d
cmp     r8d, 8
jl      short loc_140003EDA
lea     rdx, [rbp+state] ; state
lea     rcx, [rbp+last] ; block
call    Sha256Compress
xor     r9d, r9d
xor     r10d, r10d

loc_140003F10:
mov     ecx, [rbp+r9*4+state]
mov     eax, ecx
movsxd  rdx, r10d
add     r10d, 4
shr     eax, 18h
mov     [r12+rdx], al
mov     eax, ecx
shr     eax, 10h
shr     ecx, 8
mov     [r12+rdx+1], al
mov     al, byte ptr [rbp+r9*4+state]
inc     r9d
mov     [r12+rdx+2], cl
mov     [r12+rdx+3], al
cmp     r9d, 8
jl      short loc_140003F10
add     rsp, 80h
pop     r15
pop     r14
pop     r12
pop     rdi
pop     rsi
pop     rbx
pop     rbp
ret
Sha256 endp

END
