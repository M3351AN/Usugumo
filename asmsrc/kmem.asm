; Copyright (c) 2026 渟雲. All rights reserved.
EXTERNDEF __cpu_features_init:PROC

__isa_info_t STRUC
    info    BYTE ?
            BYTE 63 DUP(?)
__isa_info_t ENDS

EXTERN __isa_info:__isa_info_t

.code

kmemmove proc
    mov     rax, rcx
    cmp     r8, 8
    jb      short loc_1406B6F80
    cmp     r8, 10h
    ja      short loc_1406B6F60
    mov     r11, [rdx]
    mov     rdx, [rdx+r8-8]
    mov     [rcx], r11
    mov     [rcx+r8-8], rdx
    ret

loc_1406B6F60:
    cmp     r8, 20h
    ja      short loc_1406B6FC0
    movups  xmm0, xmmword ptr [rdx]
    movups  xmm1, xmmword ptr [rdx+r8-10h]
    movups  xmmword ptr [rcx], xmm0
    movups  xmmword ptr [rcx+r8-10h], xmm1
    ret

    align 10h
loc_1406B6F80:
    test    r8, r8
    jz      short locret_1406B6F9A
    sub     rdx, rcx
    jb      short loc_1406B6FA0

loc_1406B6F8A:
    mov     r11b, [rcx+rdx]
    inc     rcx
    dec     r8
    mov     [rcx-1], r11b
    jnz     short loc_1406B6F8A

locret_1406B6F9A:
    ret

    align 10h
loc_1406B6FA0:
    add     rcx, r8

loc_1406B6FA3:
    mov     r11b, [rcx+rdx-1]
    dec     rcx
    dec     r8
    mov     [rcx], r11b
    jnz     short loc_1406B6FA3
    ret

    align 10h
loc_1406B6FC0:
    lea     r11, [rdx+r8]
    sub     rdx, rcx
    jnb     short loc_1406B6FD2
    cmp     r11, rcx
    ja      loc_1406B7140

loc_1406B6FD2:
    movups  xmm0, xmmword ptr [rcx+rdx]
    add     rcx, 10h
    test    cl, 0Fh
    jz      short loc_1406B6FF1
    and     rcx, 0FFFFFFFFFFFFFFF0h
    movups  xmm1, xmmword ptr [rcx+rdx]
    movups  xmmword ptr [rax], xmm0
    movaps  xmm0, xmm1
    add     rcx, 10h

loc_1406B6FF1:
    add     r8, rax
    sub     r8, rcx
    mov     r9, r8
    shr     r9, 6
    jz      short loc_1406B706F
    cmp     r9, 1000h
    ja      loc_1406B70C0
    and     r8, 3Fh
    jmp     short loc_1406B7040

    align 10h
loc_1406B7040:
    movups  xmm1, xmmword ptr [rcx+rdx]
    movups  xmm2, xmmword ptr [rcx+rdx+10h]
    movups  xmm3, xmmword ptr [rcx+rdx+20h]
    movups  xmm4, xmmword ptr [rcx+rdx+30h]
    movaps  xmmword ptr [rcx-10h], xmm0
    add     rcx, 40h
    dec     r9
    movaps  xmmword ptr [rcx-40h], xmm1
    movaps  xmmword ptr [rcx-30h], xmm2
    movaps  xmmword ptr [rcx-20h], xmm3
    movaps  xmm0, xmm4
    jnz     short loc_1406B7040

loc_1406B706F:
    mov     r9, r8
    shr     r9, 4
    jz      short loc_1406B7091
    nop     dword ptr [rax+rax+00000000h]

loc_1406B7080:
    movaps  xmmword ptr [rcx-10h], xmm0
    movups  xmm0, xmmword ptr [rcx+rdx]
    add     rcx, 10h
    dec     r9
    jnz     short loc_1406B7080

loc_1406B7091:
    and     r8, 0Fh
    jz      short loc_1406B70A5
    lea     r11, [rcx+r8-10h]
    movups  xmm1, xmmword ptr [r11+rdx]
    movups  xmmword ptr [r11], xmm1

loc_1406B70A5:
    movaps  xmmword ptr [rcx-10h], xmm0
    ret

    align 10h
loc_1406B70C0:
    mov     r9, r8
    shr     r9, 6
    and     r8, 3Fh
    prefetchnta byte ptr [rcx+rdx+40h]
    jmp     short loc_1406B7100

    align 10h
loc_1406B7100:
    movups  xmm1, xmmword ptr [rcx+rdx]
    movups  xmm2, xmmword ptr [rcx+rdx+10h]
    movups  xmm3, xmmword ptr [rcx+rdx+20h]
    movups  xmm4, xmmword ptr [rcx+rdx+30h]
    movntps xmmword ptr [rcx-10h], xmm0
    add     rcx, 40h
    prefetchnta byte ptr [rcx+rdx+40h]
    dec     r9
    movntps xmmword ptr [rcx-40h], xmm1
    movntps xmmword ptr [rcx-30h], xmm2
    movntps xmmword ptr [rcx-20h], xmm3
    movaps  xmm0, xmm4
    jnz     short loc_1406B7100
    sfence
    jmp     loc_1406B706F

    align 10h
loc_1406B7140:
    add     rcx, r8
    movups  xmm0, xmmword ptr [rcx+rdx-10h]
    sub     rcx, 10h
    sub     r8, 10h
    test    cl, 0Fh
    jz      short loc_1406B716D
    mov     r11, rcx
    and     rcx, 0FFFFFFFFFFFFFFF0h
    movups  xmm1, xmmword ptr [rcx+rdx]
    movups  xmmword ptr [r11], xmm0
    movaps  xmm0, xmm1
    mov     r8, rcx
    sub     r8, rax

loc_1406B716D:
    mov     r9, r8
    shr     r9, 6
    jz      short loc_1406B71AF
    and     r8, 3Fh
    jmp     short loc_1406B7180

    align 10h
loc_1406B7180:
    movups  xmm1, xmmword ptr [rcx+rdx-10h]
    movups  xmm2, xmmword ptr [rcx+rdx-20h]
    movups  xmm3, xmmword ptr [rcx+rdx-30h]
    movups  xmm4, xmmword ptr [rcx+rdx-40h]
    movaps  xmmword ptr [rcx], xmm0
    sub     rcx, 40h
    dec     r9
    movaps  xmmword ptr [rcx+30h], xmm1
    movaps  xmmword ptr [rcx+20h], xmm2
    movaps  xmmword ptr [rcx+10h], xmm3
    movaps  xmm0, xmm4
    jnz     short loc_1406B7180

loc_1406B71AF:
    mov     r9, r8
    shr     r9, 4
    jz      short loc_1406B71D1
    nop     dword ptr [rax+rax+00000000h]

loc_1406B71C0:
    movaps  xmmword ptr [rcx], xmm0
    movups  xmm0, xmmword ptr [rcx+rdx-10h]
    sub     rcx, 10h
    dec     r9
    jnz     short loc_1406B71C0

loc_1406B71D1:
    and     r8, 0Fh
    jz      short loc_1406B71E6
    mov     r11, rcx
    sub     r11, r8
    movups  xmm1, xmmword ptr [r11+rdx]
    movups  xmmword ptr [r11], xmm1

loc_1406B71E6:
    movaps  xmmword ptr [rcx], xmm0
    ret
kmemmove endp

__kmemset_query proc

var_38= xmmword ptr -38h

push    r9
push    r8
push    rdx
push    rcx
push    rax
sub     rsp, 30h
movaps  [rsp+58h+var_38], xmm0
call    __cpu_features_init
movaps  xmm0, [rsp+58h+var_38]
add     rsp, 30h
pop     rax
pop     rcx
pop     rdx
pop     r8
pop     r9
ret
__kmemset_query endp

__kmemset_repmovs proc
push    rdi
test    __isa_info.info, 1
jz      short repmovs20

repmovs10:
mov     rdi, rcx
add     r8, rcx
movups  xmmword ptr [rcx], xmm0
add     rdi, 40h ; '@'
movups  xmmword ptr [rcx+10h], xmm0
and     rdi, 0FFFFFFFFFFFFFFC0h
movups  xmmword ptr [rcx+20h], xmm0
sub     r8, rdi
movups  xmmword ptr [rcx+30h], xmm0
mov     rcx, r8
mov     r9, rax
movq    rax, xmm0
rep stosb
mov     rax, r9
pop     rdi
ret

repmovs20:
call    __kmemset_query
jmp     short repmovs10
__kmemset_repmovs endp

kmemset proc
mov     rax, rcx
movzx   edx, dl
mov     r9, 101010101010101h
imul    rdx, r9
movq    xmm0, rdx
movlhps xmm0, xmm0
cmp     r8, 40h ; '@'
jb      short mset45

mset10:
test    __isa_info.info, 2
jz      short mset20
cmp     r8, 320h
jnb     __kmemset_repmovs

mset20:
movups  xmmword ptr [rcx], xmm0
add     r8, rcx
add     rcx, 10h
and     rcx, 0FFFFFFFFFFFFFFF0h
sub     r8, rcx
cmp     r8, 40h ; '@'
jb      short mset46
lea     rdx, [rcx+r8-10h]
lea     r9, [rcx+r8-30h]
and     r9, 0FFFFFFFFFFFFFFF0h
shr     r8, 6

mset30:
movaps  xmmword ptr [rcx], xmm0
movaps  xmmword ptr [rcx+10h], xmm0
add     rcx, 40h ; '@'
dec     r8
movaps  xmmword ptr [rcx-20h], xmm0
movaps  xmmword ptr [rcx-10h], xmm0
jnz     short mset30
movaps  xmmword ptr [r9], xmm0
movaps  xmmword ptr [r9+10h], xmm0
movaps  xmmword ptr [r9+20h], xmm0
movups  xmmword ptr [rdx], xmm0
ret
align 10h

mset45:
cmp     r8, 10h
jb      short mset47

mset46:
lea     r9, [r8+rcx-10h]
and     r8, 20h
movups  xmmword ptr [rcx], xmm0
shr     r8, 1
movups  xmmword ptr [r9], xmm0
movups  xmmword ptr [rcx+r8], xmm0
neg     r8
movups  xmmword ptr [r9+r8], xmm0
ret
align 10h

mset47:
cmp     r8, 4
jb      short mset48
lea     r9, [r8+rcx-4]
and     r8, 8
mov     [rcx], edx
shr     r8, 1
mov     [r9], edx
mov     [rcx+r8], edx
neg     r8
mov     [r9+r8], edx
ret
align 10h

mset48:
test    r8, r8
jz      short mset50
mov     [rcx], dl
lea     r9, [rcx+r8-2]
cmp     r8, 1
jz      short mset50
mov     [r9], dx

mset50:
ret
kmemset endp

END
