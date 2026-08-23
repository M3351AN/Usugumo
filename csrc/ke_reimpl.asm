; Copyright (c) 2026 渟雲. All rights reserved.
.code

KeGetCurrentIrqlMeme proc
mov     rax, cr8
ret
KeGetCurrentIrqlMeme endp

KzRaiseIrqlMeme proc
push    rbx
sub     rsp, 20h
mov     rbx, cr8
movzx   eax, cl
mov     cr8, rax
;cmp     cs:KiIrqlFlags, 0
;jnz     short loc_1403F9AE4
loc_1403F9ADA:
movzx   eax, bl
add     rsp, 20h
pop     rbx
ret
;loc_1403F9AE4:
;movzx   edx, cl
;movzx   ecx, bl
;call    KiRaiseIrqlProcessIrqlFlags
;jmp     short loc_1403F9ADA
KzRaiseIrqlMeme endp

KzLowerIrqlMeme proc
push    rbx
sub     rsp, 20h
;cmp     cs:KiIrqlFlags, 0
movzx   ebx, cl
;jz      short loc_1403F1C2E
;mov     rcx, cr8
;movzx   edx, bl
;call    KiLowerIrqlProcessIrqlFlags
;loc_1403F1C2E:
mov     cr8, rbx
add     rsp, 20h
pop     rbx
ret
KzLowerIrqlMeme endp

END
