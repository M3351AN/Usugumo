; Copyright (c) 2026 渟雲. All rights reserved.

EXTERNDEF _KeAcquireSpinLockAtDpcLevel:PROC
EXTERNDEF _KeReleaseSpinLockFromDpcLevel:PROC
EXTERNDEF _IofCompleteRequest:PROC
EXTERNDEF _IoReleaseRemoveLockEx:PROC
EXTERNDEF kmemmove:PROC
; at mouse.asm
EXTERNDEF WPP_RECORDER_SFMeme:PROC

.data
WPP_RECORDER_INITIALIZED dq 0;
WPP_GLOBAL_Control dq 0;

.code

;WPP_RECORDER_SFMeme proc
;ret
;WPP_RECORDER_SFMeme endp

KeyboardClassDequeueReadMeme proc
xor     edx, edx
lea     r8, [rcx+0A8h]

jump1:                                 ; dequeue loop
mov     rcx, qword ptr [r8]
cmp     rcx, r8
je      jump3
cmp     qword ptr [rcx+8h], r8
jne     jump4
mov     rax, qword ptr [rcx]
cmp     qword ptr [rax+8h], rcx
jne     jump4
mov     qword ptr [r8], rax
lea     rdx, [rcx-0A8h]
mov     qword ptr [rax+8h], r8
xor     eax, eax
xchg    qword ptr [rdx+68h], rax
test    rax, rax
jne     jump2
mov     qword ptr [rcx+8h], rcx
xor     edx, edx
mov     qword ptr [rcx], rcx

jump2:                                 ; got valid IRP
test    rdx, rdx
je      jump1

jump3:                                 ; return IRP (or 0)
mov     rax, rdx
ret
int     3

jump4:                                 ; list corruption, failfast
mov     ecx, 3h
int     29h
KeyboardClassDequeueReadMeme endp

KeyboardClassReadCopyDataMeme proc
var_28= -28h
arg_0= 8
arg_8= 10h
arg_10= 18h

mov     r11, rsp
mov     [rsp+arg_0], rbx
mov     [rsp+arg_8], rbp
mov     [rsp+arg_10], rsi
push    rdi
push    r12
push    r13
push    r14
push    r15
sub     rsp, 50h
inc     dword ptr [rcx+0B8h]
mov     rsi, rdx
mov     eax, dword ptr [rcx+54h]
mov     rdi, rcx
mov     r13, qword ptr [rdx+0B8h]
lea     ebp, [rax+rax*2]
mov     ebx, dword ptr [r13+8h]
shl     ebp, 2h
mov     edx, dword ptr [rdi+8Ch]
cmp     ebp, ebx
cmovae ebp, ebx
sub     edx, dword ptr [rdi+78h]
add     edx, dword ptr [rdi+68h]
mov     r12d, ebp
cmp     ebp, edx
cmovae r12d, edx
mov     r14, qword ptr [rsi+18h]
mov     rdx, qword ptr [rdi+78h]
mov     rcx, r14
mov     r8d, r12d
mov     r15d, r12d
call    kmemmove
add     r14, r15
mov     ebx, ebp
sub     ebx, r12d
je      jump5

loc_140002EE3:
mov     rdx, qword ptr [rdi+68h]
mov     r8, rbx
mov     rcx, r14
call    kmemmove
mov     rcx, qword ptr [rdi+68h]
add     rcx, rbx
mov     qword ptr [rdi+78h], rcx
jmp     loc_140002D4E

jump5:                                 ; no wrap
add     qword ptr [rdi+78h], r15

loc_140002D4E:
mov     edi, esi
mov     rax, 0AAAAAAAAAAAAAAABh
mul     rdi
shr     rdx, 3
sub     [rbx+54h], edx
jne     loc_140002DAC

loc_140002D9C:
mov     byte ptr [rbx+169h], 1

loc_140002DAC:
mov     qword ptr [rsi+38h], rbx
lea     r11, [rsp+78h+var_28]
mov     [rbp+38h], rdi
mov     rbx, [r11+30h]
xor     eax, eax
mov     rbp, [r11+38h]
mov     [r13+8], esi
mov     rsi, [r11+40h]
mov     rsp, r11
pop     r15
pop     r14
pop     r13
pop     r12
pop     rdi
ret
KeyboardClassReadCopyDataMeme endp

KeyboardClassServiceCallbackMeme proc
arg_0= 8
arg_8= 10h
arg_10=  18h
arg_18=  20h

mov     rax, rsp
mov     [rax+arg_0], rbx
mov     [rax+arg_8], rsi
mov     [rax+arg_10], rdi
mov     [rax+arg_18], r9
push    rbp
push    r12
push    r13
push    r14
push    r15
mov     rbp, rsp
sub     rsp, 70h
mov     r13, r9
mov     rbx, r8
mov     r14, rdx
mov     r15, rcx
lea     rax, WPP_RECORDER_INITIALIZED
xor     esi, esi
cmp     WPP_RECORDER_INITIALIZED, rax
jne     loc_140002321

loc_14000253E:
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_140002321
mov     rcx, [rcx+40h]
lea     r9d, [rsi+32h]
lea     r8d, [rsi+3h]
mov     dl, 5
call    WPP_RECORDER_SFMeme

loc_140002321:
mov     rdi, qword ptr [r15+40h]
sub     ebx, r14d
mov     r12d, esi
mov     dword ptr [r13+0h], esi
lea     rcx, [rdi+0A0h]
call    qword ptr _KeAcquireSpinLockAtDpcLevel
nop     dword ptr [rax+rax*1+0h]
lea     rax, [rbp-10h]
mov     rcx, rdi
mov     qword ptr [rbp-8h], rax
lea     rax, [rbp-10h]
mov     qword ptr [rbp-10h], rax
call    KeyboardClassDequeueReadMeme
mov     rsi, rax

loc_1400023A1:
xor     r9d, r9d
mov     rax, 0aaaaaaaaaaaaaaabh
test    rsi, rsi
je      loc_140002467
mov     r13, qword ptr [rsi+0B8h]
mov     r12d, ebx
mov     r8d, dword ptr [r13+8h]
cmp     ebx, r8d
cmovae r12d, r8d
mul     r12
mov     rax, qword ptr [rbp+48h]
shr     rdx, 3h
add     dword ptr [rax], edx
lea     rax, WPP_RECORDER_INITIALIZED
cmp     WPP_RECORDER_INITIALIZED, rax
jne     loc_1400023EB

loc_1400025BF:
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], r9w
je      loc_1400023EB
mov     rax, qword ptr [rsi+18h]
mov     rcx, qword ptr [rcx+40h]
mov     qword ptr [rsp+50h], rax
mov     qword ptr [rsp+48h], r14
mov     dword ptr [rsp+40h], r8d
mov     dword ptr [rsp+38h], ebx
mov     qword ptr [rsp+30h], rsi
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme

loc_1400023EB:
mov     rax, 0FFFFF78000000014h
mov     rax, qword ptr [rax]
lea     rdx, WPP_RECORDER_INITIALIZED
cmp     WPP_RECORDER_INITIALIZED, rdx
jne     loc_14000240C

loc_1400026A6:
mov     rcx, qword ptr WPP_GLOBAL_Control
mov     dword ptr [rsp+40h], r12d
mov     qword ptr [rsp+38h], rax
mov     qword ptr [rsp+30h], rsi
mov     rcx, qword ptr [rcx+40h]
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme

loc_14000240C:
mov     rcx, qword ptr [rsi+18h]
mov     r8, r12
mov     rdx, r14
call    kmemmove
mov     qword ptr [rsi+38h], r12
lea     rcx, [rbp-10h]
xor     r8d, r8d
mov     dword ptr [rsi+30h], r8d
add     rsi, 0A8h
mov     dword ptr [r13+8h], r12d
mov     rax, qword ptr [rbp-8h]
cmp     qword ptr [rax], rcx
jne     loc_140002888
mov     r13, qword ptr [rbp+48h]
lea     rcx, [rbp-10h]
mov     qword ptr [rsi], rcx
mov     qword ptr [rsi+8h], rax
mov     qword ptr [rax], rsi
mov     qword ptr [rbp-8h], rsi

loc_140002467:
mov     eax, r12d
add     r14, rax
sub     ebx, r12d
lea     r12, WPP_RECORDER_INITIALIZED
xor     esi, esi
cmp     WPP_RECORDER_INITIALIZED, r12
jne     loc_14000247D

loc_140002596:
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_14000247D
mov     rcx, qword ptr [rcx+40h]
mov     dword ptr [rsp+30h], ebx
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme

loc_14000247D:
test    ebx, ebx
je      loc_140002485
cmp     WPP_RECORDER_INITIALIZED, r12
jne     loc_1400026E4

loc_140002844:
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_1400026E4
mov     eax, dword ptr [rdi+54h]
mov     r9d, 36h
mov     rcx, qword ptr [rcx+40h]
mov     dword ptr [rsp+38h], ebx
lea     edx, [rax+rax*2]
mov     eax, dword ptr [rdi+8Ch]
shl     edx, 2h
sub     eax, edx
mov     dword ptr [rsp+30h], eax
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme

loc_1400026E4:
mov     ecx, dword ptr [rdi+8Ch]
cmp     ecx, ebx
mov     r12d, ecx
cmovae r12d, ebx
sub     ecx, dword ptr [rdi+70h]
mov     ebx, dword ptr [rdi+68h]
add     ebx, ecx
lea     rax, WPP_RECORDER_INITIALIZED
cmp     WPP_RECORDER_INITIALIZED, rax
jne     loc_14000270B

loc_1400027D4:
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_14000270B
mov     rcx, qword ptr [rcx+40h]
mov     r9d, 38h
mov     dword ptr [rsp+38h], ebx
mov     dword ptr [rsp+30h], r12d
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme
lea     rax, WPP_RECORDER_INITIALIZED

loc_14000270B:
cmp     r12d, ebx
mov     esi, r12d
cmovae esi, ebx
cmp     WPP_RECORDER_INITIALIZED, rax
jne     loc_14000271D

loc_140002807:
mov     rcx, qword ptr WPP_GLOBAL_Control
xor     eax, eax
cmp     word ptr [rcx+48h], ax
je      loc_14000271D
mov     rcx, qword ptr [rcx+40h]
lea     r9d, [rax+39h]
mov     rax, qword ptr [rdi+70h]
mov     qword ptr [rsp+40h], rax
mov     qword ptr [rsp+38h], r14
mov     dword ptr [rsp+30h], esi
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme

loc_14000271D:
mov     rcx, qword ptr [rdi+70h]
mov     rdx, r14
mov     r8d, esi
mov     ebx, esi
call    kmemmove
add     qword ptr [rdi+70h], rbx
add     r14, rbx
mov     rdx, qword ptr [rdi+68h]
mov     eax, dword ptr [rdi+8Ch]
mov     rcx, qword ptr [rdi+70h]
add     rax, rdx
cmp     rcx, rax
jb      loc_14000289B
mov     qword ptr [rdi+70h], rdx
mov     rcx, rdx

loc_14000289B:
mov     ebx, r12d
sub     ebx, esi
je      loc_140002763
lea     rdx, WPP_RECORDER_INITIALIZED
mov     rax, rcx
cmp     WPP_RECORDER_INITIALIZED, rdx
jne     loc_1400028E7

loc_1400028A7:
mov     rdx, qword ptr WPP_GLOBAL_Control
xor     r8d, r8d
cmp     word ptr [rdx+48h], r8w
je      loc_1400028E7
mov     qword ptr [rsp+40h], rcx
lea     r9d, [r8+03Ah]
mov     rcx, qword ptr [rdx+40h]
mov     qword ptr [rsp+38h], r14
mov     dword ptr [rsp+30h], ebx
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme
mov     rax, qword ptr [rdi+70h]

loc_1400028E7:
mov     r8, rbx
mov     rdx, r14
mov     rcx, rax
call    kmemmove
add     qword ptr [rdi+70h], rbx

loc_140002763:
mov     ecx, r12d
mov     rax, 0aaaaaaaaaaaaaaabh
mul     rcx
shr     rdx, 3h
add     dword ptr [rdi+54h], edx
mov     ecx, dword ptr [r13+0h]
add     ecx, edx
mov     eax, ecx
mov     dword ptr [r13+0h], ecx
lea     r12, WPP_RECORDER_INITIALIZED
xor     esi, esi
cmp     WPP_RECORDER_INITIALIZED, r12
jne     loc_140002485

jump6:                                 ; WPP trace (never run)
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_140002485
mov     rcx, qword ptr [rcx+40h]
mov     dword ptr [rsp+48h], eax
mov     rax, qword ptr [rdi+78h]
mov     qword ptr [rsp+40h], rax
mov     rax, qword ptr [rdi+70h]
mov     qword ptr [rsp+38h], rax
mov     eax, dword ptr [rdi+54h]
mov     dword ptr [rsp+30h], eax
mov     qword ptr [rsp+28h], r15
call    WPP_RECORDER_SFMeme
jmp     loc_140002485

loc_14000260F:
mov     rcx, rdi
call    KeyboardClassDequeueReadMeme
mov     rbx, rax
test    rax, rax
je      loc_14000248F
mov     rdx, rax
mov     rcx, rdi
call    KeyboardClassReadCopyDataMeme
mov     dword ptr [rbx+30h], eax
lea     rcx, [rbp-10h]
mov     rdx, qword ptr [rbp-8h]
lea     rax, [rbx+0A8h]
cmp     qword ptr [rdx], rcx
jne     loc_140002888
mov     qword ptr [rax+8h], rdx
lea     rcx, [rbp-10h]
mov     qword ptr [rax], rcx
mov     qword ptr [rdx], rax
mov     qword ptr [rbp-8h], rax

loc_140002485:
cmp     dword ptr [rdi+54h], esi
ja      loc_14000260F

loc_14000248F:
lea     rcx, [rdi+0A0h]
call    qword ptr _KeReleaseSpinLockFromDpcLevel
nop     dword ptr [rax+rax*1+0h]

loc_1400024A2:
mov     rbx, qword ptr [rbp-10h]
lea     rax, [rbp-10h]
cmp     rbx, rax
je      loc_14000256A
lea     rax, [rbp-10h]
cmp     qword ptr [rbx+8h], rax
jne     loc_140002888
mov     rax, qword ptr [rbx]
cmp     qword ptr [rax+8h], rbx
jne     loc_140002888
lea     rcx, [rbp-10h]
mov     qword ptr [rbp-10h], rax
mov     qword ptr [rax+8h], rcx
mov     dl, 6h
lea     rcx, [rbx-0A8h]
call    qword ptr _IofCompleteRequest
nop     dword ptr [rax+rax*1+0h]
lea     rcx, [rdi+20h]
mov     r8d, 20h
lea     rdx, [rbx-0A8h]
call    qword ptr _IoReleaseRemoveLockEx
nop     dword ptr [rax+rax*1+0h]
jmp     loc_1400024A2

loc_140002888:
mov     ecx, 3h
int     29h

loc_14000256A:
cmp     WPP_RECORDER_INITIALIZED, r12
jne     loc_1400024BE
mov     rcx, qword ptr WPP_GLOBAL_Control
cmp     word ptr [rcx+48h], si
je      loc_1400024BE
mov     rcx, qword ptr [rcx+40h]
mov     r9d, 3Ch
mov     dl, 5h
lea     r8d, [r9-39h]
call    WPP_RECORDER_SFMeme

loc_1400024BE:
lea     r11, [rsp+70h]
mov     rbx, qword ptr [r11+30h]
mov     rsi, qword ptr [r11+38h]
mov     rdi, qword ptr [r11+40h]
mov     rsp, r11
pop     r15
pop     r14
pop     r13
pop     r12
pop     rbp
ret
KeyboardClassServiceCallbackMeme endp

end
