// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _REIMPL_H_
#define _REIMPL_H_

int __cdecl kstricmp(const char* Str1, const char* Str2);

int __cdecl kwcsicmp(const wchar_t* Str1, const wchar_t* Str2);

size_t __cdecl kwcslen(const wchar_t* Str);

void* __cdecl kmemmove(void*, const void*, size_t);

void* __cdecl kmemset(void*, int, size_t);

KIRQL KeGetCurrentIrqlMeme(void);

KIRQL __stdcall KzRaiseIrqlMeme(KIRQL NewIrql);

void __stdcall KzLowerIrqlMeme(KIRQL NewIrql);

PIMAGE_NT_HEADERS RtlImageNtHeaderMeme(PVOID Base);

SIZE_T RtlCompareMemoryMeme(const void*, const void*, SIZE_T);

void __stdcall RtlInitUnicodeStringMeme(PUNICODE_STRING, PCWSTR);

PPEB PsGetProcessPebTrick(PEPROCESS);

PCHAR PsGetProcessImageFileNameTrick(PEPROCESS);

HANDLE PsGetProcessIdTrick(PEPROCESS);

NTSTATUS PsGetProcessExitStatusTrick(PEPROCESS);

NTSTATUS
WdmlibIoCreateDeviceSecureMeme(DRIVER_OBJECT*, unsigned int, UNICODE_STRING*,
                               unsigned int, unsigned int, unsigned __int8,
                               const UNICODE_STRING*, const GUID*,
                               DEVICE_OBJECT**);

#endif
