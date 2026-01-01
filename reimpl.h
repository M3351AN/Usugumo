// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _REIMPL_H_
#define _REIMPL_H_

int __cdecl kstricmp(const char* Str1, const char* Str2);

int __cdecl kwcsicmp(const wchar_t* Str1, const wchar_t* Str2);

void* __cdecl kmemmove(void* dst, const void* src, size_t count);

NTSTATUS
DriverCopyVirtualMemory(IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
                        IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
                        IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
                        OUT PSIZE_T ReturnSize);

KIRQL KeGetCurrentIrqlMeme(void);

PIMAGE_NT_HEADERS RtlImageNtHeaderMeme(PVOID Base);

#endif
