// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _REIMPL_H_
#define _REIMPL_H_

extern MDL_POOL g_MdlPool;

int __cdecl kstricmp(const char* Str1, const char* Str2);

int __cdecl kwcsicmp(const wchar_t* Str1, const wchar_t* Str2);

void* __cdecl kmemmove(void*, const void*, size_t);

void* __cdecl kmemset(void*, int, size_t);

NTSTATUS MdlPoolInitialize();
VOID MdlPoolRelease(PMDL);
PMDL MdlPoolAcquire(SIZE_T);
VOID MdlPoolDestroy();

NTSTATUS
DriverCopyVirtualMemory(IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
                        IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
                        IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
                        OUT PSIZE_T ReturnSize);

KIRQL KeGetCurrentIrqlMeme(void);

PIMAGE_NT_HEADERS RtlImageNtHeaderMeme(PVOID Base);

SIZE_T RtlCompareMemoryMeme(const void*, const void*, SIZE_T);

#endif
