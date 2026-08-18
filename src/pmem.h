// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _PMEM_H_
#define _PMEM_H_
#include <ntddk.h>

#define PMEM_PAGE_SIZE 0x1000ULL

NTSTATUS InitPmemPages(VOID);
VOID CleanupPmemPages(VOID);

NTSTATUS ReadPhysical(UINT64 PhysicalAddress, PVOID Buffer, SIZE_T Size,
                      PSIZE_T BytesRead);

NTSTATUS WritePhysical(UINT64 PhysicalAddress, const void* Buffer, SIZE_T Size);

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress);

UINT64 GetProcessCr3(PEPROCESS Process);

NTSTATUS ReadProcessMemory(PEPROCESS Process, UINT64 VirtualAddress,
                           PVOID Buffer, SIZE_T Size);

NTSTATUS WriteProcessMemory(PEPROCESS Process, UINT64 VirtualAddress,
                            const void* Buffer, SIZE_T Size);

NTSTATUS CopyVirtualMemory(PEPROCESS FromProcess, UINT64 FromAddress,
                           PEPROCESS ToProcess, UINT64 ToAddress,
                           SIZE_T Size);

#endif