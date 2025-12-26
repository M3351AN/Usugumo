// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _IMPORTS_H_
#define _IMPORTS_H_
#include <ntifs.h>
#include <wdmsec.h>

#include "./defines.h"

NTKERNELAPI NTSTATUS
IoCreateDriver(_In_ PUNICODE_STRING DriverName,
               _In_ PDRIVER_INITIALIZE InitializationFunction);

__declspec(dllimport) NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess, IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);

__declspec(dllimport) PPEB PsGetProcessPeb(PEPROCESS);

NTSYSCALLAPI
POBJECT_TYPE* IoDriverObjectType;

NTSYSCALLAPI
NTSTATUS
ObReferenceObjectByName(__in PUNICODE_STRING ObjectName, __in ULONG Attributes,
                        __in_opt PACCESS_STATE AccessState,
                        __in_opt ACCESS_MASK DesiredAccess,
                        __in POBJECT_TYPE ObjectType,
                        __in KPROCESSOR_MODE AccessMode,
                        __inout_opt PVOID ParseContext, __out PVOID* Object);
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress,
                       IN OUT PSIZE_T RegionSize, IN ULONG NewProtect,
                       OUT PULONG OldProtect);

NTSYSAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);

VOID MouseClassServiceCallback(PDEVICE_OBJECT DeviceObject,
                               PMOUSE_INPUT_DATA InputDataStart,
                               PMOUSE_INPUT_DATA InputDataEnd,
                               PULONG InputDataConsumed);
#endif
