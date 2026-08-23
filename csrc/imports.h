// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _IMPORTS_H_
#define _IMPORTS_H_
#include <ntifs.h>
#include <wdmsec.h>

#include "./defines.h"

PVOID FindKernelProcAddress(_In_ PCCH ExportName);

NTSTATUS ResolveImports(/*_In_ struct _DRIVER_OBJECT* DriverObject*/);

typedef VOID(NTAPI* fn_KeAcquireSpinLockAtDpcLevel)(_Inout_ PKSPIN_LOCK SpinLock);
typedef VOID(NTAPI* fn_KeReleaseSpinLockFromDpcLevel)(_Inout_ PKSPIN_LOCK SpinLock,
                                                      _In_ KIRQL OldIrql);
typedef VOID(NTAPI* fn_IofCompleteRequest)(_In_ PIRP Irp,
                                           _In_ CCHAR PriorityBoost);
typedef NTSTATUS(NTAPI* fn_IoReleaseRemoveLockEx)(
    _Inout_ PIO_REMOVE_LOCK RemoveLock, _In_opt_ PVOID Tag, _In_ UCHAR NumBytes);
typedef NTSTATUS(NTAPI* fn_IoCreateDriver)(_In_opt_ PUNICODE_STRING DriverName,
                                           _In_ PDRIVER_INITIALIZE InitializationFunction);
typedef NTSTATUS(NTAPI* fn_ObReferenceObjectByName)(
    _In_ PUNICODE_STRING ObjectName, _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState, _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext, _Out_ PVOID* Object);
typedef LONG_PTR(NTAPI* fn_ObfReferenceObject)(_In_ PVOID Object);
typedef LONG_PTR(NTAPI* fn_ObfDereferenceObject)(_In_ PVOID Object);
typedef PVOID(NTAPI* fn_MmMapLockedPagesSpecifyCache)(
    _In_ PMDL MemoryDescriptorList, _In_ KPROCESSOR_MODE AccessMode,
    _In_ MEMORY_CACHING_TYPE CacheType, _In_opt_ PVOID RequestedAddress,
    _In_ ULONG Priority);
typedef BOOLEAN(NTAPI* fn_MmIsAddressValid)(_In_ PVOID VirtualAddress);
typedef PVOID(NTAPI* fn_MmAllocateContiguousMemory)(
    _In_ SIZE_T NumberOfBytes, _In_ PHYSICAL_ADDRESS HighestAcceptableAddress);
typedef VOID(NTAPI* fn_MmFreeContiguousMemory)(_In_ PVOID BaseAddress);
typedef NTSTATUS(NTAPI* fn_PsLookupProcessByProcessId)(
    _In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
typedef NTSTATUS(NTAPI* fn_IoCreateSymbolicLink)(
    _In_ PUNICODE_STRING SymbolicLinkName, _In_ PUNICODE_STRING DeviceName);
typedef NTSTATUS(NTAPI* fn_IoDeleteDevice)(_In_ PDEVICE_OBJECT DeviceObject);
typedef NTSTATUS(NTAPI* fn_IoDeleteSymbolicLink)(
    _In_ PUNICODE_STRING SymbolicLinkName);
typedef PVOID(NTAPI* fn_ExAllocatePool2)(_In_ POOL_FLAGS Flags,
                                         _In_ SIZE_T NumberOfBytes,
                                         _In_ ULONG Tag);
typedef VOID(NTAPI* fn_ExFreePoolWithTag)(_In_ PVOID P, _In_ ULONG Tag);
typedef NTSTATUS(NTAPI* fn_ZwClose)(_In_ HANDLE Handle);
typedef NTSTATUS(NTAPI* fn_ZwCreateFile)(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);
typedef NTSTATUS(NTAPI* fn_ZwDeviceIoControlFile)(
    _In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength);
typedef NTSTATUS(NTAPI* fn_ZwQueryVolumeInformationFile)(
    _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_opt_(Length) PVOID FsInformation, _In_ ULONG Length,
    _In_ FS_INFORMATION_CLASS FsInformationClass);

extern fn_KeAcquireSpinLockAtDpcLevel _KeAcquireSpinLockAtDpcLevel;
extern fn_KeReleaseSpinLockFromDpcLevel _KeReleaseSpinLockFromDpcLevel;
extern fn_IofCompleteRequest _IofCompleteRequest;
extern fn_IoReleaseRemoveLockEx _IoReleaseRemoveLockEx;
extern fn_IoCreateDriver _IoCreateDriver;
extern fn_ObReferenceObjectByName _ObReferenceObjectByName;
extern fn_ObfReferenceObject _ObfReferenceObject;
extern fn_ObfDereferenceObject _ObfDereferenceObject;
extern fn_MmMapLockedPagesSpecifyCache _MmMapLockedPagesSpecifyCache;
extern fn_MmIsAddressValid _MmIsAddressValid;
extern fn_MmAllocateContiguousMemory _MmAllocateContiguousMemory;
extern fn_MmFreeContiguousMemory _MmFreeContiguousMemory;
extern fn_PsLookupProcessByProcessId _PsLookupProcessByProcessId;
extern fn_IoCreateSymbolicLink _IoCreateSymbolicLink;
extern fn_IoDeleteDevice _IoDeleteDevice;
extern fn_IoDeleteSymbolicLink _IoDeleteSymbolicLink;
extern fn_ExAllocatePool2 _ExAllocatePool2;
extern fn_ExFreePoolWithTag _ExFreePoolWithTag;
extern fn_ZwClose _ZwClose;
extern fn_ZwCreateFile _ZwCreateFile;
extern fn_ZwDeviceIoControlFile _ZwDeviceIoControlFile;
extern fn_ZwQueryVolumeInformationFile _ZwQueryVolumeInformationFile;

extern POBJECT_TYPE* _IoDriverObjectType;
extern PLIST_ENTRY _PsLoadedModuleList;
extern USHORT _NtBuildNumber;

#endif
