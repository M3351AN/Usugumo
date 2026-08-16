// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _IMPORTS_H_
#define _IMPORTS_H_
#include <ntifs.h>
#include <wdmsec.h>

#include "./defines.h"

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

extern fn_KeAcquireSpinLockAtDpcLevel _KeAcquireSpinLockAtDpcLevel;
extern fn_KeReleaseSpinLockFromDpcLevel _KeReleaseSpinLockFromDpcLevel;
extern fn_IofCompleteRequest _IofCompleteRequest;
extern fn_IoReleaseRemoveLockEx _IoReleaseRemoveLockEx;
extern fn_IoCreateDriver _IoCreateDriver;
extern fn_ObReferenceObjectByName _ObReferenceObjectByName;

extern POBJECT_TYPE* _IoDriverObjectType;

NTSTATUS ResolveImports(VOID);

#endif
