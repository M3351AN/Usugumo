// Copyright (c) 2026 渟雲. All rights reserved.
#include "./imports.h"

fn_KeAcquireSpinLockAtDpcLevel _KeAcquireSpinLockAtDpcLevel;
fn_KeReleaseSpinLockFromDpcLevel _KeReleaseSpinLockFromDpcLevel;
fn_IofCompleteRequest _IofCompleteRequest;
fn_IoReleaseRemoveLockEx _IoReleaseRemoveLockEx;
fn_IoCreateDriver _IoCreateDriver;
fn_ObReferenceObjectByName _ObReferenceObjectByName;
fn_ObfDereferenceObject _ObfDereferenceObject;
fn_MmMapLockedPagesSpecifyCache _MmMapLockedPagesSpecifyCache;
fn_MmIsAddressValid _MmIsAddressValid;
fn_MmMapIoSpace _MmMapIoSpace;
fn_MmUnmapIoSpace _MmUnmapIoSpace;
fn_MmCopyMemory _MmCopyMemory;
POBJECT_TYPE* _IoDriverObjectType;

NTSTATUS ResolveImports(VOID) {
  static UNICODE_STRING func_names[] = {
      RTL_CONSTANT_STRING(L"KeAcquireSpinLockAtDpcLevel"),
      RTL_CONSTANT_STRING(L"KeReleaseSpinLockFromDpcLevel"),
      RTL_CONSTANT_STRING(L"IofCompleteRequest"),
      RTL_CONSTANT_STRING(L"IoReleaseRemoveLockEx"),
      RTL_CONSTANT_STRING(L"IoCreateDriver"),
      RTL_CONSTANT_STRING(L"ObReferenceObjectByName"),
      RTL_CONSTANT_STRING(L"ObfDereferenceObject"),
      RTL_CONSTANT_STRING(L"MmMapLockedPagesSpecifyCache"),
      RTL_CONSTANT_STRING(L"MmIsAddressValid"),
      RTL_CONSTANT_STRING(L"MmMapIoSpace"),
      RTL_CONSTANT_STRING(L"MmUnmapIoSpace"),
      RTL_CONSTANT_STRING(L"MmCopyMemory"),
  };
  PVOID* func_slots[] = {
      (PVOID*)&_KeAcquireSpinLockAtDpcLevel,
      (PVOID*)&_KeReleaseSpinLockFromDpcLevel,
      (PVOID*)&_IofCompleteRequest,
      (PVOID*)&_IoReleaseRemoveLockEx,
      (PVOID*)&_IoCreateDriver,
      (PVOID*)&_ObReferenceObjectByName,
      (PVOID*)&_ObfDereferenceObject,
      (PVOID*)&_MmMapLockedPagesSpecifyCache,
      (PVOID*)&_MmIsAddressValid,
      (PVOID*)&_MmMapIoSpace,
      (PVOID*)&_MmUnmapIoSpace,
      (PVOID*)&_MmCopyMemory,
  };

  for (ULONG i = 0; i < RTL_NUMBER_OF(func_names); i++) {
    PVOID address = MmGetSystemRoutineAddress((PUNICODE_STRING)&func_names[i]);
    if (address == NULL) {
      return STATUS_NOT_FOUND;
    }
    *func_slots[i] = address;
  }

  UNICODE_STRING data_name = RTL_CONSTANT_STRING(L"IoDriverObjectType");
  PVOID data_address = MmGetSystemRoutineAddress(&data_name);
  if (data_address == NULL) {
    return STATUS_NOT_FOUND;
  }
  _IoDriverObjectType = *(POBJECT_TYPE**)data_address;

  return STATUS_SUCCESS;
}
