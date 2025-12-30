// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  if (DriverObject->DeviceObject) {
    UNICODE_STRING symbolic_link_name =
        RTL_CONSTANT_STRING(L"\\DosDevices\\Global\\Usugum0");
    IoDeleteSymbolicLink(&symbolic_link_name);
    IoDeleteDevice(DriverObject->DeviceObject);
  }
}

NTSTATUS DriverInit(_In_ PDRIVER_OBJECT DriverObject,
                    _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);
  /* Microsoft compiler is sometimes retarded, thats why we have to do this non
   * sense */
  /* It would otherwise generate wrapper functions around, and it would cause
   * system BSOD */
  _KeAcquireSpinLockAtDpcLevel = (QWORD)KeAcquireSpinLockAtDpcLevel;
  _KeReleaseSpinLockFromDpcLevel = (QWORD)KeReleaseSpinLockFromDpcLevel;
  _IofCompleteRequest = (QWORD)IofCompleteRequest;
  _IoReleaseRemoveLockEx = (QWORD)IoReleaseRemoveLockEx;

  UNICODE_STRING device_name =
      RTL_CONSTANT_STRING(L"\\Device\\Usugum0");  // die lit
  UNICODE_STRING sddl_string = RTL_CONSTANT_STRING(SDDL_STRING);
  UNICODE_STRING symbolic_link_name =
      RTL_CONSTANT_STRING(L"\\DosDevices\\Global\\Usugum0");

  PDEVICE_OBJECT device_object;

  NTSTATUS status = IoCreateDeviceSecure(
      DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN, FALSE, &sddl_string, NULL, &device_object);
  if (status != STATUS_SUCCESS) return status;

  status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
  if (status != STATUS_SUCCESS) return status;

  KeyboardSpinLockInit();
  status = SearchKdbServiceCallBack();
  if (status != STATUS_SUCCESS) return status;

  if (!InitGreProtectSpriteContent()) {
    return STATUS_ABANDONED;
    // NOT HANDLE. CONTINUE
  }
  SetFlag(device_object->Flags, DO_BUFFERED_IO);

  DriverObject->MajorFunction[IRP_MJ_CREATE] = DefaultDispatch;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DefaultDispatch;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatch;
  DriverObject->DriverUnload = DriverUnload;

  ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
  return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);
  UNICODE_STRING drv_name = RTL_CONSTANT_STRING(L"\\Driver\\Usugum0");
  return IoCreateDriver(&drv_name, DriverInit);
}
