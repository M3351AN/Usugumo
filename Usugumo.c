// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
UNICODE_STRING g_symbolic_link_name = {0};

VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  if (DriverObject->DeviceObject) {
    if (g_symbolic_link_name.Buffer != NULL) {
      IoDeleteSymbolicLink(&g_symbolic_link_name);
      ExFreePool(g_symbolic_link_name.Buffer);
    }
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

  LARGE_INTEGER perf_counter;
  KeQueryPerformanceCounter(&perf_counter);
  ULONG ramdon_seed =
      (ULONG)perf_counter.LowPart ^ (ULONG)perf_counter.HighPart;
  WCHAR random_device_name_buf[256];
  kmemset(random_device_name_buf, 0, sizeof(random_device_name_buf));
  UNICODE_STRING device_name;
  RtlStringCbPrintfW(random_device_name_buf,
             sizeof(random_device_name_buf) / sizeof(WCHAR),
                     L"\\Device\\%04X", RtlRandomEx(&ramdon_seed));
  RtlInitUnicodeString(&device_name, random_device_name_buf);

  WCHAR guid_buf[64];
  kmemset(guid_buf, 0, sizeof(guid_buf));
  NTSTATUS status = GetMachineGuid(guid_buf, ARRAYSIZE(guid_buf));
  if (status != STATUS_SUCCESS) return status;

  WCHAR sym_link_buf[256];
  kmemset(sym_link_buf, 0, sizeof(sym_link_buf));
  RtlStringCbPrintfW(sym_link_buf, sizeof(sym_link_buf),
                     L"\\DosDevices\\Global\\%sUsugum0", guid_buf);
  RtlInitUnicodeString(&g_symbolic_link_name, sym_link_buf);

  UNICODE_STRING sddl_string = RTL_CONSTANT_STRING(SDDL_STRING);

  PDEVICE_OBJECT device_object;

  status = IoCreateDeviceSecure(
      DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN, FALSE, &sddl_string, NULL, &device_object);

  if (status != STATUS_SUCCESS) return status;

  status = IoCreateSymbolicLink(&g_symbolic_link_name, &device_name);
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

NTSTATUS UsugumoEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);
  // So it's kdmapper able
  return IoCreateDriver(NULL, DriverInit);
}
