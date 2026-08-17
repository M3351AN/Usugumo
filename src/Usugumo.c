// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
#include "./random.h"
UNICODE_STRING g_symbolic_link_name = {0};

VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  MouseRelease();
  KeyboardRelease();
  if (g_symbolic_link_name.Buffer != NULL) {
    _IoDeleteSymbolicLink(&g_symbolic_link_name);
    RtlSecureZeroMemory(g_symbolic_link_name.Buffer,
                        g_symbolic_link_name.MaximumLength);
    _ExFreePoolWithTag(g_symbolic_link_name.Buffer, 0);
    g_symbolic_link_name.Buffer = NULL;
    g_symbolic_link_name.Length = 0;
    g_symbolic_link_name.MaximumLength = 0;
  }

  if (DriverObject->DeviceObject) {
    _IoDeleteDevice(DriverObject->DeviceObject);
    DriverObject->DeviceObject = NULL;
  }
}

NTSTATUS DriverInit(_In_ PDRIVER_OBJECT DriverObject,
                    _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  RandomEngineInit();

  WCHAR random_device_name_buf[256];
  kmemset(random_device_name_buf, 0, sizeof(random_device_name_buf));
  UNICODE_STRING device_name;
  RtlStringCbPrintfW(random_device_name_buf,
                     sizeof(random_device_name_buf) / sizeof(WCHAR),
                     L"\\Device\\%04X", (ULONG)RandomEngineNext());
  RtlInitUnicodeStringMeme(&device_name, random_device_name_buf);

  WCHAR guid_buf[64];
  kmemset(guid_buf, 0, sizeof(guid_buf));
  NTSTATUS status = GetMachineGuid(guid_buf, ARRAYSIZE(guid_buf));
  if (status != STATUS_SUCCESS) return status;

  WCHAR sym_link_buf[256];
  kmemset(sym_link_buf, 0, sizeof(sym_link_buf));
  RtlStringCbPrintfW(sym_link_buf, sizeof(sym_link_buf),
                     L"\\DosDevices\\Global\\%sUsugum0", guid_buf);
  RtlInitUnicodeStringMeme(&g_symbolic_link_name, sym_link_buf);

  UNICODE_STRING sddl_string = RTL_CONSTANT_STRING(SDDL_STRING);
  PDEVICE_OBJECT device_object;

  status = WdmlibIoCreateDeviceSecureMeme(
      DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN, FALSE, &sddl_string, NULL, &device_object);

  if (status != STATUS_SUCCESS) return status;

  status = _IoCreateSymbolicLink(&g_symbolic_link_name, &device_name);
  if (status != STATUS_SUCCESS) return status;

  if (!InitGreProtectSpriteContent()) {
    // NOT HANDLE. RETURN
  }

  SetFlag(device_object->Flags, DO_DIRECT_IO);
  // just in case.
  ClearFlag(device_object->Flags, DO_BUFFERED_IO);

  DriverObject->MajorFunction[IRP_MJ_CREATE] = DefaultDispatch;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DefaultDispatch;
  DriverObject->MajorFunction[IRP_MJ_READ] = ReadDispatch;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteDispatch;
  DriverObject->DriverUnload = DriverUnload;

  ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
  return status;
}

NTSTATUS UsugumoEntry(_In_ PDRIVER_OBJECT DriverObject,
                      _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS status = ResolveImports();
  if (!NT_SUCCESS(status)) return status;

#pragma warning(disable : 6387)
  // So it's kdmapper able
  return _IoCreateDriver(NULL, DriverInit);
#pragma warning(default : 6387)
}
