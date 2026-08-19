// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
#include "./random.h"
UNICODE_STRING g_symbolic_link_name = {0};

VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  CleanupPmemPages();
  MouseRelease();
  KeyboardRelease();
  if (g_symbolic_link_name.Buffer != NULL) {
    _IoDeleteSymbolicLink(&g_symbolic_link_name);
    RtlSecureZeroMemory(g_symbolic_link_name.Buffer,
                        g_symbolic_link_name.MaximumLength);
    _ExFreePoolWithTag(g_symbolic_link_name.Buffer, 0x6B4C7355);
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

  NTSTATUS status = InitPmemPages();

  if (!NT_SUCCESS(status)) return status;

  RandomEngineInit();

  WCHAR random_device_name_buf[256];
  kmemset(random_device_name_buf, 0, sizeof(random_device_name_buf));
  UNICODE_STRING device_name;
  const WCHAR device_prefix[] = L"\\Device\\";
  kmemmove(random_device_name_buf, device_prefix,
           (kwcslen(device_prefix)) * sizeof(WCHAR));
  ULONG rand_val = (ULONG)RandomEngineNext();
  for (INT n = 3; n >= 0; n--) {
    WCHAR nibble = (WCHAR)(rand_val & 0xF);
    random_device_name_buf[8 + n] =
        (nibble < 10) ? (WCHAR)(L'0' + nibble) : (WCHAR)(L'A' + (nibble - 10));
    rand_val >>= 4;
  }
  random_device_name_buf[12] = L'\0';
  RtlInitUnicodeStringMeme(&device_name, random_device_name_buf);

  WCHAR guid_buf[64];
  kmemset(guid_buf, 0, sizeof(guid_buf));
  status = GetMachineGuid(guid_buf, ARRAYSIZE(guid_buf));
  if (status != STATUS_SUCCESS) {
    DriverUnload(DriverObject);
    return status;
  }

  WCHAR sym_link_buf[256];
  kmemset(sym_link_buf, 0, sizeof(sym_link_buf));
  const WCHAR sym_prefix[] = L"\\DosDevices\\Global\\";
  const WCHAR sym_suffix[] = L"Usugum0";
  SIZE_T pre_len = kwcslen(sym_prefix);
  SIZE_T guid_len = kwcslen(guid_buf);
  SIZE_T suf_len = kwcslen(sym_suffix);
  kmemmove(sym_link_buf, sym_prefix, pre_len * sizeof(WCHAR));
  kmemmove(sym_link_buf + pre_len, guid_buf, guid_len * sizeof(WCHAR));
  kmemmove(sym_link_buf + pre_len + guid_len, sym_suffix,
           suf_len * sizeof(WCHAR));
  sym_link_buf[pre_len + guid_len + suf_len] = L'\0';
  RtlSecureZeroMemory(guid_buf, sizeof(guid_buf));

  SIZE_T sym_link_bytes = (kwcslen(sym_link_buf) + 1) * sizeof(WCHAR);
  PWSTR sym_link_pool =
      (PWSTR)_ExAllocatePool2(POOL_FLAG_NON_PAGED, sym_link_bytes, 0x6B4C7355);
  if (sym_link_pool == NULL) {
    DriverUnload(DriverObject);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  kmemmove(sym_link_pool, sym_link_buf, sym_link_bytes);
  RtlInitUnicodeStringMeme(&g_symbolic_link_name, sym_link_pool);

  UNICODE_STRING sddl_string = RTL_CONSTANT_STRING(SDDL_STRING);
  PDEVICE_OBJECT device_object;

  status = WdmlibIoCreateDeviceSecureMeme(
      DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN, FALSE, &sddl_string, NULL, &device_object);
  if (status != STATUS_SUCCESS) {
    DriverUnload(DriverObject);
    return status;
  }

  status = _IoCreateSymbolicLink(&g_symbolic_link_name, &device_name);

  if (status != STATUS_SUCCESS) {
    DriverUnload(DriverObject);
    return status;
  }

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

  NTSTATUS status = ResolveImports(/*DriverObject*/);
  if (!NT_SUCCESS(status)) return status;

#pragma warning(disable : 6387)
  // So it's kdmapper able
  return _IoCreateDriver(NULL, DriverInit);
#pragma warning(default : 6387)
}
