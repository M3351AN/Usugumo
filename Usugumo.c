#include "imports.h"
#include "defines.h"
#include "Dispatches.h"
VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  if (DriverObject->DeviceObject) {
    UNICODE_STRING symbolic_link_name;
    RtlInitUnicodeString(&symbolic_link_name, L"\\DosDevices\\Usugum0");
    IoDeleteSymbolicLink(&symbolic_link_name);
    IoDeleteDevice(DriverObject->DeviceObject);
  }
}



NTSTATUS DriverInit(_In_ PDRIVER_OBJECT DriverObject,
                  _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

 UNICODE_STRING device_name, symbolic_link_name;
 PDEVICE_OBJECT device_object;

  RtlInitUnicodeString(&device_name, L"\\Device\\Usugum0");  // die lit
  NTSTATUS status =
      IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
                     FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
  if (status != STATUS_SUCCESS) return status;

  RtlInitUnicodeString(&symbolic_link_name, L"\\DosDevices\\Usugum0");
  status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
  if (status != STATUS_SUCCESS) return status;

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
  UNICODE_STRING drv_name;
  RtlInitUnicodeString(&drv_name, L"\\Driver\\Usugum0");
  return IoCreateDriver(&drv_name, DriverInit);
}


