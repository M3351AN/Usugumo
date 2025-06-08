#include "imports.h"
#include "functions.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING sym_link;
  RtlInitUnicodeString(&sym_link, L"\\DosDevices\\Usugumo");
  IoDeleteSymbolicLink(&sym_link);
  if (DriverObject->DeviceObject) {
    IoDeleteDevice(DriverObject->DeviceObject);
  }
}

//https://github.com/beans42/kernel-read-write-using-ioctl
auto real_main(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path)
    -> NTSTATUS {
  UNREFERENCED_PARAMETER(registery_path);

  UNICODE_STRING dev_name, sym_link;
  PDEVICE_OBJECT dev_obj;

  RtlInitUnicodeString(&dev_name, L"\\Device\\Usugumo");  // die lit
  NTSTATUS status =
      IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN,
                     FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
  if (status != STATUS_SUCCESS) return status;

  RtlInitUnicodeString(&sym_link, L"\\DosDevices\\Usugumo");
  status = IoCreateSymbolicLink(&sym_link, &dev_name);
  if (status != STATUS_SUCCESS) return status;

  // ���� DO_BUFFERED_IO λ
  SetFlag(dev_obj->Flags, DO_BUFFERED_IO);

  // Ϊ��Ӧ�� IRP ���������ô�����
  driver_obj->MajorFunction[IRP_MJ_CREATE] = default_dispatch;  // ��������
  driver_obj->MajorFunction[IRP_MJ_CLOSE] = default_dispatch;   // �رպ���
  driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
      ioctl_dispatch;                       // ���ƴ��뺯��
  driver_obj->DriverUnload = DriverUnload;  // ж�غ���

  // ����豸��ʼ��
  ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
  return status;
}

auto driver_entry() -> const NTSTATUS
{
	UNICODE_STRING  drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\Usugumo");
	return IoCreateDriver(&drv_name, real_main); //so it's kdmapper-able
}