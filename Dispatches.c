#include "Dispatches.h"
#include "Functions.h"
#include "defines.h"
NTSTATUS DefaultDispatch(PDEVICE_OBJECT device_obj, PIRP irp){
  UNREFERENCED_PARAMETER(device_obj);
  UNREFERENCED_PARAMETER(irp);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS IoctlDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
  UNREFERENCED_PARAMETER(device_obj);
  UNREFERENCED_PARAMETER(irp);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  PVOID buffer = (Requests*)irp->AssociatedIrp.SystemBuffer;
  ULONG length = stack->Parameters.DeviceIoControl.InputBufferLength;
  ULONG ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
  if (length >= sizeof(Requests)) {
    if (ctl_code == kIoctlCallDriver && RequestHandler(buffer)) {
      irp->IoStatus.Information = sizeof(Requests);
      irp->IoStatus.Status = STATUS_SUCCESS;
    } else {
      irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    }
  } else {
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}