#include "./common.h"

NTSTATUS DefaultDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
  UNREFERENCED_PARAMETER(device_obj);
  UNREFERENCED_PARAMETER(irp);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS WriteDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
  UNREFERENCED_PARAMETER(device_obj);
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  ULONG write_len = stack->Parameters.Write.Length;

  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;

  PMDL pMdl = irp->MdlAddress;
  if (pMdl == NULL) {
    irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
  }

  PRequests pRequest =
      (PRequests)MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
  if (pRequest == NULL) {
    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
  }

  if (write_len >= sizeof(Requests)) {
    if (RequestHandler(pRequest)) {
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

NTSTATUS ReadDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
  UNREFERENCED_PARAMETER(device_obj);
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  ULONG read_len = stack->Parameters.Read.Length;

  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;

  PMDL pMdl = irp->MdlAddress;
  if (pMdl == NULL) {
    irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
  }

  PRequests pRequest =
      (PRequests)MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
  if (pRequest == NULL) {
    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
  }

  if (read_len >= sizeof(Requests)) {
    irp->IoStatus.Information = sizeof(Requests);
    irp->IoStatus.Status = STATUS_SUCCESS;
  } else {
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
  }

  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
