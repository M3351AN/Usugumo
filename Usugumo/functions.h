#pragma once
#include <string>

wchar_t* convertToPCWSTR(const char* asciiStr) {
  SIZE_T len = 0;

  while (asciiStr[len] != '\0') {
    len++;
  }

  wchar_t* wStr = (wchar_t*)ExAllocatePoolWithTag(
      NonPagedPool, (len + 1) * sizeof(WCHAR), 'pcwT');
  if (!wStr) {
    return NULL;
  }

  for (SIZE_T i = 0; i < len; i++) {
    wStr[i] = (WCHAR)asciiStr[i];
  }
  wStr[len] = L'\0';

  return wStr;
}

  auto readvm(_requests* in) -> bool
{
	PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
	if (in->src_pid == 0) return STATUS_UNSUCCESSFUL;
  if (in->dst_pid == 0) return STATUS_UNSUCCESSFUL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
	if (status != STATUS_SUCCESS) return false;

	NTSTATUS status1 =
            PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
    if (status1 != STATUS_SUCCESS) return false;

	size_t memsize = 0;

	if (!NT_SUCCESS(utils::readprocessmemory(
                source_process, (void*)in->src_addr,
                dist_process,(void*) in->dst_addr, in->size, &memsize)))
		return false;

	ObDereferenceObject(source_process);

	return true;
}

auto writevm(_requests* in) -> bool
{
  PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
  if (in->src_pid == 0) return STATUS_UNSUCCESSFUL;
  if (in->dst_pid == 0) return STATUS_UNSUCCESSFUL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return false;

  NTSTATUS status1 =
      PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
  if (status1 != STATUS_SUCCESS) return false;

	size_t memsize = 0;

	if (!NT_SUCCESS(utils::writeprocessmemory(
                source_process, (void*)in->src_addr,
                dist_process,(void*) in->dst_addr, in->size, &memsize)))
		return false;

	ObDereferenceObject(source_process);

	return true;
}

ULONG64 get_dll_address(_requests* in) {
  PEPROCESS source_process = NULL;
  if (in->src_pid == 0) return 0;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return 0;
  UNICODE_STRING moduleName;
  
  char decoded[33] = {0};
  decodeFixedStr64(&in->dll_name, decoded, in->dll_name_length);
  wchar_t* wStr = convertToPCWSTR(decoded);
  RtlInitUnicodeString(&moduleName, wStr);
  ExFreePoolWithTag(wStr, 'pcwT');
  ULONG64 base_address =
      utils::GetModuleBasex64(source_process, moduleName, false);
  return base_address;
}

auto requesthandler(_requests* pstruct) -> bool {
  switch (pstruct->request_key) {
    case DLL_BASE: {
      ULONG64 base = get_dll_address(pstruct);
      pstruct->dll_base = base;
      return pstruct->dll_base;
    }
    case DRIVER_READVM: {
      return readvm(pstruct);
    }
    case DRIVER_WRITEVM: {
      return writevm(pstruct);
    }
    case HID: {
      return true;
    }
  }

  return true;
}

auto default_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) -> NTSTATUS {
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

auto ioctl_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) -> NTSTATUS {
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  auto stack = IoGetCurrentIrpStackLocation(irp);
  auto buffer = (_requests*)irp->AssociatedIrp.SystemBuffer;
  auto length = stack->Parameters.DeviceIoControl.InputBufferLength;
  auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
  if (length >= sizeof(_requests)) {
    if (ctl_code == ioctl_call_driver && requesthandler(buffer)) {
      irp->IoStatus.Information = sizeof(_requests);
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