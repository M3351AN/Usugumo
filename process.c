// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

NTSTATUS MmCopyProtectVirtualMemory(PEPROCESS fromProcess, PVOID fromAddress,
                                    PEPROCESS toProcess, PVOID toAddress,
                                    SIZE_T bufferSize,
                                    KPROCESSOR_MODE previousMode,
                                    PSIZE_T bytesCopied) {
  if (!fromProcess || !fromAddress || !toProcess || !toAddress ||
      !bytesCopied || bufferSize == 0) {
    return STATUS_INVALID_PARAMETER;
  }
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return STATUS_INVALID_DEVICE_REQUEST;
  }

  NTSTATUS status = STATUS_SUCCESS;
  KAPC_STATE apcState = {0};
  ULONG oldProtect = 0;
  PVOID alignedAddress = NULL;
  SIZE_T alignedSize = 0;
  BOOLEAN protectionChanged = FALSE;
  BOOLEAN attached = FALSE;

  *bytesCopied = 0;

  if (PsGetProcessExitStatus(fromProcess) != STATUS_PENDING) {
    return STATUS_PROCESS_IS_TERMINATING;
  }

  if (PsGetProcessExitStatus(toProcess) != STATUS_PENDING) {
    return STATUS_PROCESS_IS_TERMINATING;
  }

  __try {
    ULONG_PTR start = (ULONG_PTR)toAddress;
    ULONG_PTR end = start + bufferSize;
    if (end < start) {
      status = STATUS_INVALID_PARAMETER;
      __leave;
    }

    KeStackAttachProcess(toProcess, &apcState);
    attached = TRUE;

    alignedAddress = (PVOID)(start & ~(PAGE_SIZE - 1));
    alignedSize =
        ((end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - (ULONG_PTR)alignedAddress;

    status = ZwProtectVirtualMemory(NtCurrentProcess(), &alignedAddress,
                                    &alignedSize, PAGE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status)) {
      __leave;
    }
    protectionChanged = TRUE;

    status = DriverCopyVirtualMemory(fromProcess, fromAddress, toProcess, toAddress,
                                 bufferSize, previousMode, bytesCopied);

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;
  }

  if (protectionChanged) {
    ULONG tempProtect;
    ZwProtectVirtualMemory(NtCurrentProcess(), &alignedAddress, &alignedSize,
                           oldProtect, &tempProtect);
  }

  if (attached) {
    KeUnstackDetachProcess(&apcState);
  }

  return status;
}

BOOLEAN ReadVM(Requests* in) {
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return FALSE;
  }

  PEPROCESS from_process = NULL;
  PEPROCESS to_process = NULL;
  if (in->request_pid == 0 || in->target_pid == 0) return FALSE;

  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->request_pid, &to_process);
  if (!NT_SUCCESS(status)) {
    return FALSE;
  }

  status = PsLookupProcessByProcessId((HANDLE)in->target_pid, &from_process);
  if (!NT_SUCCESS(status)) {
    ObDereferenceObject(to_process);
    return FALSE;
  }

    if (PsGetProcessExitStatus(from_process) != STATUS_PENDING) {
    ObDereferenceObject(from_process);
    ObDereferenceObject(to_process);
    return FALSE;
  }

  SIZE_T memsize = 0;
  __try {
    status = DriverCopyVirtualMemory(from_process, (void*)in->target_addr,
                                 to_process, (void*)in->request_addr,
                                 in->mem_size, KernelMode, &memsize);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;
  }

  ObDereferenceObject(from_process);
  ObDereferenceObject(to_process);
  return NT_SUCCESS(status);
}

BOOLEAN WriteVM(Requests* in) {
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return FALSE;
  }

  PEPROCESS from_process = NULL;
  PEPROCESS to_process = NULL;
  if (in->request_pid == 0 || in->target_pid == 0) return FALSE;

  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->request_pid, &from_process);
  if (!NT_SUCCESS(status)) {
    return FALSE;
  }

  status = PsLookupProcessByProcessId((HANDLE)in->target_pid, &to_process);
  if (!NT_SUCCESS(status)) {
    ObDereferenceObject(from_process);
    return FALSE;
  }

  if (PsGetProcessExitStatus(to_process) != STATUS_PENDING) {
    ObDereferenceObject(from_process);
    ObDereferenceObject(to_process);
    return FALSE;
  }

  SIZE_T memsize = 0;
  __try {
    status = MmCopyProtectVirtualMemory(from_process, (void*)in->request_addr,
                                        to_process, (void*)in->target_addr,
                                        in->mem_size, KernelMode, &memsize);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;
  }

  ObDereferenceObject(from_process);
  ObDereferenceObject(to_process);
  return NT_SUCCESS(status);
}

UINT64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name,
                        BOOL get_size) {
  if (!proc) return 0;
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return 0;
  }

  PPEB pPeb = NULL;
  KAPC_STATE state;
  KeStackAttachProcess(proc, &state);

  UINT64 result = 0;
  __try {
    pPeb = (PPEB)PsGetProcessPeb(proc);
    if (!pPeb) {
      KeUnstackDetachProcess(&state);
      return 0;
    }

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (!pLdr) {
      KeUnstackDetachProcess(&state);
      return 0;
    }

    for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
         list != &pLdr->InLoadOrderModuleList;
         list = (PLIST_ENTRY)list->Flink) {
      PLDR_DATA_TABLE_ENTRY pEntry =
          CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

      if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
          0) {
        result =
            get_size ? (UINT64)pEntry->SizeOfImage : (UINT64)pEntry->DllBase;
        break;
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    result = 0;
  }

  KeUnstackDetachProcess(&state);
  return result;
}

UINT64 GetDllAddress(Requests* in) {
  if (in->target_pid == 0) return 0;
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return 0;
  }

  PEPROCESS source_process = NULL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->target_pid, &source_process);
  if (!NT_SUCCESS(status)) return 0;

  if (PsGetProcessExitStatus(source_process) != STATUS_PENDING) {
    ObDereferenceObject(source_process);
    return 0;
  }

  char decoded[65] = {0};
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    ObDereferenceObject(source_process);
    return 0;
  }

  UNICODE_STRING moduleName;
  RtlInitUnicodeString(&moduleName, wStr);
  ULONG64 base_address = 0;

  __try {
    base_address = GetModuleBasex64(source_process, moduleName, FALSE);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    base_address = 0;
  }

  ExFreePoolWithTag(wStr, 'NtFs');
  ObDereferenceObject(source_process);
  return base_address;
}

UINT64 GetDllSize(Requests* in) {
  if (in->target_pid == 0) return 0;
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return 0;
  }

  PEPROCESS source_process = NULL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->target_pid, &source_process);
  if (!NT_SUCCESS(status)) return 0;

  if (PsGetProcessExitStatus(source_process) != STATUS_PENDING) {
    ObDereferenceObject(source_process);
    return 0;
  }

  char decoded[65] = {0};
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    ObDereferenceObject(source_process);
    return 0;
  }

  UNICODE_STRING moduleName;
  RtlInitUnicodeString(&moduleName, wStr);
  ULONG64 module_size = 0;

  __try {
    module_size = GetModuleBasex64(source_process, moduleName, TRUE);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    module_size = 0;
  }

  ExFreePoolWithTag(wStr, 'NtFs');
  ObDereferenceObject(source_process);
  return module_size;
}

ULONG g_ActiveProcessLinksOffset = 0;

BOOLEAN InitOffsetsByVersion() {
  RTL_OSVERSIONINFOW ver = {0};
  ver.dwOSVersionInfoSize = sizeof(ver);
  if (!NT_SUCCESS(RtlGetVersion(&ver))) {
    return FALSE;
  }

  if (ver.dwMajorVersion == 10 && ver.dwMinorVersion == 0) {
    if (ver.dwBuildNumber >= 26000) {
      g_ActiveProcessLinksOffset = 0x1d8;
    } else {
      g_ActiveProcessLinksOffset = 0x448;
    }
    return TRUE;
  }
  return FALSE;
}

UINT64 GetProcessIdByName(Requests* in) {
  if (!in || in->name_length == 0 || in->name_length > 64) return 0;
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return 0;
  }

  if (g_ActiveProcessLinksOffset == 0) {
    if (!InitOffsetsByVersion()) {
      return 0;
    }
  }

  char targetName[65] = {0};
  DecodeFixedStr64(&in->name_str, targetName, in->name_length);

  PEPROCESS startProcess = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &startProcess)))
    return 0;

  PEPROCESS currentProcess = startProcess;
  ObReferenceObject(currentProcess);
  UINT64 foundPid = 0;
  ULONG processCount = 0;

  while (currentProcess && processCount < 1000) {
    processCount++;
    HANDLE currentPid = PsGetProcessId(currentProcess);
    PCHAR imageName = NULL;

    __try {
      imageName = PsGetProcessImageFileName(currentProcess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      break;
    }

    if (imageName && imageName[0]) {
      if (kstricmp(targetName, imageName) == 0) {
        foundPid = (UINT64)currentPid;
        break;
      }
    }

    PLIST_ENTRY listEntry = NULL;
    __try {
      listEntry =
          (PLIST_ENTRY)((ULONG_PTR)currentProcess + g_ActiveProcessLinksOffset);
      if (!listEntry->Flink || listEntry->Flink == listEntry) break;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      break;
    }

    ULONG_PTR nextAddr =
        (ULONG_PTR)listEntry->Flink - g_ActiveProcessLinksOffset;
    PEPROCESS nextProcess = (PEPROCESS)nextAddr;
    HANDLE nextPid = NULL;

    __try {
      nextPid = PsGetProcessId(nextProcess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      break;
    }

    PEPROCESS nextSafe = NULL;

    if (nextPid && NT_SUCCESS(PsLookupProcessByProcessId(nextPid, &nextSafe))) {
      if (nextSafe == startProcess) {
        ObDereferenceObject(nextSafe);
        break;
      }
      ObDereferenceObject(currentProcess);
      currentProcess = nextSafe;
    } else {
      break;
    }
  }

  if (currentProcess && currentProcess != startProcess)
    ObDereferenceObject(currentProcess);
  if (startProcess) ObDereferenceObject(startProcess);

  return foundPid;
}
