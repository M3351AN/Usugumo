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

  NTSTATUS status = STATUS_SUCCESS;
  KAPC_STATE apcState = {0};
  ULONG oldProtect = 0;
  PVOID alignedAddress = NULL;
  SIZE_T alignedSize = 0;
  BOOLEAN protectionChanged = FALSE;

  if (PsGetProcessExitStatus(fromProcess) != STATUS_PENDING) {
    return STATUS_PROCESS_IS_TERMINATING;
  }

  if (PsGetProcessExitStatus(toProcess) != STATUS_PENDING) {
    return STATUS_PROCESS_IS_TERMINATING;
  }

  KeStackAttachProcess(toProcess, &apcState);

  alignedAddress = (PVOID)((ULONG_PTR)toAddress & ~(PAGE_SIZE - 1));
  alignedSize =
      ((ULONG_PTR)toAddress + bufferSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  alignedSize = alignedSize - (ULONG_PTR)alignedAddress;

  status = ZwProtectVirtualMemory(ZwCurrentProcess(), &alignedAddress,
                                  &alignedSize, PAGE_READWRITE, &oldProtect);

  if (NT_SUCCESS(status)) {
    protectionChanged = TRUE;
  }

  status = MmCopyVirtualMemory(fromProcess, fromAddress, toProcess, toAddress,
                               bufferSize, previousMode, bytesCopied);

  if (protectionChanged) {
    ULONG tempProtect;
    ZwProtectVirtualMemory(ZwCurrentProcess(), &alignedAddress, &alignedSize,
                           oldProtect, &tempProtect);
  }

  KeUnstackDetachProcess(&apcState);
  return status;
}

BOOLEAN ReadVM(Requests* in) {
  PEPROCESS from_process = NULL;
  PEPROCESS to_process = NULL;
  if (in->request_pid == 0 || in->target_pid == 0) return FALSE;

  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->request_pid, &to_process);
  if (!NT_SUCCESS(status)) {
    if (to_process) ObDereferenceObject(to_process);
    return FALSE;
  }

  status = PsLookupProcessByProcessId((HANDLE)in->target_pid, &from_process);
  if (!NT_SUCCESS(status)) {
    ObDereferenceObject(to_process);
    if (from_process) ObDereferenceObject(from_process);
    return FALSE;
  }

  SIZE_T memsize = 0;
  status =
      MmCopyVirtualMemory(from_process, (void*)in->target_addr, to_process,
                               (void*)in->request_addr, in->mem_size,
                               KernelMode, &memsize);

  ObDereferenceObject(from_process);
  ObDereferenceObject(to_process);
  return NT_SUCCESS(status);
}

BOOLEAN WriteVM(Requests* in) {
  PEPROCESS from_process = NULL;
  PEPROCESS to_process = NULL;
  if (in->request_pid == 0 || in->target_pid == 0) return FALSE;

  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->request_pid, &from_process);
  if (!NT_SUCCESS(status)) {
    if (from_process) ObDereferenceObject(from_process);
    return FALSE;
  }

  status = PsLookupProcessByProcessId((HANDLE)in->target_pid, &to_process);
  if (!NT_SUCCESS(status)) {
    ObDereferenceObject(from_process);
    if (to_process) ObDereferenceObject(to_process);
    return FALSE;
  }

  SIZE_T memsize = 0;
  status = MmCopyProtectVirtualMemory(from_process, (void*)in->request_addr, to_process,
                               (void*)in->target_addr, in->mem_size,
                               KernelMode, &memsize);

  ObDereferenceObject(from_process);
  ObDereferenceObject(to_process);
  return NT_SUCCESS(status);
}

UINT64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name,
                        BOOL get_size) {
  PPEB pPeb = (PPEB)PsGetProcessPeb(proc);
  if (!pPeb) return 0;

  KAPC_STATE state;
  KeStackAttachProcess(proc, &state);

  PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
  if (!pLdr) {
    KeUnstackDetachProcess(&state);
    return 0;
  }

  for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
       list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink) {
    PLDR_DATA_TABLE_ENTRY pEntry =
        CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
        0) {
      UINT64 result =
          get_size ? (UINT64)pEntry->SizeOfImage : (UINT64)pEntry->DllBase;
      KeUnstackDetachProcess(&state);
      return result;
    }
  }

  KeUnstackDetachProcess(&state);
  return 0;
}

UINT64 GetDllAddress(Requests* in) {
  if (in->target_pid == 0) return 0;

  PEPROCESS source_process = NULL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->target_pid, &source_process);
  if (!NT_SUCCESS(status)) return 0;

  char decoded[65] = {0};
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    ObDereferenceObject(source_process);
    return 0;
  }

  UNICODE_STRING moduleName;
  RtlInitUnicodeString(&moduleName, wStr);
  ULONG64 base_address = GetModuleBasex64(source_process, moduleName, FALSE);

  ExFreePoolWithTag(wStr, 'pcwT');
  ObDereferenceObject(source_process);
  return base_address;
}

UINT64 GetDllSize(Requests* in) {
  if (in->target_pid == 0) return 0;

  PEPROCESS source_process = NULL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->target_pid, &source_process);
  if (!NT_SUCCESS(status)) return 0;

  char decoded[65] = {0};
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    ObDereferenceObject(source_process);
    return 0;
  }

  UNICODE_STRING moduleName;
  RtlInitUnicodeString(&moduleName, wStr);
  ULONG64 module_size = GetModuleBasex64(source_process, moduleName, TRUE);

  ExFreePoolWithTag(wStr, 'pcwT');
  ObDereferenceObject(source_process);
  return module_size;
}

UINT64 GetProcessIdByName(Requests* in) {
  if (!in || in->name_length == 0 || in->name_length > 64) return 0;

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

    PCHAR imageName = PsGetProcessImageFileName(currentProcess);
    if (imageName && imageName[0]) {
      BOOLEAN match = TRUE;
      SIZE_T i = 0;

      while (targetName[i] != '\0') {
        char c1 = targetName[i];
        char c2 = imageName[i];

        if (c2 == '\0') {
          match = FALSE;
          break;
        }

        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

        if (c1 != c2) {
          match = FALSE;
          break;
        }
        i++;
      }

      if (match && imageName[i] == '\0') {
        foundPid = (UINT64)currentPid;
        break;
      }
    }

    PLIST_ENTRY listEntry =
        (PLIST_ENTRY)((ULONG_PTR)currentProcess + ACTIVE_PROCESS_LINKS_OFFSET);
    if (!listEntry->Flink || listEntry->Flink == listEntry) break;

    ULONG_PTR nextAddr =
        (ULONG_PTR)listEntry->Flink - ACTIVE_PROCESS_LINKS_OFFSET;
    PEPROCESS nextProcess = (PEPROCESS)nextAddr;

    HANDLE nextPid = PsGetProcessId(nextProcess);
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
