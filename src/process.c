// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"


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
    _ObfDereferenceObject(to_process);
    return FALSE;
  }

    if (PsGetProcessExitStatusTrick(from_process) != STATUS_PENDING) {
    _ObfDereferenceObject(from_process);
    _ObfDereferenceObject(to_process);
    return FALSE;
  }

  __try {
    status = CopyVirtualMemory(from_process, (UINT64)in->target_addr,
                               to_process, (UINT64)in->request_addr,
                               in->mem_size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;
  }

  _ObfDereferenceObject(from_process);
  _ObfDereferenceObject(to_process);
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
    _ObfDereferenceObject(from_process);
    return FALSE;
  }

  if (PsGetProcessExitStatusTrick(to_process) != STATUS_PENDING) {
    _ObfDereferenceObject(from_process);
    _ObfDereferenceObject(to_process);
    return FALSE;
  }

  __try {
    status = CopyVirtualMemory(from_process, (UINT64)in->request_addr,
                               to_process, (UINT64)in->target_addr,
                               in->mem_size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;
  }

  _ObfDereferenceObject(from_process);
  _ObfDereferenceObject(to_process);
  return NT_SUCCESS(status);
}

#define OFF_PEB_LDR            0x18  // PEB.Ldr
#define OFF_LDR_INLOAD_ORDER   0x10  // PEB_LDR_DATA.InLoadOrderModuleList(LIST_ENTRY)
#define OFF_ENTRY_INLOAD_LINKS 0x00  // LDR_DATA_TABLE_ENTRY.InLoadOrderLinks(Flink@+0x00)
#define OFF_ENTRY_DLLBASE      0x30  // LDR_DATA_TABLE_ENTRY.DllBase
#define OFF_ENTRY_SIZEIMAGE    0x40  // LDR_DATA_TABLE_ENTRY.SizeOfImage
#define OFF_ENTRY_BASENAME     0x58  // BaseDllName(UNICODE_STRING: Length@+0, Buffer@+8)

UINT64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name,
                        BOOL get_size) {
  if (!proc) return 0;
  if (KeGetCurrentIrqlMeme() > PASSIVE_LEVEL) {
    return 0;
  }
  if (module_name.Buffer == NULL || module_name.Length == 0) return 0;

  UINT64 peb_va = (UINT64)PsGetProcessPebTrick(proc);
  if (peb_va == 0) return 0;

  UINT64 result = 0;
  __try {
    UINT64 ldr_va = 0;
    if (!NT_SUCCESS(
            ReadProcessMemory(proc, peb_va + OFF_PEB_LDR, &ldr_va,
                              sizeof(ldr_va))))
      return 0;
    if (ldr_va == 0) return 0;

    UINT64 head = ldr_va + OFF_LDR_INLOAD_ORDER;
    UINT64 flink = 0;
    if (!NT_SUCCESS(ReadProcessMemory(proc, head, &flink, sizeof(flink))))
      return 0;

    for (ULONG i = 0; i < 0x1000; i++) {
      if (flink == 0 || flink == head) break;
      if (flink < 0x10000 || (flink & 0x7)) break;

      UINT64 entry_va = flink - OFF_ENTRY_INLOAD_LINKS;
      UCHAR raw[0x68];
      if (!NT_SUCCESS(ReadProcessMemory(proc, entry_va, raw, sizeof(raw))))
        break;

      UINT64 dll_base = *(UINT64*)(raw + OFF_ENTRY_DLLBASE);
      UINT64 size_of_image = *(UINT64*)(raw + OFF_ENTRY_SIZEIMAGE);
      USHORT name_len = *(USHORT*)(raw + OFF_ENTRY_BASENAME);
      UINT64 name_buf = *(UINT64*)(raw + OFF_ENTRY_BASENAME + 0x8);

      if (name_len > 0 && name_len <= 0x400 && name_buf) {
        WCHAR local_name[256];
        SIZE_T bytes =
            min((SIZE_T)name_len, sizeof(local_name) - sizeof(WCHAR));
        if (NT_SUCCESS(ReadProcessMemory(proc, name_buf, local_name, bytes))) {
          local_name[bytes / sizeof(WCHAR)] = L'\0';
          if (kwcsicmp(local_name, module_name.Buffer) == 0) {
            result = get_size ? size_of_image : dll_base;
            break;
          }
        }
      }

      UINT64 next = *(UINT64*)(raw + OFF_ENTRY_INLOAD_LINKS);
      if (next == 0 || next == flink) break;
      flink = next;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    result = 0;
  }

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

  if (PsGetProcessExitStatusTrick(source_process) != STATUS_PENDING) {
    _ObfDereferenceObject(source_process);
    return 0;
  }

  char decoded[65];
  kmemset(decoded, 0, sizeof(decoded));
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    _ObfDereferenceObject(source_process);
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
  _ObfDereferenceObject(source_process);
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

  if (PsGetProcessExitStatusTrick(source_process) != STATUS_PENDING) {
    _ObfDereferenceObject(source_process);
    return 0;
  }

  char decoded[65];
  kmemset(decoded, 0, sizeof(decoded));
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  if (!wStr) {
    _ObfDereferenceObject(source_process);
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
  _ObfDereferenceObject(source_process);
  return module_size;
}

ULONG g_ActiveProcessLinksOffset = 0;
ULONG g_UserDirectoryTableBaseOffset = 0;

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
    if (ver.dwBuildNumber >= 19041) {
      g_UserDirectoryTableBaseOffset = 0x388;
    } else if (ver.dwBuildNumber >= 18362) {
      g_UserDirectoryTableBaseOffset = 0x280;
    } else {
      g_UserDirectoryTableBaseOffset = 0x278;
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

  char targetName[65];
  kmemset(targetName, 0, sizeof(targetName));
  DecodeFixedStr64(&in->name_str, targetName, in->name_length);

  PEPROCESS startProcess = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &startProcess)))
    return 0;

  PEPROCESS currentProcess = startProcess;
  _ObfReferenceObject(currentProcess);
  UINT64 foundPid = 0;
  ULONG processCount = 0;

  while (currentProcess && processCount < 1000) {
    processCount++;
    HANDLE currentPid = PsGetProcessIdTrick(currentProcess);
    PCHAR imageName = NULL;

    __try {
      imageName = PsGetProcessImageFileNameTrick(currentProcess);
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
      nextPid = PsGetProcessIdTrick(nextProcess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      break;
    }

    PEPROCESS nextSafe = NULL;

    if (nextPid && NT_SUCCESS(PsLookupProcessByProcessId(nextPid, &nextSafe))) {
      if (nextSafe == startProcess) {
        _ObfDereferenceObject(nextSafe);
        break;
      }
      _ObfDereferenceObject(currentProcess);
      currentProcess = nextSafe;
    } else {
      break;
    }
  }

  if (currentProcess && currentProcess != startProcess)
    _ObfDereferenceObject(currentProcess);
  if (startProcess) _ObfDereferenceObject(startProcess);

  return foundPid;
}
