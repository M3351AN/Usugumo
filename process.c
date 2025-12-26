// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

inline NTSTATUS KernelReadProcessMemory(PEPROCESS process, PVOID address,
                                        PEPROCESS callprocess, PVOID buffer,
                                        SIZE_T size, SIZE_T* read) {
  if (!process || !address || !buffer || !read) return STATUS_INVALID_PARAMETER;

  SIZE_T bytesCopied = 0;
  NTSTATUS status = STATUS_SUCCESS;

  status = MmCopyVirtualMemory(process,      // 源进程
                               address,      // 源地址
                               callprocess,  // 目标进程（当前进程上下文）
                               buffer,       // 目标缓冲区
                               size,         // 要复制的字节数
                               KernelMode,   // 访问模式
                               &bytesCopied  // 实际复制的字节数
  );

  *read = bytesCopied;
  return status;
}

inline NTSTATUS KernelWriteProcessMemory(PEPROCESS process, PVOID address,
                                         PEPROCESS callprocess, PVOID buffer,
                                         SIZE_T size, SIZE_T* written) {
  if (!process || !address || !buffer || !written)
    return STATUS_INVALID_PARAMETER;

  SIZE_T bytesCopied = 0;
  NTSTATUS status = STATUS_SUCCESS;

  KAPC_STATE apcState;
  ULONG oldProtect = 0;
  PVOID tempAddress = address;
  SIZE_T tempSize = size;

  KeStackAttachProcess(process, &apcState);

  __try {
    status = ZwProtectVirtualMemory(
        NtCurrentProcess(),  // 当前进程（现在是目标进程）
        &tempAddress,        // 要修改的地址
        &tempSize,           // 大小
        PAGE_READWRITE,      // 可读写
        &oldProtect          // 保存旧保护
    );

    if (!NT_SUCCESS(status)) {
      __leave;
    }

    status = MmCopyVirtualMemory(callprocess,  // 源进程（当前进程上下文）
                                 buffer,       // 源缓冲区
                                 process,      // 目标进程
                                 address,      // 目标地址
                                 size,         // 要复制的字节数
                                 KernelMode,   // 访问模式
                                 &bytesCopied  // 实际复制的字节数
    );

    if (oldProtect != PAGE_READWRITE) {
      ULONG tempProtect;
      ZwProtectVirtualMemory(NtCurrentProcess(), &tempAddress, &tempSize,
                             oldProtect, &tempProtect);
    }

  } __finally {
    KeUnstackDetachProcess(&apcState);
  }

  *written = bytesCopied;
  return status;
}

BOOLEAN ReadVM(Requests* in) {
  PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
  if (in->src_pid == 0) return FALSE;
  if (in->dst_pid == 0) return FALSE;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return FALSE;

  status =
      PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
  if (status != STATUS_SUCCESS) return FALSE;

  size_t memsize = 0;

  if (!NT_SUCCESS(KernelReadProcessMemory(source_process, (void*)in->src_addr,
                                          dist_process, (void*)in->dst_addr,
                                          in->mem_size, &memsize)))
    return FALSE;

  ObDereferenceObject(source_process);
  ObDereferenceObject(dist_process);
  return TRUE;
}

BOOLEAN WriteVM(Requests* in) {
  PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
  if (in->src_pid == 0) return FALSE;
  if (in->dst_pid == 0) return FALSE;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return FALSE;

  status =
      PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
  if (status != STATUS_SUCCESS) return FALSE;

  size_t memsize = 0;

  if (!NT_SUCCESS(KernelWriteProcessMemory(source_process, (void*)in->src_addr,
                                           dist_process, (void*)in->dst_addr,
                                           in->mem_size, &memsize)))
    return FALSE;

  ObDereferenceObject(source_process);
  ObDereferenceObject(dist_process);
  return TRUE;
}

UINT64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name,
                        BOOL get_size) {
  PPEB pPeb = (PPEB)PsGetProcessPeb(
      proc);  // get Process PEB, function is unexported and undoc

  if (!pPeb) {
    return 0;  // failed
  }

  KAPC_STATE state;

  KeStackAttachProcess(proc, &state);

  PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

  if (!pLdr) {
    KeUnstackDetachProcess(&state);
    return 0;  // failed
  }

  // loop the linked list
  for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
       list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink) {
    PLDR_DATA_TABLE_ENTRY pEntry =
        CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
        0) {
      ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
      ULONG64 moduleSize =
          (ULONG64)pEntry->SizeOfImage;  // get the size of the module
      KeUnstackDetachProcess(&state);
      if (get_size) {
        return moduleSize;  // return the size of the module if get_size is TRUE
      }
      return baseAddr;
    }
  }

  KeUnstackDetachProcess(&state);

  return 0;  // failed
}

UINT64 GetDllAddress(Requests* in) {
  PEPROCESS source_process = NULL;
  if (in->src_pid == 0) return 0;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return 0;
  UNICODE_STRING moduleName;

  char decoded[65] = {0};
  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  RtlInitUnicodeString(&moduleName, wStr);
  ULONG64 base_address = GetModuleBasex64(source_process, moduleName, FALSE);
  ExFreePoolWithTag(wStr, 'pcwT');
  ObDereferenceObject(source_process); 
  return base_address;
}

UINT64 GetDllSize(Requests* in) {
  PEPROCESS source_process = NULL;
  if (in->src_pid == 0) return 0;

  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return 0;

  UNICODE_STRING moduleName;
  char decoded[65] = {0};

  DecodeFixedStr64(&in->name_str, decoded, in->name_length);
  PWSTR wStr = ConvertToPWSTR(decoded);
  RtlInitUnicodeString(&moduleName, wStr);

  ULONG64 module_size = GetModuleBasex64(source_process, moduleName, TRUE);

  ExFreePoolWithTag(wStr, 'pcwT');
  ObDereferenceObject(source_process);

  return module_size;
}
