#include "Functions.h"

inline void DecodeFixedStr64(const FixedStr64* fs, char* output,
                             size_t origLen) {
  size_t idx = 0;
  for (size_t block = 0; block < 4; block++) {
    for (int i = 0; i < 8; i++) {
      if (idx >= origLen) {
        break;
      }
      int shift = 8 * (7 - i);
      output[idx++] = (char)((fs->blocks[block] >> shift) & 0xFF);
    }
  }
  output[origLen] = '\0';
}
inline wchar_t* ConvertToPCWSTR(const char* ascii_str) {
  SIZE_T len = 0;

  while (ascii_str[len] != '\0') {
    len++;
  }

  wchar_t* w_str = (wchar_t*)ExAllocatePoolWithTag(
      NonPagedPool, (len + 1) * sizeof(WCHAR), 'pcwT');
  if (!w_str) {
    return NULL;
  }

  for (SIZE_T i = 0; i < len; i++) {
    w_str[i] = (WCHAR)ascii_str[i];
  }
  w_str[len] = L'\0';

  return w_str;
}
inline NTSTATUS KernelReadProcessMemory(PEPROCESS process, PVOID address,
                           PEPROCESS callprocess,
                       PVOID buffer, SIZE_T size, SIZE_T* read) {
  if (!process || !address || !buffer || !read) return STATUS_INVALID_PARAMETER;

  SIZE_T bytes_copied = 0;
  NTSTATUS status =
      MmCopyVirtualMemory(process,      // 源进程
                          address,      // 源地址
                          callprocess,  // 目标进程（当前进程上下文）
                          buffer,       // 目标缓冲区
                          size,         // 要复制的字节数
                          KernelMode,   // 访问模式
                          &bytes_copied  // 实际复制的字节数
      );

  *read = bytes_copied;
  return status;
}
inline NTSTATUS KernelWriteProcessMemory(PEPROCESS process, PVOID address,
                            PEPROCESS callprocess,
                        PVOID buffer, SIZE_T size, SIZE_T* written) {
  if (!process || !address || !buffer || !written)
    return STATUS_INVALID_PARAMETER;

  SIZE_T bytesCopied = 0;
  NTSTATUS status =
      MmCopyVirtualMemory(callprocess,  // 源进程（当前进程上下文）
                          buffer,       // 源缓冲区
                          process,      // 目标进程
                          address,      // 目标地址
                          size,         // 要复制的字节数
                          KernelMode,   // 访问模式
                          &bytesCopied  // 实际复制的字节数
      );

  *written = bytesCopied;
  return status;
}
BOOL ReadVM(Requests* in) {
  PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
  if (in->src_pid == 0) return STATUS_UNSUCCESSFUL;
  if (in->dst_pid == 0) return STATUS_UNSUCCESSFUL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return FALSE;

  NTSTATUS status1 =
      PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
  if (status1 != STATUS_SUCCESS) return FALSE;

  size_t memsize = 0;

  if (!NT_SUCCESS(KernelReadProcessMemory(source_process, (void*)in->src_addr,
                                           dist_process, (void*)in->dst_addr,
                                           in->size, &memsize)))
    return FALSE;

  ObDereferenceObject(source_process);

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
BOOL WriteVM(Requests* in){
  PEPROCESS source_process = NULL;
  PEPROCESS dist_process = NULL;
  if (in->src_pid == 0) return STATUS_UNSUCCESSFUL;
  if (in->dst_pid == 0) return STATUS_UNSUCCESSFUL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return FALSE;

  NTSTATUS status1 =
      PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dist_process);
  if (status1 != STATUS_SUCCESS) return FALSE;

  size_t memsize = 0;

  if (!NT_SUCCESS(KernelWriteProcessMemory(source_process, (void*)in->src_addr,
                                            dist_process, (void*)in->dst_addr,
                                            in->size, &memsize)))
    return FALSE;

  ObDereferenceObject(source_process);

  return TRUE;
}
UINT64 GetDllAddress(Requests* in) {
  PEPROCESS source_process = NULL;
  if (in->src_pid == 0) return 0;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
  if (status != STATUS_SUCCESS) return 0;
  UNICODE_STRING moduleName;

  char decoded[33] = {0};
  DecodeFixedStr64(&in->dll_name, decoded, in->dll_name_length);
  wchar_t* wStr = ConvertToPCWSTR(decoded);
  RtlInitUnicodeString(&moduleName, wStr);
  ExFreePoolWithTag(wStr, 'pcwT');
  ULONG64 base_address =
      GetModuleBasex64(source_process, moduleName, FALSE);
  return base_address;
}

BOOL RequestHandler(Requests* pstruct) {
  switch (pstruct->request_key) {
    case DLL_BASE: {
      ULONG64 base = GetDllAddress(pstruct);
      pstruct->dll_base = base;
      return pstruct->dll_base != 0;
    }
    case DRIVER_READVM: {
      return ReadVM(pstruct);
    }
    case DRIVER_WRITEVM: {
      return WriteVM(pstruct);
    }
    case HID: {
      return TRUE;
    }
  }

  return TRUE;
}