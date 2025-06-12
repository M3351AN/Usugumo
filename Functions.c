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

MOUSE_OBJECT gMouseObject;
QWORD _KeAcquireSpinLockAtDpcLevel;
QWORD _KeReleaseSpinLockFromDpcLevel;
QWORD _IofCompleteRequest;
QWORD _IoReleaseRemoveLockEx;

inline BOOL MouseOpen(void) {
  // https://github.com/nbqofficial/norsefire
  // https://github.com/ekknod/MouseClassServiceCallbackMeme

  /* Microsoft compiler is sometimes retarded, thats why we have to do this non
   * sense */
  /* It would otherwise generate wrapper functions around, and it would cause
   * system BSOD */
  _KeAcquireSpinLockAtDpcLevel = (QWORD)KeAcquireSpinLockAtDpcLevel;
  _KeReleaseSpinLockFromDpcLevel = (QWORD)KeReleaseSpinLockFromDpcLevel;
  _IofCompleteRequest = (QWORD)IofCompleteRequest;
  _IoReleaseRemoveLockEx = (QWORD)IoReleaseRemoveLockEx;

  if (gMouseObject.use_mouse == 0) {
    UNICODE_STRING class_string;
    RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");

    PDRIVER_OBJECT class_driver_object = NULL;
    NTSTATUS status = ObReferenceObjectByName(
        &class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,
        KernelMode, NULL, (PVOID*)&class_driver_object);
    if (!NT_SUCCESS(status)) {
      gMouseObject.use_mouse = 0;
      return 0;
    }

    UNICODE_STRING hid_string;
    RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");

    PDRIVER_OBJECT hid_driver_object = NULL;

    status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID*)&hid_driver_object);
    if (!NT_SUCCESS(status)) {
      if (class_driver_object) {
        ObfDereferenceObject(class_driver_object);
      }
      gMouseObject.use_mouse = 0;
      return 0;
    }

    PVOID class_driver_base = NULL;

    PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
    while (hid_device_object && !gMouseObject.service_callback) {
      PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
      while (class_device_object && !gMouseObject.service_callback) {
        if (!class_device_object->NextDevice && !gMouseObject.mouse_device) {
          gMouseObject.mouse_device = class_device_object;
        }

        PULONG_PTR device_extension =
            (PULONG_PTR)hid_device_object->DeviceExtension;
        ULONG_PTR device_ext_size =
            ((ULONG_PTR)hid_device_object->DeviceObjectExtension -
             (ULONG_PTR)hid_device_object->DeviceExtension) /
            4;
        class_driver_base = class_driver_object->DriverStart;
        for (ULONG_PTR i = 0; i < device_ext_size; i++) {
          if (device_extension[i] == (ULONG_PTR)class_device_object &&
              device_extension[i + 1] > (ULONG_PTR)class_driver_object) {
            gMouseObject.service_callback =
                (MouseClassServiceCallbackFn)(device_extension[i + 1]);

            break;
          }
        }
        class_device_object = class_device_object->NextDevice;
      }
      hid_device_object = hid_device_object->AttachedDevice;
    }

    if (!gMouseObject.mouse_device) {
      PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
      while (target_device_object) {
        if (!target_device_object->NextDevice) {
          gMouseObject.mouse_device = target_device_object;
          break;
        }
        target_device_object = target_device_object->NextDevice;
      }
    }

    ObfDereferenceObject(class_driver_object);
    ObfDereferenceObject(hid_driver_object);

    if (gMouseObject.mouse_device && gMouseObject.service_callback) {
      gMouseObject.use_mouse = 1;
    }
  }

  return gMouseObject.mouse_device && gMouseObject.service_callback;
}

inline void MouseMove(long x, long y, unsigned short button_flags) {
  KIRQL irql;
  ULONG input_data;
  MOUSE_INPUT_DATA mid = {0};
  mid.LastX = x;
  mid.LastY = y;
  mid.ButtonFlags = button_flags;
  if (!MouseOpen()) {
    return;
  }
  mid.UnitId = 1;
  RAISE_IRQL(DISPATCH_LEVEL, &irql);
  MouseClassServiceCallback(gMouseObject.mouse_device, &mid,
                            (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
  KeLowerIrql(irql);
}

void KernelMouseEvent(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData,
                        ULONG_PTR dwExtraInfo) {
  UNREFERENCED_PARAMETER(dwFlags);
  UNREFERENCED_PARAMETER(dx);
  UNREFERENCED_PARAMETER(dy);
  UNREFERENCED_PARAMETER(dwData);
  UNREFERENCED_PARAMETER(dwExtraInfo);

  long x = 0, y = 0;
  unsigned short button_flags = 0;

  if (dwFlags & MOUSEEVENTF_MOVE) {
     /* we cant fetch screen resolution from kernel
    if (dwFlags & MOUSEEVENTF_ABSOLUTE) {
      x = (long)dx;
      y = (long)dy;
    }
    else */{
      x = (long)(short)LOWORD(dx);
      y = (long)(short)LOWORD(dy);
    }
  }

  if (dwFlags & MOUSEEVENTF_LEFTDOWN)
    button_flags |= 0x0001;  // MOUSE_LEFT_BUTTON_DOWN
  if (dwFlags & MOUSEEVENTF_LEFTUP)
    button_flags |= 0x0002;  // MOUSE_LEFT_BUTTON_UP
  if (dwFlags & MOUSEEVENTF_RIGHTDOWN)
    button_flags |= 0x0004;  // MOUSE_RIGHT_BUTTON_DOWN
  if (dwFlags & MOUSEEVENTF_RIGHTUP)
    button_flags |= 0x0008;  // MOUSE_RIGHT_BUTTON_UP
  if (dwFlags & MOUSEEVENTF_MIDDLEDOWN)
    button_flags |= 0x0010;  // MOUSE_MIDDLE_BUTTON_DOWN
  if (dwFlags & MOUSEEVENTF_MIDDLEUP)
    button_flags |= 0x0020;  // MOUSE_MIDDLE_BUTTON_UP

  MouseMove(x, y, button_flags);
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
      KernelMouseEvent(pstruct->dwFlags, pstruct->dx, pstruct->dy,
                       pstruct->dwData, pstruct->dwExtraInfo);
      return TRUE;
    }
  }

  return TRUE;
}