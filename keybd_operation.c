// Copyright (c) 2026 渟雲. All rights reserved.
// https://github.com/oakboat/GsDriver-ring3/
#include "./common.h"

KSPIN_LOCK g_KeyboardSpinLock;
KEYBOARD_OBJECT gKeyboardObject = {0};

VOID KeyboardSpinLockInit() { KeInitializeSpinLock(&g_KeyboardSpinLock); }

NTSTATUS SearchServiceFromKdbExt(PDRIVER_OBJECT KbdDriverObject,
                                 PDEVICE_OBJECT pPortDev) {
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  PDEVICE_OBJECT pTargetDeviceObject = NULL;
  UCHAR* DeviceExt = NULL;
  PVOID KbdDriverStart = NULL;
  ULONG KbdDriverSize = 0;
  PDEVICE_OBJECT pTmpDev = NULL;
  UNICODE_STRING kbdDriName = RTL_CONSTANT_STRING(L"\\Driver\\kbdclass");
  ULONG_PTR i = 0;
  ULONG_PTR DeviceExtSize = 0;
  KIRQL Irql;

  KbdDriverStart = KbdDriverObject->DriverStart;
  KbdDriverSize = KbdDriverObject->DriverSize;

  pTmpDev = pPortDev;
  while (pTmpDev->AttachedDevice != NULL) {
    if (RtlCompareUnicodeString(
            &pTmpDev->AttachedDevice->DriverObject->DriverName, &kbdDriName,
            TRUE)) {
      pTmpDev = pTmpDev->AttachedDevice;
    } else {
      break;
    }
  }

  if (pTmpDev->AttachedDevice != NULL) {
    pTargetDeviceObject = KbdDriverObject->DeviceObject;
    while (pTargetDeviceObject) {
      if (pTmpDev->AttachedDevice != pTargetDeviceObject) {
        pTargetDeviceObject = pTargetDeviceObject->NextDevice;
        continue;
      }

      DeviceExt = (UCHAR*)pTmpDev->DeviceExtension;
      DeviceExtSize = (ULONG_PTR)pTmpDev->DeviceObjectExtension -
                      (ULONG_PTR)pTmpDev->DeviceExtension;
      if (DeviceExtSize == 0 || DeviceExtSize > PAGE_SIZE) {
        DeviceExtSize = PAGE_SIZE;
      }

      KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
      gKeyboardObject.keyboard_device = NULL;
      gKeyboardObject.service_callback = NULL;
      KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);

      for (i = 0; i < DeviceExtSize; i++, DeviceExt++) {
        if (MmIsAddressValid(DeviceExt) &&
            MmIsAddressValid((PVOID*)DeviceExt)) {
          PVOID pTemp = *(PVOID*)DeviceExt;

          KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
          if (gKeyboardObject.keyboard_device &&
              gKeyboardObject.service_callback) {
            KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
            Status = STATUS_SUCCESS;
            break;
          }
          KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);

          if (pTemp == pTargetDeviceObject) {
            KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
            gKeyboardObject.keyboard_device = pTargetDeviceObject;
            KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
            continue;
          }

          if (pTemp > KbdDriverStart &&
              pTemp < (PVOID)((UCHAR*)KbdDriverStart + KbdDriverSize) &&
              MmIsAddressValid(pTemp)) {
            KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
            gKeyboardObject.service_callback = (MY_KEYBOARDCALLBACK)pTemp;
            KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
          }
        } else {
          break;
        }
      }

      if (Status == STATUS_SUCCESS) {
        break;
      }

      pTargetDeviceObject = pTargetDeviceObject->NextDevice;
    }
  }

  return Status;
}

NTSTATUS SearchKdbServiceCallBack(void) {
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  PDRIVER_OBJECT ClassObject = NULL;
  PDRIVER_OBJECT DriverObject = NULL;
  PDEVICE_OBJECT DeviceObject = NULL;
  UNICODE_STRING DeviceName[] = {RTL_CONSTANT_STRING(L"\\Driver\\kbdhid"),
                                 RTL_CONSTANT_STRING(L"\\Driver\\i8042prt")};
  size_t i = 0;
  UNICODE_STRING ClassName = RTL_CONSTANT_STRING(L"\\Driver\\kbdclass");

  for (i = 0; i < ARRAYSIZE(DeviceName); i++) {
    Status = ZwReferenceObjectByName(&DeviceName[i], OBJ_CASE_INSENSITIVE, NULL,
                                     0, *IoDriverObjectType, KernelMode, NULL,
                                     (PDRIVER_OBJECT*)&DriverObject);
    if (NT_SUCCESS(Status)) {
      break;
    }
  }

  if (DriverObject != NULL) {
    Status = ZwReferenceObjectByName(&ClassName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PDRIVER_OBJECT*)&ClassObject);
    if (NT_SUCCESS(Status)) {
      DeviceObject = DriverObject->DeviceObject;
      while (DeviceObject) {
        Status = SearchServiceFromKdbExt(ClassObject, DeviceObject);
        if (!NT_SUCCESS(Status)) {
          DeviceObject = DeviceObject->NextDevice;
        } else {
          break;
        }
      }
      ObfDereferenceObject(ClassObject);
    }
    ObfDereferenceObject(DriverObject);
  }

  return Status;
}

inline BOOL KeyboardOpen(void) {
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  KIRQL Irql;

  KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
  if (gKeyboardObject.use_keyboard && gKeyboardObject.keyboard_device &&
      gKeyboardObject.service_callback) {
    KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
    return TRUE;
  }
  KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);

  Status = SearchKdbServiceCallBack();

  KeAcquireSpinLock(&g_KeyboardSpinLock, &Irql);
  if (NT_SUCCESS(Status) && gKeyboardObject.keyboard_device &&
      gKeyboardObject.service_callback) {
    gKeyboardObject.use_keyboard = 1;
    KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
    return TRUE;
  } else {
    KeReleaseSpinLock(&g_KeyboardSpinLock, Irql);
    return FALSE;
  }
}

inline void KeyboardCall(USHORT make_code, USHORT flags, ULONG extra_info) {
  KIRQL irql;
  ULONG input_data = 0;
  KEYBOARD_INPUT_DATA kbd = {0};

  if (!KeyboardOpen()) {
    return;
  }

  kbd.UnitId = 0;
  kbd.MakeCode = make_code;
  kbd.Flags = flags;
  kbd.Reserved = 0;
  kbd.ExtraInformation = extra_info;

  RAISE_IRQL(DISPATCH_LEVEL, &irql);
  gKeyboardObject.service_callback(gKeyboardObject.keyboard_device, &kbd,
                                   &kbd + 1, &input_data);
  KeLowerIrql(irql);
}

VOID HandleKeybdEvent(Requests* request) {
  if (!request) return;

  DWORD dwFlags = request->dwFlags;
  USHORT make_code = request->bVK;
  USHORT key_flags = request->bScan;
  ULONG extra_info = (ULONG)request->dwExtraInfo;

  USHORT final_makecode = 0;
  USHORT final_flags = 0;
  ULONG final_extra = 0;

  if (dwFlags & 0x0001) final_makecode |= make_code;
  if (dwFlags & 0x0002) final_flags |= key_flags;
  if (dwFlags & 0x0004) final_extra |= extra_info;

  final_makecode = make_code;
  final_flags = key_flags;
  final_extra = extra_info;

  KeyboardCall(make_code, final_flags, extra_info);

  request->return_value = TRUE;
}
