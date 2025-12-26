// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
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
   else */
    {
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
