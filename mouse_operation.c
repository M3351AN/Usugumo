// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
MOUSE_OBJECT gMouseObject = {0};

inline BOOL MouseOpen(void) {
  // https://github.com/nbqofficial/norsefire
  // https://github.com/ekknod/MouseClassServiceCallbackMeme

  if (gMouseObject.use_mouse == 0) {
    UNICODE_STRING class_string = RTL_CONSTANT_STRING(L"\\Driver\\MouClass");
    UNICODE_STRING mouse_driver_names[] = {
        RTL_CONSTANT_STRING(L"\\Driver\\MouHID"),
        RTL_CONSTANT_STRING(L"\\Driver\\i8042prt")};

    PDRIVER_OBJECT class_driver_object = NULL;
    PDRIVER_OBJECT hid_driver_object = NULL;
    PDEVICE_OBJECT hid_device_object = NULL;
    PDEVICE_OBJECT class_device_object = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    size_t driver_idx = 0;

    status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL,
                                     0, *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID*)&class_driver_object);
    if (!NT_SUCCESS(status)) {
      gMouseObject.use_mouse = 0;
      return FALSE;
    }

    for (driver_idx = 0; driver_idx < ARRAYSIZE(mouse_driver_names);
         driver_idx++) {
      status = ObReferenceObjectByName(
          &mouse_driver_names[driver_idx], OBJ_CASE_INSENSITIVE, NULL, 0,
          *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
      if (NT_SUCCESS(status)) {
        break;
      }
    }

    if (!NT_SUCCESS(status) || hid_driver_object == NULL) {
      ObfDereferenceObject(class_driver_object);
      gMouseObject.use_mouse = 0;
      return FALSE;
    }

    hid_device_object = hid_driver_object->DeviceObject;
    gMouseObject.service_callback = NULL;
    gMouseObject.mouse_device = NULL;

    while (hid_device_object && !gMouseObject.service_callback) {
      class_device_object = class_driver_object->DeviceObject;
      while (class_device_object && !gMouseObject.service_callback) {
        if (!gMouseObject.mouse_device && !class_device_object->NextDevice) {
          gMouseObject.mouse_device = class_device_object;
        }

        PULONG_PTR device_extension =
            (PULONG_PTR)hid_device_object->DeviceExtension;
        ULONG_PTR device_ext_size =
            ((ULONG_PTR)hid_device_object->DeviceObjectExtension -
             (ULONG_PTR)hid_device_object->DeviceExtension) /
            4;

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

    gMouseObject.use_mouse =
        (gMouseObject.mouse_device && gMouseObject.service_callback) ? 1 : 0;
  }

  return (gMouseObject.mouse_device != NULL) &&
         (gMouseObject.service_callback != NULL);
}

inline void MouseCall(long x, long y, unsigned short button_flags,
                      unsigned short flags) {
  KIRQL irql;
  ULONG input_data;
  MOUSE_INPUT_DATA mid = {0};
  mid.LastX = x;
  mid.LastY = y;
  mid.ButtonFlags = button_flags;
  mid.Flags = flags;
  if (!MouseOpen()) {
    return;
  }
  mid.UnitId = 1;
  RAISE_IRQL(DISPATCH_LEVEL, &irql);
  MouseClassServiceCallbackMeme(gMouseObject.mouse_device, &mid,
                            (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
  KeLowerIrql(irql);
}

VOID HandleMouseEvent(Requests* request) {
  if (!request) return;

  DWORD dwFlags = request->dwFlags;
  LONG dx = request->dx;
  LONG dy = request->dy;

  long x = 0, y = 0;
  unsigned short button_flags = 0;
  unsigned short flags = MOUSE_MOVE_RELATIVE;

  if (dwFlags & MOUSEEVENTF_MOVE) {
    x = dx;
    y = dy;

    if (dwFlags & MOUSEEVENTF_ABSOLUTE) {
      flags = MOUSE_MOVE_ABSOLUTE;

      if (dwFlags & MOUSEEVENTF_VIRTUALDESK) {
        flags |= MOUSE_VIRTUAL_DESKTOP;
      }

      x = max(0, min(65535, dx));
      y = max(0, min(65535, dy));
    }
  }

  if (dwFlags & MOUSEEVENTF_LEFTDOWN) button_flags |= 0x0001;
  if (dwFlags & MOUSEEVENTF_LEFTUP) button_flags |= 0x0002;
  if (dwFlags & MOUSEEVENTF_RIGHTDOWN) button_flags |= 0x0004;
  if (dwFlags & MOUSEEVENTF_RIGHTUP) button_flags |= 0x0008;
  if (dwFlags & MOUSEEVENTF_MIDDLEDOWN) button_flags |= 0x0010;
  if (dwFlags & MOUSEEVENTF_MIDDLEUP) button_flags |= 0x0020;
  if (dwFlags & MOUSEEVENTF_XDOWN) button_flags |= 0x0040;
  if (dwFlags & MOUSEEVENTF_XUP) button_flags |= 0x0080;

  MouseCall(x, y, button_flags, flags);

  request->return_value = TRUE;
}
