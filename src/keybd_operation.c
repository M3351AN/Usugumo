// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
KEYBOARD_OBJECT gKeyboardObject = {0};

inline BOOL KeyboardOpen(void) {

  if (gKeyboardObject.use_keyboard == 0) {
    UNICODE_STRING class_string = RTL_CONSTANT_STRING(L"\\Driver\\kbdclass");
    UNICODE_STRING keyboard_driver_names[] = {
        RTL_CONSTANT_STRING(L"\\Driver\\kbdhid"),
        RTL_CONSTANT_STRING(L"\\Driver\\i8042prt")};
    
    PDRIVER_OBJECT class_driver_object = NULL;
    PDRIVER_OBJECT hid_driver_object = NULL;
    PDEVICE_OBJECT hid_device_object = NULL;
    PDEVICE_OBJECT class_device_object = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    size_t driver_idx = 0;

    status = _ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL,
                                      0, *_IoDriverObjectType, KernelMode, NULL,
                                      (PVOID*)&class_driver_object);
    if (!NT_SUCCESS(status)) {
      gKeyboardObject.use_keyboard = 0;
      return FALSE;
    }

    for (driver_idx = 0; driver_idx < ARRAYSIZE(keyboard_driver_names);
         driver_idx++) {
      status = _ObReferenceObjectByName(
          &keyboard_driver_names[driver_idx], OBJ_CASE_INSENSITIVE, NULL, 0,
          *_IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
      if (NT_SUCCESS(status)) {
        break;
      }
    }
    if (!NT_SUCCESS(status) || hid_driver_object == NULL) {
      _ObfDereferenceObject(class_driver_object);
      gKeyboardObject.use_keyboard = 0;
      return FALSE;
    }

    PDEVICE_OBJECT port_device_object = hid_driver_object->DeviceObject;
    gKeyboardObject.service_callback = NULL;
    gKeyboardObject.keyboard_device = NULL;

    while (port_device_object && !gKeyboardObject.service_callback) {
      hid_device_object = port_device_object;
      while (hid_device_object && !gKeyboardObject.service_callback) {
        class_device_object = class_driver_object->DeviceObject;
        while (class_device_object && !gKeyboardObject.service_callback) {
          if (!gKeyboardObject.keyboard_device &&
              !class_device_object->NextDevice) {
            gKeyboardObject.keyboard_device = class_device_object;
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
              gKeyboardObject.service_callback =
                  (KeyboardClassServiceCallbackFn)(device_extension[i + 1]);
              gKeyboardObject.keyboard_device = class_device_object;
              break;
            }
          }
          class_device_object = class_device_object->NextDevice;
        }
        hid_device_object = hid_device_object->AttachedDevice;
      }
      port_device_object = port_device_object->NextDevice;
    }

    if (!gKeyboardObject.keyboard_device) {
      PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
      while (target_device_object) {
        if (!target_device_object->NextDevice) {
          gKeyboardObject.keyboard_device = target_device_object;
          break;
        }
        target_device_object = target_device_object->NextDevice;
      }
    }

    gKeyboardObject.class_driver_object = class_driver_object;
    gKeyboardObject.hid_driver_object = hid_driver_object;

    gKeyboardObject.use_keyboard =
        (gKeyboardObject.keyboard_device && gKeyboardObject.service_callback)
            ? 1
            : 0;
  }

  return (gKeyboardObject.keyboard_device != NULL) &&
         (gKeyboardObject.service_callback != NULL);
}

VOID KeyboardRelease(void) {
  if (gKeyboardObject.class_driver_object) {
    _ObfDereferenceObject(gKeyboardObject.class_driver_object);
    gKeyboardObject.class_driver_object = NULL;
  }
  if (gKeyboardObject.hid_driver_object) {
    _ObfDereferenceObject(gKeyboardObject.hid_driver_object);
    gKeyboardObject.hid_driver_object = NULL;
  }
  gKeyboardObject.use_keyboard = 0;
  RtlSecureZeroMemory(&gKeyboardObject, sizeof(gKeyboardObject));
}

inline void KeyboardCall(USHORT make_code, USHORT flags, ULONG extra_info) {
  KIRQL irql;
  ULONG input_data;
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
  KeyboardClassServiceCallbackMeme(gKeyboardObject.keyboard_device, &kbd,
                                   (PKEYBOARD_INPUT_DATA)&kbd + 1, &input_data);
  KzLowerIrqlMeme(irql);
}

static const UCHAR kScanTable[256] = {
    // 0x00-0x0F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0E, 0x0F, 0x00, 0x00, 0x4C, 0x1C, 0x00, 0x00,
    // 0x10-0x1F  Shift Ctrl Alt Pause Caps Esc
    0x2A, 0x1D, 0x38, 0x00, 0x3A, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // 0x20-0x2F  Space PgUp PgDn End Home Left Up Right Down PrtSc Ins Del
    0x39, 0x49 | 0x80, 0x51 | 0x80, 0x4F | 0x80, 0x47 | 0x80,
    0x4B | 0x80, 0x48 | 0x80, 0x4D | 0x80, 0x50 | 0x80,
    0x00, 0x00, 0x00, 0x37 | 0x80, 0x52 | 0x80, 0x53 | 0x80,
    // 0x30-0x3F  0 1 2 3 4 5 6 7 8 9
    0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x40-0x4F  A B C D E F G H I J K L M N O
    0x00, 0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22,
    0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
    // 0x50-0x5F  P Q R S T U V W X Y Z LWin RWin Apps Sleep
    0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11,
    0x2D, 0x15, 0x2C, 0x5B | 0x80, 0x5C | 0x80, 0x5D | 0x80,
    0x00, 0x5F | 0x80,
    // 0x60-0x6F  Numpad 0-9 * + Sep - . /
    0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47,
    0x48, 0x49, 0x37, 0x4E, 0x4C, 0x4A, 0x53, 0x35 | 0x80,
    // 0x70-0x7F  F1-F16
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42,
    0x43, 0x44, 0x57, 0x58, 0x64, 0x65, 0x66, 0x67,
    // 0x80-0x8F  F17-F24
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x76,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x90-0x9F  NumLock Scroll
    0x45, 0x46, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xA0-0xAF  LShift RShift LCtrl RCtrl LAlt RAlt
    0x2A, 0x36, 0x1D, 0x1D | 0x80, 0x38, 0x38 | 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    // 0xB0-0xBF  OEM ; = , - . /
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x27, 0x0D, 0x33, 0x0C, 0x34, 0x35,
    // 0xC0-0xCF  OEM `
    0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xD0-0xDF  OEM [ \ ] '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x1A, 0x2B, 0x1B, 0x28, 0x00,
    // 0xE0-0xEF
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xF0-0xFF
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static USHORT VkToScanCode(USHORT vk) {
  if (vk > 0xFF) {
    return 0;
  }
  return kScanTable[vk];
}

VOID HandleKeybdEvent(Requests* request) {
  if (!request) return;
  if (!VerifySecureKey(request->secure_key)) {
    request->return_value = FALSE;
    return;
  }
  DWORD dwFlags = request->dwFlags;
  ULONG extra_info = (ULONG)request->dwExtraInfo;

  // KEYEVENTF_UNICODE (0x0004): type a Unicode character.
  // NOTE: untested.
  if (dwFlags & KEYEVENTF_UNICODE) {
    WCHAR unicode_char = (WCHAR)request->bVK;
    KeyboardCall((USHORT)unicode_char, KEY_MAKE, extra_info);
    KeyboardCall((USHORT)unicode_char, KEY_BREAK, extra_info);

    request->return_value = TRUE;
    return;
  }

  USHORT make_code;
  USHORT final_flags = dwFlags & KEYEVENTF_KEYUP ? KEY_BREAK : KEY_MAKE;

  if (dwFlags & KEYEVENTF_SCANCODE) {
    // bScan already carries the scan code.
    make_code = request->bScan;
    if (dwFlags & KEYEVENTF_EXTENDEDKEY) {
      final_flags |= KEY_E0;
    }
  } else {
    // Convert the virtual key code to its scan code, deriving the 0xE0
    // prefix from the key (or the caller-supplied extended flag).
    USHORT mapped = VkToScanCode(request->bVK);
    make_code = mapped & 0x7F;
    if ((mapped & 0x80) || (dwFlags & KEYEVENTF_EXTENDEDKEY)) {
      final_flags |= KEY_E0;
    }
  }

  KeyboardCall(make_code, final_flags, extra_info);

  request->return_value = TRUE;
  return;
}
