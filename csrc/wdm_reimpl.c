// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

BOOL g_WdmlibInitialized = FALSE;

typedef int(__fastcall* fn_IoCreateDeviceSecure)(DRIVER_OBJECT*, unsigned int,
                                                 UNICODE_STRING*, unsigned int,
                                                 unsigned int, unsigned __int8,
                                                 const UNICODE_STRING*,
                                                 const GUID*, DEVICE_OBJECT**);
fn_IoCreateDeviceSecure _IoCreateDeviceSecure = 0;

typedef int(__fastcall* fn_IoValidateDeviceIoControlAccess)(IRP*, unsigned int);
fn_IoValidateDeviceIoControlAccess _IoValidateDeviceIoControlAccess = 0;
/*
NTSTATUS __fastcall IoDevObjCreateDeviceSecureMeme(
    DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize,
    UNICODE_STRING* DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics,
    BOOLEAN Exclusive, const UNICODE_STRING* DefaultSDDLString,
    const GUID* DeviceClassGuid, DEVICE_OBJECT** DeviceObject) {
  DEVICE_OBJECT** v9;                      // rsi
  ULONG Characteristics;                   // r14d
  NTSTATUS result;                         // eax
  char Flags;                              // al
  NTSTATUS updated;                        // ebx
  BOOLEAN Exclusivity;                     // cl
  STACK_CREATION_SETTINGS stackSettings;   // [rsp+40h] [rbp-30h] BYREF
  STACK_CREATION_SETTINGS updateSettings;  // [rsp+58h] [rbp-18h] BYREF
  void* securityDescriptor;                // [rsp+B0h] [rbp+40h] BYREF

  v9 = DeviceObject;
  Characteristics = DeviceCharacteristics;
  securityDescriptor = 0;
  *(QWORD*)&stackSettings.Characteristics = 0;
  *DeviceObject = 0;
  DeviceObject = 0;
  *(QWORD*)&stackSettings.Flags = 0;
  memset(&updateSettings, 0, sizeof(updateSettings));
  if (!DeviceName && (Characteristics & 0x80u) == 0) return -1073741811;
  if (!DeviceClassGuid) {
    PpRegStateInitEmptyCreationSettings(&stackSettings);
  LABEL_8:
    Flags = stackSettings.Flags;
    if ((stackSettings.Flags & 2) == 0) {
      updated = SeSddlSecurityDescriptorFromSDDL(DefaultSDDLString, 1u,
                                                 &securityDescriptor);
      if (updated < 0 ||
          (PpRegStateLoadSecurityDescriptor(securityDescriptor, &stackSettings),
           DeviceClassGuid) &&
              (PpRegStateInitEmptyCreationSettings(&updateSettings),
               PpRegStateLoadSecurityDescriptor(securityDescriptor,
                                                &updateSettings),
               updated = PpRegStateUpdateStackCreationSettings(DeviceClassGuid,
                                                               &updateSettings),
               updated < 0)) {
      $Exit:
        PpRegStateFreeStackCreationSettings(&stackSettings);
        return updated;
      }
      Flags = stackSettings.Flags;
    }
    Exclusivity = Exclusive;
    if ((Flags & 1) != 0) DeviceType = stackSettings.DeviceType;
    if ((Flags & 4) != 0) Characteristics = stackSettings.Characteristics;
    if ((Flags & 8) != 0) Exclusivity = stackSettings.Exclusivity;
    updated = IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName,
                             DeviceType, Characteristics, Exclusivity,
                             (PDEVICE_OBJECT*)&DeviceObject);
    if (updated >= 0) {
      updated = IopDevObjApplyPostCreationSettings((DEVICE_OBJECT*)DeviceObject,
                                                   &stackSettings);
      if (updated >= 0)
        *v9 = (DEVICE_OBJECT*)DeviceObject;
      else
        _IoDeleteDevice((PDEVICE_OBJECT)DeviceObject);
    }
    goto $Exit;
  }
  result = PpRegStateReadCreateClassCreationSettings(
      DeviceClassGuid, DriverObject, &stackSettings);
  if (result >= 0) goto LABEL_8;
  return result;
}
*/
int(__fastcall* WdmlibInitMeme())(IRP*, unsigned int) {
  int(__fastcall * result)(IRP*, unsigned int);  // rax

  _IoCreateDeviceSecure =
      (int(__fastcall*)(DRIVER_OBJECT*, unsigned int, UNICODE_STRING*, unsigned int, unsigned int,
      unsigned __int8, const UNICODE_STRING*, const GUID*,
      DEVICE_OBJECT**))FindKernelProcAddress("IoCreateDeviceSecure");
  /*
   if (!_IoCreateDeviceSecure)
     _IoCreateDeviceSecure = IoDevObjCreateDeviceSecureMeme;*/
  result = (int(__fastcall*)(IRP*, unsigned int))FindKernelProcAddress(
      "IoValidateDeviceIoControlAccess");
  _IoValidateDeviceIoControlAccess = result;
  g_WdmlibInitialized = 1;
  return result;
}

NTSTATUS
WdmlibIoCreateDeviceSecureMeme(
    DRIVER_OBJECT* DriverObject, unsigned int DeviceExtensionSize,
    UNICODE_STRING* DeviceName, unsigned int DeviceType,
    unsigned int DeviceCharacteristics, unsigned __int8 Exclusive,
    const UNICODE_STRING* DefaultSDDLString, const GUID* DeviceClassGuid,
    DEVICE_OBJECT** DeviceObject) {
  if (!g_WdmlibInitialized) WdmlibInitMeme();
  return _IoCreateDeviceSecure(DriverObject, DeviceExtensionSize, DeviceName,
                               DeviceType, DeviceCharacteristics, Exclusive,
                               DefaultSDDLString, DeviceClassGuid,
                               DeviceObject);
}
