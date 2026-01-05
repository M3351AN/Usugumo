// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"


VOID DecodeFixedStr64(const FixedStr64* fs, char* output, SIZE_T origLen) {
  size_t idx = 0;
  for (size_t block = 0; block < 8; block++) {
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

PWSTR ConvertToPWSTR(const char* ascii_str) {
  SIZE_T len = 0;

  while (ascii_str[len] != '\0') {
    len++;
  }

  wchar_t* w_str = (wchar_t*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                             (len + 1) * sizeof(WCHAR), 'NtFs');
  if (!w_str) {
    return NULL;
  }

  for (SIZE_T i = 0; i < len; i++) {
    w_str[i] = (WCHAR)ascii_str[i];
  }
  w_str[len] = L'\0';

  return w_str;
}

PVOID SearchSignForImage(PVOID ImageBase, PUCHAR Pattern, PCHAR Mask,
                                ULONG PatternSize) {
  PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeaderMeme(ImageBase);
  if (!NtHeaders) return NULL;

  PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
  for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections;
       i++, Section++) {
    if (kstricmp((PCHAR)Section->Name, ".text") == 0 ||
        (Section->Characteristics & IMAGE_SCN_CNT_CODE)) {
      PUCHAR Start = (PUCHAR)ImageBase + Section->VirtualAddress;
      ULONG Size = Section->Misc.VirtualSize;

      for (ULONG j = 0; j <= Size - PatternSize; j++) {
        BOOLEAN Found = TRUE;

        for (ULONG k = 0; k < PatternSize; k++) {
          if (Mask[k] == 'x' && Start[j + k] != Pattern[k]) {
            Found = FALSE;
            break;
          }
        }

        if (Found) return Start + j;
      }
    }
  }

  return NULL;
}

LPBYTE ResolveRelativeAddress(LPBYTE pAddress, ULONG Index) {
  LPBYTE Result = NULL;
  if (pAddress != NULL) {
    Result = (LPBYTE)(pAddress + *(INT*)(pAddress + Index) + Index + 4);
  }
  return Result;
}

NTSTATUS ZwReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes,
                                 PACCESS_STATE PassedAccessState,
                                 ACCESS_MASK DesiredAccess,
                                 POBJECT_TYPE ObjectType,
                                 KPROCESSOR_MODE AccessMode,
                                 LPVOID ParseContext, PDRIVER_OBJECT* Object) {
  static fn_ObReferenceObjectByName _ObReferenceObjectByName = NULL;
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  if (_ObReferenceObjectByName == NULL) {
    UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"ObReferenceObjectByName");
    _ObReferenceObjectByName =
        (fn_ObReferenceObjectByName)MmGetSystemRoutineAddress(&FuncName);
  }

  if (_ObReferenceObjectByName != NULL) {
    Status = _ObReferenceObjectByName(ObjectName, Attributes, PassedAccessState,
                                      DesiredAccess, ObjectType, AccessMode,
                                      ParseContext, Object);
  }

  return Status;
}

NTSTATUS GetMachineGuid(WCHAR* guid_buf, size_t buf_len) {
  if (!guid_buf || buf_len < 64) {
    return STATUS_INVALID_PARAMETER;
  }

  UNICODE_STRING key_path = RTL_CONSTANT_STRING(
      L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
  UNICODE_STRING value_name = RTL_CONSTANT_STRING(L"MachineGuid");
  HANDLE hKey = NULL;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG data_len = 0;
  PKEY_VALUE_PARTIAL_INFORMATION pInfo = NULL;

  OBJECT_ATTRIBUTES obj_attr;
  InitializeObjectAttributes(
      &obj_attr,
      &key_path,
      OBJ_CASE_INSENSITIVE,
      NULL,
      NULL
  );

  status = ZwOpenKey(&hKey, KEY_READ, &obj_attr);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = ZwQueryValueKey(hKey, &value_name, KeyValuePartialInformation, NULL,
                           0, &data_len);
  if (status != STATUS_BUFFER_TOO_SMALL) {
    ZwClose(hKey);
    return status;
  }

  pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED,
                                                          data_len, 'Usug');
  if (!pInfo) {
    ZwClose(hKey);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = ZwQueryValueKey(hKey, &value_name, KeyValuePartialInformation, pInfo,
                           data_len, &data_len);
  if (NT_SUCCESS(status)) {
    size_t copy_len = min((size_t)data_len, buf_len - 1);
    kmemmove(guid_buf, pInfo->Data, copy_len * sizeof(WCHAR));
    guid_buf[copy_len] = L'\0';
  }

  if (pInfo) ExFreePool(pInfo);
  ZwClose(hKey);
  return status;
}
