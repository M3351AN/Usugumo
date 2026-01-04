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

unsigned __int64 CalculateRequestsChecksum(Requests* pRequest) {
  if (pRequest == NULL) {
    return 0;
  }
  // CRC64-ECMA
  const unsigned __int64 CRC64_POLYNOMIAL = 0x42F0E1EBA9EA3693ULL;
  static unsigned __int64 crc64_table[256] = {0};
  static BOOLEAN table_initialized = FALSE;

  if (!table_initialized) {
    for (unsigned int i = 0; i < 256; i++) {
      unsigned __int64 crc = (unsigned __int64)i;
      for (int j = 0; j < 8; j++) {
        if (crc & 1) {
          crc = (crc >> 1) ^ CRC64_POLYNOMIAL;
        } else {
          crc >>= 1;
        }
      }
      crc64_table[i] = crc;
    }
    table_initialized = TRUE;
  }

  unsigned __int64 validDataLen =
      sizeof(Requests) - sizeof(pRequest->check_sum);
  const unsigned char* pData = (const unsigned char*)pRequest;

  unsigned __int64 crc64 = 0xFFFFFFFFFFFFFFFFULL;
  for (unsigned __int64 i = 0; i < validDataLen; i++) {
    crc64 = crc64_table[(crc64 ^ pData[i]) & 0xFF] ^ (crc64 >> 8);
  }
  crc64 ^= 0xFFFFFFFFFFFFFFFFULL;
  return crc64;
}
