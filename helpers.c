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
                                             (len + 1) * sizeof(WCHAR), 'pcwT');
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
  PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
  if (!NtHeaders) return NULL;

  PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
  for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections;
       i++, Section++) {
    if (strcmp((PCHAR)Section->Name, ".text") == 0 ||
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
