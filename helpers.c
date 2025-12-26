// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"


VOID DecodeFixedStr64(const FixedStr64* fs, char* output, SIZE_T origLen) {
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

PWSTR ConvertToPWSTR(const char* ascii_str) {
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
