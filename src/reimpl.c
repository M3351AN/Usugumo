// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

__int64 _kascii_stricmp(const char* a1, const char* a2) {
  int v4;  // r8d
  int v5;  // edx
  int v6;  // r9d
  int v7;  // eax

  do {
    v4 = *a1++;
    v5 = *a2;
    v6 = v4 + 32;
    if ((unsigned int)(v4 - 65) > 0x19) v6 = v4;
    v7 = v5 + 32;
    ++a2;
    if ((unsigned int)(v5 - 65) > 0x19) v7 = v5;
  } while (v6 && v6 == v7);
  return (unsigned int)(v6 - v7);
}

int kstricmp(const char* Str1, const char* Str2) {
  return (int)_kascii_stricmp(Str1, Str2);
}

int kwcsicmp(const wchar_t* Str1, const wchar_t* Str2) {
  const wchar_t* v2;    // r10
  signed __int64 v3;    // r9
  unsigned __int16 v4;  // r8
  unsigned __int16 v5;  // cx
  unsigned __int16 v6;  // dx
  unsigned __int16 v7;  // r8

  v2 = Str2;
  v3 = (char*)Str1 - (char*)Str2;
  do {
    v4 = *(const wchar_t*)((char*)v2 + v3);
    v5 = *v2++;
    v6 = v4 + 32;
    if ((unsigned __int16)(v4 - 65) > 0x19u) v6 = v4;
    v7 = v5 + 32;
    if ((unsigned __int16)(v5 - 65) > 0x19u) v7 = v5;
  } while (v6 && v6 == v7);
  return v6 - v7;
}

