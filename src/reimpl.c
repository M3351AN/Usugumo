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

size_t __cdecl kwcslen(const wchar_t* Str) {
  __m128i* i;           // rdx
  unsigned __int64 v2;  // r9
  const wchar_t* v3;    // rax
  size_t v4;            // rdx

  i = (__m128i*)Str;
  if (((uintptr_t)Str & 1) != 0) {
    while (i->m128i_i16[0]) i = (__m128i*)((char*)i + 2);
    return ((char*)i - (char*)Str) >> 1;
  }
  v2 = ((16LL - ((uintptr_t)Str & 0xF)) &
        (unsigned __int64)-(__int64)(((uintptr_t)Str & 0xF) != 0)) >>
       1;
  v3 = &Str[v2];
  if (Str != v3) {
    do {
      if (!i->m128i_i16[0]) break;
      i = (__m128i*)((char*)i + 2);
    } while (i != (__m128i*)v3);
  }
  v4 = ((char*)i - (char*)Str) >> 1;
  if (v4 == v2) {
    for (i = (__m128i*)&Str[v4];
         !_mm_movemask_epi8(_mm_cmpeq_epi16(_mm_setzero_si128(), *i)); ++i);
    while (i->m128i_i16[0]) i = (__m128i*)((char*)i + 2);
    return ((char*)i - (char*)Str) >> 1;
  }
  return v4;
}

ULONG g_PebOffset = 0;

ULONG GetPebOffset() {
  if (g_PebOffset != 0) return g_PebOffset;

  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessPeb");

  PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
  if (!pFunc) {
    return 0;
  }

  // 48 8B 81 ?? ?? ?? ?? mov     rax, [rcx+2E0h]
  for (int i = 0; i < 0x10; i++) {
    if (pFunc[i] == 0x48 && pFunc[i + 1] == 0x8B && pFunc[i + 2] == 0x81) {
      ULONG offset = *(PULONG)(pFunc + i + 3);
      // just guessing the range
      if (offset > 0x10 && offset <= 0x1000) {
        g_PebOffset = offset;
        return offset;
      }
    }
  }

  return 0;
}

PPEB PsGetProcessPebTrick(PEPROCESS Process) {
  ULONG offset = GetPebOffset();
  return *(PPEB*)((PUCHAR)Process + offset);
}

ULONG g_ImageFileNameOffset = 0;

ULONG GetImageFileNameOffset() {
  if (g_ImageFileNameOffset != 0) return g_ImageFileNameOffset;

  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");

  PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
  if (!pFunc) {
    return 0;
  }

  // 48 8D 81 ?? ?? ?? ?? lea     rax, [rcx+338h]
  for (int i = 0; i < 0x10; i++) {
    if (pFunc[i] == 0x48 && pFunc[i + 1] == 0x8D && pFunc[i + 2] == 0x81) {
      ULONG offset = *(PULONG)(pFunc + i + 3);
      // just guessing the range
      if (offset > 0x10 && offset <= 0x1000) {
        g_ImageFileNameOffset = offset;
        return offset;
      }
    }
  }

  return 0;
}

PCHAR PsGetProcessImageFileNameTrick(PEPROCESS Process) {
  ULONG offset = GetImageFileNameOffset();
  return (PCHAR)((PUCHAR)Process + offset);
}

ULONG g_ProcessIdOffset = 0;

ULONG GetProcessIdOffset() {
  if (g_ProcessIdOffset != 0) return g_ProcessIdOffset;

  UNICODE_STRING routineName =
      RTL_CONSTANT_STRING(L"PsGetProcessId");

  PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
  if (!pFunc) {
    return 0;
  }

  // 48 8B 81 ?? ?? ?? ?? mov     rax, [rcx+1D0h]
  for (int i = 0; i < 0x10; i++) {
    if (pFunc[i] == 0x48 && pFunc[i + 1] == 0x8B && pFunc[i + 2] == 0x81) {
      ULONG offset = *(PULONG)(pFunc + i + 3);
      // just guessing the range
      if (offset > 0x10 && offset <= 0x1000) {
        g_ProcessIdOffset = offset;
        return offset;
      }
    }
  }

  return 0;
}

HANDLE PsGetProcessIdTrick(PEPROCESS Process) {
  ULONG offset = GetProcessIdOffset();
  return *(HANDLE*)((PUCHAR)Process + offset);
}

ULONG g_ProcessExitStatusOffset = 0;

ULONG GetProcessExitStatusOffset() {
  if (g_ProcessExitStatusOffset != 0) return g_ProcessExitStatusOffset;

  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessExitStatus");

  PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
  if (!pFunc) {
    return 0;
  }

  // 8B 81 ?? ?? ?? ?? mov     eax, [rcx+554h]
  for (int i = 0; i < 0x10; i++) {
    if (pFunc[i] == 0x8B && pFunc[i + 1] == 0x81) {
      ULONG offset = *(PULONG)(pFunc + i + 2);
      // just guessing the range
      if (offset > 0x10 && offset <= 0x1000) {
        g_ProcessExitStatusOffset = offset;
        return offset;
      }
    }
  }

  return 0;
}

NTSTATUS PsGetProcessExitStatusTrick(PEPROCESS Process) {
  ULONG offset = GetProcessExitStatusOffset();
  return *(NTSTATUS*)((PUCHAR)Process + offset);
}
