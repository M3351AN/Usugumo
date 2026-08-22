// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _HELPERS_H_
#define _HELPERS_H_
#include "../includes/usugumo_request_define.h"

#define SHA256_DIGEST_SIZE 32

VOID Sha256(const void* data, SIZE_T length, UCHAR digest[SHA256_DIGEST_SIZE]);

VOID DecodeFixedStr64(const FixedStr64*, char*, SIZE_T);

PWSTR ConvertToPWSTR(const char*);

FORCEINLINE VOID FreeConvertedPWSTR(PWSTR* ppwStr) {
  if (ppwStr == NULL || *ppwStr == NULL) {
    return;
  }
  SIZE_T cch = kwcslen(*ppwStr) + 1;
  SIZE_T byteSize = cch * sizeof(WCHAR);

  RtlSecureZeroMemory(*ppwStr, byteSize);
  _ExFreePoolWithTag(*ppwStr, 0x72656355);

  *ppwStr = NULL;
}

PVOID SearchSignForImage(PVOID, PUCHAR, PCHAR, ULONG);

LPBYTE ResolveRelativeAddress(PVOID, ULONG);

unsigned __int64 CalculateRequestsChecksum(Requests*);

NTSTATUS GetMachineGuid(WCHAR*, SIZE_T);

NTSTATUS GetBootVolumeSerial(_Out_ char* out, _In_ ULONG outLen);
NTSTATUS GenerateObfuscatedName(_In_ const UCHAR* serial, _In_ ULONG serialLen,
                                _Out_ WCHAR* out, _In_ ULONG outLen);

#endif
