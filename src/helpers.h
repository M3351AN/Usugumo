// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _HELPERS_H_
#define _HELPERS_H_
#include "../includes/usugumo_request_define.h"

#define SHA256_DIGEST_SIZE 32

VOID Sha256(const void* data, SIZE_T length, UCHAR digest[SHA256_DIGEST_SIZE]);

VOID DecodeFixedStr64(const FixedStr64*, char*, SIZE_T);

PWSTR ConvertToPWSTR(const char*);

VOID FreeConvertedPWSTR(PWSTR* ppwStr);

PVOID SearchSignForImage(PVOID, PUCHAR, PCHAR, ULONG);

LPBYTE ResolveRelativeAddress(PVOID, ULONG);

unsigned __int64 CalculateRequestsChecksum(Requests*);

NTSTATUS GetMachineGuid(WCHAR*, SIZE_T);

#endif
