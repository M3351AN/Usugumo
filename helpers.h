// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _HELPERS_H_
#define _HELPERS_H_

VOID DecodeFixedStr64(const FixedStr64*, char*, SIZE_T);

PWSTR ConvertToPWSTR(const char*);

PVOID SearchSignForImage(PVOID, PUCHAR, PCHAR, ULONG);

LPBYTE ResolveRelativeAddress(PVOID, ULONG);

NTSTATUS ZwReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE,
                                 ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE,
                                 LPVOID, PDRIVER_OBJECT*);

unsigned __int64 CalculateRequestsChecksum(Requests*);

NTSTATUS GetMachineGuid(WCHAR*, SIZE_T);

#endif
