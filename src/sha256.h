// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _SHA256_H_
#define _SHA256_H_

#include <ntddk.h>

#define SHA256_DIGEST_SIZE 32

VOID Sha256(const void* data, SIZE_T length, UCHAR digest[SHA256_DIGEST_SIZE]);

#endif
