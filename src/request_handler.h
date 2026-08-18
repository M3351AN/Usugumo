// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _REQUEST_HANDLER_H_
#define _REQUEST_HANDLER_H_
#include "../includes/usugumo_request_define.h"

#define CHECKSUM_SIZE SHA256_DIGEST_SIZE

extern const UCHAR PUBLIC_KEY[CHECKSUM_SIZE];

FORCEINLINE BOOLEAN VerifySecureKey(UINT64 SecureKey) {
  UCHAR localChecksum[CHECKSUM_SIZE];
  kmemset(localChecksum, 0, sizeof(localChecksum));

  Sha256(&SecureKey, sizeof(UINT64), localChecksum);

  return (RtlCompareMemoryMeme(localChecksum, PUBLIC_KEY, CHECKSUM_SIZE) ==
          CHECKSUM_SIZE);
}

BOOLEAN RequestHandler(Requests*);

#endif
