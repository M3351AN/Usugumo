// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"
#define CHECKSUM_ALGORITHM BCRYPT_SHA256_ALGORITHM
#define CHECKSUM_SIZE 32

// 0xBEEFDEADFEEDCAFE
const UCHAR PUBLIC_KEY[CHECKSUM_SIZE] = {
    0x29, 0x51, 0x35, 0x8E, 0x6F, 0x85, 0xA5, 0xDA, 0xE0, 0x8E, 0x60,
    0x3E, 0x94, 0x6E, 0xE9, 0xBD, 0x49, 0xA1, 0x67, 0xE1, 0x02, 0xA3,
    0xA0, 0x61, 0x4E, 0x55, 0x24, 0x5C, 0x0A, 0x16, 0xD6, 0xD0
};

BOOLEAN VerifySecureKey(UINT64 SecureKey) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  UCHAR localChecksum[CHECKSUM_SIZE];
  kmemset(localChecksum, 0, sizeof(localChecksum));
  NTSTATUS status = STATUS_SUCCESS;
  BOOLEAN bPass = FALSE;

  status = BCryptOpenAlgorithmProvider(&hAlg, CHECKSUM_ALGORITHM, NULL, 0);
  if (NT_SUCCESS(status))
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);

  if (NT_SUCCESS(status))
    status = BCryptHashData(hHash, (PBYTE)&SecureKey, sizeof(UINT64), 0);
  if (NT_SUCCESS(status))
    status = BCryptFinishHash(hHash, localChecksum, CHECKSUM_SIZE, 0);

  if (NT_SUCCESS(status)) {
    bPass = (RtlCompareMemoryMeme(localChecksum, PUBLIC_KEY,
                              CHECKSUM_SIZE) == CHECKSUM_SIZE);
  }

  if (hHash) BCryptDestroyHash(hHash);
  if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

  return bPass;
}

BOOLEAN RequestHandler(Requests* pstruct) {
  if (!pstruct) {
    return FALSE;
  }
  if (!IsTimestampValid(pstruct->time_stamp, 1)) {  // +-1s
    return FALSE;
  }
  if (pstruct->check_sum != CalculateRequestsChecksum(pstruct)) {
    return FALSE;
  }
  if (!VerifySecureKey(pstruct->secure_key)) {
    return FALSE;
  }
  switch (pstruct->request_key) {
    case USUGUMO_PROBE: {
      pstruct->return_value = TRUE;
      break;
    }
    case USUGUMO_READ: {
      pstruct->return_value = ReadVM(pstruct);
      break;
    }
    case USUGUMO_WRITE: {
      pstruct->return_value = WriteVM(pstruct);
      break;
    }
    case USUGUMO_MOUSE: {
      HandleMouseEvent(pstruct);
      pstruct->return_value = TRUE;
      break;
    }
    case USUGUMO_KEYBD: {
      HandleKeybdEvent(pstruct);
      pstruct->return_value = TRUE;
      break;
    }
    case USUGUMO_MODULE_BASE: {
      pstruct->return_value = GetDllAddress(pstruct);
      break;
    }
    case USUGUMO_MODULE_SIZE: {
      pstruct->return_value = GetDllSize(pstruct);
      break;
    }
    case USUGUMO_PID: {
      pstruct->return_value = GetProcessIdByName(pstruct);
      break;
    }
    case USUGUMO_ANTI_CAPTURE: {
      pstruct->return_value = HandleAntiCapture(pstruct);
      break;
    }
    default: {
      pstruct->return_value = FALSE;
      break;
    }
  }

  return TRUE;
}
