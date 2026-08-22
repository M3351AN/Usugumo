// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

// 0xBEEFDEADFEEDCAFE
const UCHAR PUBLIC_KEY[CHECKSUM_SIZE] = {
    0x29, 0x51, 0x35, 0x8E, 0x6F, 0x85, 0xA5, 0xDA, 0xE0, 0x8E, 0x60,
    0x3E, 0x94, 0x6E, 0xE9, 0xBD, 0x49, 0xA1, 0x67, 0xE1, 0x02, 0xA3,
    0xA0, 0x61, 0x4E, 0x55, 0x24, 0x5C, 0x0A, 0x16, 0xD6, 0xD0
};

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
  if ((pstruct->request_key & USUGUMO_SIGNATURE_MASK) != USUGUMO_SIGNATURE_MASK) {
    return FALSE;
  }
  UINT64 func = pstruct->request_key & USUGUMO_FUNC_BITS;

  if (func & USUGUMO_PROBE) {
    pstruct->return_value = USUGUMO_SUPPORTED_MASK;
    return TRUE;
  }

  BOOLEAN handled = FALSE;

  if (func & USUGUMO_READ) {
    pstruct->return_value = ReadVM(pstruct);
    handled = TRUE;
  }
  if (func & USUGUMO_WRITE) {
    pstruct->return_value = WriteVM(pstruct);
    handled = TRUE;
  }
  if (func & USUGUMO_MOUSE) {
    HandleMouseEvent(pstruct);
    pstruct->return_value = TRUE;
    handled = TRUE;
  }
  if (func & USUGUMO_KEYBD) {
    HandleKeybdEvent(pstruct);
    pstruct->return_value = TRUE;
    handled = TRUE;
  }
  if (func & USUGUMO_MODULE_BASE) {
    pstruct->return_value = GetDllAddress(pstruct);
    handled = TRUE;
  }
  if (func & USUGUMO_MODULE_SIZE) {
    pstruct->return_value = GetDllSize(pstruct);
    handled = TRUE;
  }
  if (func & USUGUMO_PID) {
    pstruct->return_value = GetProcessIdByName(pstruct);
    handled = TRUE;
  }
  if (func & USUGUMO_ANTI_CAPTURE) {
    pstruct->return_value = HandleAntiCapture(pstruct);
    handled = TRUE;
  }

  return handled;
}
