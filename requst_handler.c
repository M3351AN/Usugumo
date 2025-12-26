// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

BOOLEAN RequestHandler(Requests* pstruct) {
  switch (pstruct->request_key) {
    case DLL_BASE: {
      ULONG64 base = GetDllAddress(pstruct);
      pstruct->return_value = base;
      return pstruct->return_value != 0;
    }
    case DLL_SIZE: {
      ULONG64 size = GetDllSize(pstruct);
      pstruct->return_value = size;
      return size != 0;
    }
    case DRIVER_READVM: {
      return ReadVM(pstruct);
    }
    case DRIVER_WRITEVM: {
      return WriteVM(pstruct);
    }
    case HID: {
      KernelMouseEvent(pstruct->dwFlags, pstruct->dx, pstruct->dy,
                       pstruct->dwData, pstruct->dwExtraInfo);
      return TRUE;
    }
  }

  return TRUE;
}
