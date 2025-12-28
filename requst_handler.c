// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

BOOLEAN RequestHandler(Requests* pstruct) {
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
    default: {
      pstruct->return_value = FALSE;
      break;
    }
  }

  return TRUE;
}
