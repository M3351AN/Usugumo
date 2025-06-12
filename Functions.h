#pragma once
#include "imports.h"
#include "defines.h"
BOOL ReadVM(Requests* in);

BOOL WriteVM(Requests* in);

UINT64 GetDllAddress(Requests* in);

BOOL RequestHandler(Requests* pstruct);