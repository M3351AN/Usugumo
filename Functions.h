// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_

#include "./imports.h"
#include "./defines.h"
BOOL ReadVM(Requests* in);

BOOL WriteVM(Requests* in);

UINT64 GetDllAddress(Requests* in);

void KernelMouseEvent(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData,
                        ULONG_PTR dwExtraInfo);

BOOL RequestHandler(Requests* pstruct);

#endif
