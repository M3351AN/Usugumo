// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _KEYBD_OPERATION_H_
#define _KEYBD_OPERATION_H_
#include "includes/usugumo_request_define.h"

NTSTATUS SearchKdbServiceCallBack(void);

VOID HandleKeybdEvent(Requests*);

VOID KeyboardSpinLockInit();

#endif
