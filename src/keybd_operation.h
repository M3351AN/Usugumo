// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _KEYBD_OPERATION_H_
#define _KEYBD_OPERATION_H_
#include "../includes/usugumo_request_define.h"

VOID KeyboardClassServiceCallbackMeme(PDEVICE_OBJECT DeviceObject,
                                      PKEYBOARD_INPUT_DATA InputDataStart,
                                      PKEYBOARD_INPUT_DATA InputDataEnd,
                                      PULONG InputDataConsumed);

VOID KeyboardRelease(void);

VOID HandleKeybdEvent(Requests*);

#endif
