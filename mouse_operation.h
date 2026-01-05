// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _MOUSE_OPERATION_H_
#define _MOUSE_OPERATION_H_

VOID MouseClassServiceCallbackMeme(PDEVICE_OBJECT DeviceObject,
                               PMOUSE_INPUT_DATA InputDataStart,
                               PMOUSE_INPUT_DATA InputDataEnd,
                               PULONG InputDataConsumed);

VOID HandleMouseEvent(Requests*);

#endif
