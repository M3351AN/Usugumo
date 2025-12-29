// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _MOUSE_OPERATION_H_
#define _MOUSE_OPERATION_H_

QWORD _KeAcquireSpinLockAtDpcLevel;
QWORD _KeReleaseSpinLockFromDpcLevel;
QWORD _IofCompleteRequest;
QWORD _IoReleaseRemoveLockEx;

VOID HandleMouseEvent(Requests*);

#endif
