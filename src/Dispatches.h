// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _DISPATCHES_H_
#define _DISPATCHES_H_
#include "./imports.h"

NTSTATUS DefaultDispatch(PDEVICE_OBJECT, PIRP);

NTSTATUS WriteDispatch(PDEVICE_OBJECT, PIRP);

NTSTATUS ReadDispatch(PDEVICE_OBJECT, PIRP);

#endif
