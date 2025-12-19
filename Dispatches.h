// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _DISPATCHES_H_
#define _DISPATCHES_H_
#include "./imports.h"

NTSTATUS DefaultDispatch(PDEVICE_OBJECT device_obj, PIRP irp);

NTSTATUS IoctlDispatch(PDEVICE_OBJECT device_obj, PIRP irp);
#endif
