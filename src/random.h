// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _RANDOM_H_
#define _RANDOM_H_

#include <ntddk.h>

VOID RandomEngineInit(VOID);

ULONGLONG RandomEngineNext(VOID);

#endif
