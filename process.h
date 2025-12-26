// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_

BOOLEAN ReadVM(Requests*);

BOOLEAN WriteVM(Requests*);

UINT64 GetDllAddress(Requests*);

UINT64 GetDllSize(Requests*);

UINT64 GetProcessIdByName(Requests*);

#endif
