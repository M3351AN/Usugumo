// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _REIMPL_H_
#define _REIMPL_H_

NTSTATUS
DriverCopyVirtualMemory(IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
                        IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
                        IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
                        OUT PSIZE_T ReturnSize);

#endif
