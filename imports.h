#pragma once
#include <ntifs.h>

NTKERNELAPI NTSTATUS
IoCreateDriver(_In_ PUNICODE_STRING DriverName,
               _In_ PDRIVER_INITIALIZE InitializationFunction);

__declspec(dllimport) NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess, IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);

__declspec(dllimport) PPEB PsGetProcessPeb(PEPROCESS);