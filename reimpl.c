// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

#define MI_MAPPED_COPY_PAGES 14
#define MI_POOL_COPY_BYTES 512
#define MI_MAX_TRANSFER_SIZE (64 * 1024)

static inline void* kmemcpy(void* dest, const void* src, unsigned long count) {
  __movsb((unsigned char*)dest, (const unsigned char*)src, count);
  return dest;
}

static inline void* reimpl_memcpy(void* dest, const void* src, SIZE_T count) {
  return kmemcpy((unsigned char*)dest, (const unsigned char*)src, (unsigned long)count);
}

NTSTATUS
MiDoMappedCopy(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
               _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
               _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
               _Out_ PSIZE_T ReturnSize) {
  PFN_NUMBER
      MdlBuffer[(sizeof(MDL) / sizeof(PFN_NUMBER)) + MI_MAPPED_COPY_PAGES + 1];
  PMDL Mdl = (PMDL)MdlBuffer;
  SIZE_T TotalSize, CurrentSize, RemainingSize;
  BOOLEAN PagesLocked = FALSE;
  PVOID CurrentAddress = SourceAddress, CurrentTargetAddress = TargetAddress;
  PVOID MdlAddress = NULL;
  KAPC_STATE ApcState;
  NTSTATUS Status = STATUS_SUCCESS;

  PAGED_CODE();

  TotalSize = MI_MAPPED_COPY_PAGES * PAGE_SIZE;
  if (BufferSize <= TotalSize) TotalSize = BufferSize;

  CurrentSize = TotalSize;
  RemainingSize = BufferSize;

  while (RemainingSize > 0) {
    if (RemainingSize < CurrentSize) CurrentSize = RemainingSize;

    KeStackAttachProcess((PRKPROCESS)SourceProcess, &ApcState);

    MmInitializeMdl(Mdl, CurrentAddress, CurrentSize);
    __try {
      MmProbeAndLockPages(Mdl, PreviousMode, IoReadAccess);
      PagesLocked = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      Status = GetExceptionCode();
      KeUnstackDetachProcess(&ApcState);
      goto Exit;
    }
    if (!NT_SUCCESS(Status)) {
      KeUnstackDetachProcess(&ApcState);
      goto Exit;
    }
    PagesLocked = TRUE;

    KeUnstackDetachProcess(&ApcState);

    MdlAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL,
                                              FALSE, HighPagePriority);
    if (!MdlAddress) {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
    }

    KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    __try {
      reimpl_memcpy(CurrentTargetAddress, MdlAddress, CurrentSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      Status = GetExceptionCode();
      KeUnstackDetachProcess(&ApcState);
      goto Exit;
    }

    KeUnstackDetachProcess(&ApcState);

    MmUnmapLockedPages(MdlAddress, Mdl);
    MdlAddress = NULL;
    MmUnlockPages(Mdl);
    PagesLocked = FALSE;

    RemainingSize -= CurrentSize;
    CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
    CurrentTargetAddress =
        (PVOID)((ULONG_PTR)CurrentTargetAddress + CurrentSize);
  }

Exit:
  if (MdlAddress != NULL) MmUnmapLockedPages(MdlAddress, Mdl);

  if (PagesLocked) MmUnlockPages(Mdl);

  if (Status == STATUS_SUCCESS) *ReturnSize = BufferSize;

  return Status;
}

NTSTATUS
MiDoPoolCopy(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
             _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
             _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
             _Out_ PSIZE_T ReturnSize) {
  UNREFERENCED_PARAMETER(PreviousMode);
  UCHAR StackBuffer[MI_POOL_COPY_BYTES];
  SIZE_T TotalSize, CurrentSize, RemainingSize;
  BOOLEAN HavePoolAddress = FALSE;
  PVOID CurrentAddress = SourceAddress, CurrentTargetAddress = TargetAddress;
  PVOID PoolAddress;
  KAPC_STATE ApcState;
  NTSTATUS Status = STATUS_SUCCESS;

  PAGED_CODE();

  TotalSize = MI_MAX_TRANSFER_SIZE;
  if (BufferSize <= MI_MAX_TRANSFER_SIZE) TotalSize = BufferSize;

  CurrentSize = TotalSize;
  RemainingSize = BufferSize;

  if (BufferSize <= MI_POOL_COPY_BYTES) {
    PoolAddress = (PVOID)StackBuffer;
  } else {
    PoolAddress = ExAllocatePool2(POOL_FLAG_NON_PAGED, TotalSize, 'NtFs');
    if (!PoolAddress) return STATUS_INSUFFICIENT_RESOURCES;

    HavePoolAddress = TRUE;
  }

  while (RemainingSize > 0) {
    if (RemainingSize < CurrentSize) CurrentSize = RemainingSize;

    KeStackAttachProcess((PRKPROCESS)SourceProcess, &ApcState);

    reimpl_memcpy(PoolAddress, CurrentAddress, CurrentSize);

    KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status)) goto Exit;

    KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    reimpl_memcpy(CurrentTargetAddress, PoolAddress, CurrentSize);

    KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status)) goto Exit;

    RemainingSize -= CurrentSize;
    CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
    CurrentTargetAddress =
        (PVOID)((ULONG_PTR)CurrentTargetAddress + CurrentSize);
  }

Exit:
  if (HavePoolAddress) ExFreePoolWithTag(PoolAddress, 'NtFs');

  if (Status == STATUS_SUCCESS) *ReturnSize = BufferSize;

  return Status;
}

NTSTATUS
DriverCopyVirtualMemory(IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
                        IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
                        IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
                        OUT PSIZE_T ReturnSize) {
  NTSTATUS Status;
  PEPROCESS Process = SourceProcess;

  if (BufferSize == 0) {
    if (ReturnSize) *ReturnSize = 0;
    return STATUS_SUCCESS;
  }

  PEPROCESS CurrentProcess = PsGetCurrentProcess();
  if (SourceProcess == CurrentProcess) Process = TargetProcess;

  ObReferenceObject(Process);

  if (BufferSize > MI_POOL_COPY_BYTES) {
    Status = MiDoMappedCopy(SourceProcess, SourceAddress, TargetProcess,
                          TargetAddress, BufferSize, PreviousMode, ReturnSize);
  } else {
    Status = MiDoPoolCopy(SourceProcess, SourceAddress, TargetProcess,
                          TargetAddress, BufferSize, PreviousMode, ReturnSize);
  }

  ObDereferenceObject(Process);

  return Status;
}
