// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

#define MI_MAPPED_COPY_PAGES 14

static inline void* kmemcpy(void* dest, const void* src, unsigned long count) {
  __movsb((unsigned char*)dest, (const unsigned char*)src, count);
  return dest;
}

static inline void* reimpl_memcpy(void* dest, const void* src, SIZE_T count) {
  return kmemcpy((unsigned char*)dest, (const unsigned char*)src,
                 (unsigned long)count);
}

NTSTATUS
MiDoMappedCopy(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
               _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
               _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
               _Out_ PSIZE_T ReturnSize) {
  PMDL Mdl = NULL;
  SIZE_T TotalSize = 0;
  SIZE_T CurrentSize = 0;
  SIZE_T RemainingSize = 0;
  BOOLEAN PagesLocked = FALSE;
  PVOID CurrentAddress = SourceAddress;
  PVOID CurrentTargetAddress = TargetAddress;
  PVOID MdlAddress = NULL;
  KAPC_STATE ApcState;
  NTSTATUS Status = STATUS_SUCCESS;
  SIZE_T MdlRequiredSize = 0;

  PAGED_CODE();

  MdlRequiredSize =
      MmSizeOfMdl(SourceAddress, MI_MAPPED_COPY_PAGES * PAGE_SIZE);
  if (MdlRequiredSize == 0 ||
      MdlRequiredSize > (MI_MAPPED_COPY_PAGES * PAGE_SIZE * 2)) {
    Status = STATUS_INVALID_PARAMETER;
    goto Exit;
  }

  Mdl = (PMDL)ExAllocatePool2(
      POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
      MdlRequiredSize, 'sFtN');

  if (Mdl == NULL) {
    Status = STATUS_INSUFFICIENT_RESOURCES;
    goto Exit;
  }

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
      PagesLocked =
          FALSE;
      KeUnstackDetachProcess(&ApcState);
      goto Exit;
    }

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
  if (MdlAddress != NULL) {
    MmUnmapLockedPages(MdlAddress, Mdl);
    MdlAddress = NULL;
  }

  if (PagesLocked) {
    MmUnlockPages(Mdl);
    PagesLocked = FALSE;
  }

  if (Mdl != NULL) {
    ExFreePoolWithTag(Mdl, 'sFtN');
    Mdl = NULL;
  }

  if (Status == STATUS_SUCCESS && ReturnSize != NULL) {
    *ReturnSize = BufferSize;
  }

  return Status;
}

NTSTATUS
DriverCopyVirtualMemory(IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
                        IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
                        IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
                        OUT PSIZE_T ReturnSize) {
  NTSTATUS Status;

  if (SourceProcess == NULL || TargetProcess == NULL || SourceAddress == NULL ||
      TargetAddress == NULL) {
    if (ReturnSize != NULL) {
      *ReturnSize = 0;
    }
    return STATUS_INVALID_PARAMETER;
  }

  if (BufferSize == 0) {
    if (ReturnSize) *ReturnSize = 0;
    return STATUS_SUCCESS;
  }

  Status = MiDoMappedCopy(SourceProcess, SourceAddress, TargetProcess,
                          TargetAddress, BufferSize, PreviousMode, ReturnSize);

  return Status;
}
