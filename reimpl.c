// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

#define MI_MAPPED_COPY_PAGES 14

__int64 _kascii_stricmp(const char* a1, const char* a2) {
  int v4;  // r8d
  int v5;  // edx
  int v6;  // r9d
  int v7;  // eax

  do {
    v4 = *a1++;
    v5 = *a2;
    v6 = v4 + 32;
    if ((unsigned int)(v4 - 65) > 0x19) v6 = v4;
    v7 = v5 + 32;
    ++a2;
    if ((unsigned int)(v5 - 65) > 0x19) v7 = v5;
  } while (v6 && v6 == v7);
  return (unsigned int)(v6 - v7);
}

int kstricmp(const char* Str1, const char* Str2) {
  return (int)_kascii_stricmp(Str1, Str2);
}

int kwcsicmp(const wchar_t* Str1, const wchar_t* Str2) {
  const wchar_t* v2;    // r10
  signed __int64 v3;    // r9
  unsigned __int16 v4;  // r8
  unsigned __int16 v5;  // cx
  unsigned __int16 v6;  // dx
  unsigned __int16 v7;  // r8

  v2 = Str2;
  v3 = (char*)Str1 - (char*)Str2;
  do {
    v4 = *(const wchar_t*)((char*)v2 + v3);
    v5 = *v2++;
    v6 = v4 + 32;
    if ((unsigned __int16)(v4 - 65) > 0x19u) v6 = v4;
    v7 = v5 + 32;
    if ((unsigned __int16)(v5 - 65) > 0x19u) v7 = v5;
  } while (v6 && v6 == v7);
  return v6 - v7;
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
      MmSizeOfMdlMeme(SourceAddress, MI_MAPPED_COPY_PAGES * PAGE_SIZE);
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
      kmemmove(CurrentTargetAddress, MdlAddress, CurrentSize);
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

SIZE_T MmSizeOfMdlMeme(PVOID Base, SIZE_T Length) {
  UINT_PTR base_ptr_val = (UINT_PTR)Base;
  unsigned __int16 base_low_12bit = (unsigned __int16)(base_ptr_val & 0xFFF);

    return 8 * ((((unsigned __int16)base_low_12bit + Length + 4095) >> 12) + 48);
}
