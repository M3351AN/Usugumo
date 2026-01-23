// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

MDL_POOL g_MdlPool = {0};

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

NTSTATUS MdlPoolInitialize() {
  NTSTATUS status = STATUS_SUCCESS;

  KeInitializeSpinLock(&g_MdlPool.Lock);
  g_MdlPool.MaxSingleMdlSize = MDL_MAX_BUFFER_SIZE;

  for (INT i = 0; i < MDL_POOL_SIZE; i++) {
    g_MdlPool.Items[i].Mdl =
        IoAllocateMdl(NULL,
                      (ULONG)MDL_MAX_BUFFER_SIZE,
                      FALSE,
                      FALSE,
                      NULL
        );

    if (!g_MdlPool.Items[i].Mdl) {
      status = STATUS_INSUFFICIENT_RESOURCES;
      goto Cleanup;
    }

    g_MdlPool.Items[i].IsAvailable = TRUE;
    g_MdlPool.Items[i].MaxBufferSize = MDL_MAX_BUFFER_SIZE;
  }

  return status;

Cleanup:
  for (INT i = 0; i < MDL_POOL_SIZE; i++) {
    if (g_MdlPool.Items[i].Mdl) {
      IoFreeMdl(g_MdlPool.Items[i].Mdl);
      g_MdlPool.Items[i].Mdl = NULL;
    }
    g_MdlPool.Items[i].IsAvailable = FALSE;
  }
  return status;
}

PMDL MdlPoolAcquire(SIZE_T BufferSize) {
  if (BufferSize == 0 || BufferSize > g_MdlPool.MaxSingleMdlSize)
    return NULL;

  KIRQL oldIrql = 0;
  PMDL mdl = NULL;

  KeAcquireSpinLock(&g_MdlPool.Lock, &oldIrql);

  for (INT i = 0; i < MDL_POOL_SIZE; i++) {
    if (g_MdlPool.Items[i].IsAvailable &&
        g_MdlPool.Items[i].MaxBufferSize >= BufferSize) {
      g_MdlPool.Items[i].IsAvailable = FALSE;
      mdl = g_MdlPool.Items[i].Mdl;
      break;
    }
  }

  KeReleaseSpinLock(&g_MdlPool.Lock, oldIrql);

  return mdl;
}

VOID MdlPoolRelease(PMDL Mdl) {
  if (!Mdl) return;

  KIRQL oldIrql = 0;

  KeAcquireSpinLock(&g_MdlPool.Lock, &oldIrql);

  for (INT i = 0; i < MDL_POOL_SIZE; i++) {
    if (g_MdlPool.Items[i].Mdl == Mdl) {
      Mdl->Next = NULL;
      Mdl->Size = MDL_HDR_SIZE + (CSHORT)g_MdlPool.Items[i].MaxBufferSize;
      Mdl->MdlFlags = 0;
      Mdl->StartVa = NULL;
      Mdl->ByteOffset = 0;
      Mdl->ByteCount = 0;

      g_MdlPool.Items[i].IsAvailable = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&g_MdlPool.Lock, oldIrql);
}

VOID MdlPoolDestroy() {
  for (INT i = 0; i < MDL_POOL_SIZE; i++) {
    if (g_MdlPool.Items[i].Mdl) {
      IoFreeMdl(g_MdlPool.Items[i].Mdl);
      g_MdlPool.Items[i].Mdl = NULL;
    }
    g_MdlPool.Items[i].IsAvailable = FALSE;
  }
}

NTSTATUS
MiDoMappedCopy(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
               _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
               _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
               _Out_ PSIZE_T ReturnSize) {
  KAPC_STATE ApcState;
  NTSTATUS Status = STATUS_SUCCESS;
  PMDL SourceMdl = NULL;
  PMDL TargetMdl = NULL;
  PVOID SourceMappedAddr = NULL;
  PVOID TargetMappedAddr = NULL;
  BOOLEAN bSourceMdlFromPool = FALSE;
  BOOLEAN bTargetMdlFromPool = FALSE;

  if (ReturnSize != NULL) {
    *ReturnSize = 0;
  }

  if (SourceProcess == NULL || SourceAddress == NULL || TargetProcess == NULL ||
      TargetAddress == NULL || BufferSize == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  SourceMdl = MdlPoolAcquire(BufferSize);
  if (SourceMdl) {
    bSourceMdlFromPool = TRUE;
    MmInitializeMdl(SourceMdl, SourceAddress, (ULONG)BufferSize);
  } else {
    KeStackAttachProcess((PRKPROCESS)SourceProcess, &ApcState);
    SourceMdl =
        IoAllocateMdl(SourceAddress, (ULONG)BufferSize, FALSE, FALSE, NULL);
    KeUnstackDetachProcess(&ApcState);

    if (SourceMdl == NULL) {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
    }
  }

  KeStackAttachProcess((PRKPROCESS)SourceProcess, &ApcState);
  __try {
    MmProbeAndLockPages(SourceMdl, PreviousMode, IoReadAccess);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Status = GetExceptionCode();
    if (bSourceMdlFromPool)
      MdlPoolRelease(SourceMdl);
    else
      IoFreeMdl(SourceMdl);
    SourceMdl = NULL;
    KeUnstackDetachProcess(&ApcState);
    goto Exit;
  }
  KeUnstackDetachProcess(&ApcState);

  SourceMappedAddr = MmMapLockedPagesSpecifyCache(
      SourceMdl, PreviousMode, MmNonCached, NULL, FALSE, NormalPagePriority);
  if (SourceMappedAddr == NULL) {
    Status = STATUS_INSUFFICIENT_RESOURCES;
    goto Exit;
  }

  TargetMdl = MdlPoolAcquire(BufferSize);
  if (TargetMdl) {
    bTargetMdlFromPool = TRUE;
    MmInitializeMdl(TargetMdl, TargetAddress, (ULONG)BufferSize);
  } else {
    KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);
    TargetMdl =
        IoAllocateMdl(TargetAddress, (ULONG)BufferSize, FALSE, FALSE, NULL);
    KeUnstackDetachProcess(&ApcState);

    if (TargetMdl == NULL) {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
    }
  }

  KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);
  __try {
    MmProbeAndLockPages(TargetMdl, PreviousMode, IoWriteAccess);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Status = GetExceptionCode();
    if (bTargetMdlFromPool)
      MdlPoolRelease(TargetMdl);
    else
      IoFreeMdl(TargetMdl);
    TargetMdl = NULL;
    KeUnstackDetachProcess(&ApcState);
    goto Exit;
  }
  KeUnstackDetachProcess(&ApcState);

  TargetMappedAddr = MmMapLockedPagesSpecifyCache(
      TargetMdl, PreviousMode, MmNonCached, NULL, FALSE, NormalPagePriority);
  if (TargetMappedAddr == NULL) {
    Status = STATUS_INSUFFICIENT_RESOURCES;
    goto Exit;
  }

  kmemmove(TargetMappedAddr, SourceMappedAddr, BufferSize);

  if (ReturnSize != NULL) {
    *ReturnSize = BufferSize;
  }

Exit:
  if (TargetMappedAddr != NULL) {
    MmUnmapLockedPages(TargetMappedAddr, TargetMdl);
    TargetMappedAddr = NULL;
  }
  if (TargetMdl != NULL) {
    MmUnlockPages(TargetMdl);
    if (bTargetMdlFromPool)
      MdlPoolRelease(TargetMdl);
    else
      IoFreeMdl(TargetMdl);
    TargetMdl = NULL;
  }
  if (SourceMappedAddr != NULL) {
    MmUnmapLockedPages(SourceMappedAddr, SourceMdl);
    SourceMappedAddr = NULL;
  }
  if (SourceMdl != NULL) {
    MmUnlockPages(SourceMdl);
    if (bSourceMdlFromPool)
      MdlPoolRelease(SourceMdl);
    else
      IoFreeMdl(SourceMdl);
    SourceMdl = NULL;
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
