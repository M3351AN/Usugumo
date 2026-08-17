// Copyright (c) 2026 渟雲. All rights reserved.
// Cross-process memory read/write via CR3 + page table walk + physical I/O.
// Ported from Valthrun valthrun-driver-kernel driver/src/pmem.rs
#include "./common.h"

// Mask for the physical frame bits of a page table entry.
#define PMEM_PMASK 0x000FFFFFFFFFF000ULL
#define PMEM_PAGE_OFFSET_SIZE 12

extern ULONG g_UserDirectoryTableBaseOffset;

NTSTATUS ReadPhysical(UINT64 PhysicalAddress, PVOID Buffer, SIZE_T Size,
                      PSIZE_T BytesRead) {
  if (Size == 0) return STATUS_SUCCESS;
  PHYSICAL_ADDRESS phys;
  phys.QuadPart = (LONGLONG)PhysicalAddress;
  PVOID mapped = _MmMapIoSpace(phys, Size, MmCached);
  if (mapped == NULL) return STATUS_INSUFFICIENT_RESOURCES;
  kmemmove(Buffer, mapped, Size);
  _MmUnmapIoSpace(mapped, Size);
  if (BytesRead != NULL) *BytesRead = Size;
  return STATUS_SUCCESS;
}

NTSTATUS WritePhysical(UINT64 PhysicalAddress, const void* Buffer,
                       SIZE_T Size) {
  if (Size == 0) return STATUS_SUCCESS;
  PHYSICAL_ADDRESS phys;
  phys.QuadPart = (LONGLONG)PhysicalAddress;
  PVOID mapped = _MmMapIoSpace(phys, Size, MmCached);
  if (mapped == NULL) return STATUS_INSUFFICIENT_RESOURCES;
  kmemmove(mapped, Buffer, Size);
  _MmUnmapIoSpace(mapped, Size);
  return STATUS_SUCCESS;
}

static UINT64 ReadPhysicalU64(UINT64 PhysicalAddress) {
  UINT64 value = 0;
  SIZE_T done = 0;
  MM_COPY_ADDRESS address;
  address.PhysicalAddress.QuadPart = (LONGLONG)PhysicalAddress;
  NTSTATUS status = _MmCopyMemory(&value, address, sizeof(value),
                                  MM_COPY_MEMORY_PHYSICAL, &done);
  if (!NT_SUCCESS(status)) return 0;
  return value;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase,
                              UINT64 VirtualAddress) {
  DirectoryTableBase &= ~0xFULL;
  UINT64 pageOffset = VirtualAddress & ~(~0ULL << PMEM_PAGE_OFFSET_SIZE);
  UINT64 pte = (VirtualAddress >> 12) & 0x1FF;
  UINT64 pt = (VirtualAddress >> 21) & 0x1FF;
  UINT64 pd = (VirtualAddress >> 30) & 0x1FF;
  UINT64 pdp = (VirtualAddress >> 39) & 0x1FF;

  UINT64 pdpValue = ReadPhysicalU64(DirectoryTableBase + pdp * 0x08);
  if (!(pdpValue & 0x01)) return 0;

  UINT64 pdValue = ReadPhysicalU64((pdpValue & PMEM_PMASK) + pd * 0x08);
  if (!(pdValue & 0x01)) return 0;
  if (pdValue & 0x80) {
    /* 1GB large page, use pde's 12-34 bits */
    return (pdValue & (0xFFFFFFFFFFFFFFFFULL << 42 >> 12)) +
           (VirtualAddress & ~(~0ULL << 30));
  }

  UINT64 ptValue = ReadPhysicalU64((pdValue & PMEM_PMASK) + pt * 0x08);
  if (!(ptValue & 0x01)) return 0;
  if (ptValue & 0x80) {
    /* 2MB large page */
    return (ptValue & PMEM_PMASK) + (VirtualAddress & ~(~0ULL << 21));
  }

  UINT64 pteValue =
      ReadPhysicalU64((ptValue & PMEM_PMASK) + pte * 0x08) & PMEM_PMASK;
  if (pteValue == 0) return 0;
  return pteValue + pageOffset;
}

UINT64 GetProcessCr3(PEPROCESS Process) {
  if (Process == NULL) return 0;
  // KPROCESS.DirectoryTableBase is at offset 0x28 on x64 (stable).
  UINT64 dtb = *(volatile UINT64*)((UINT_PTR)Process + 0x28);
  if (dtb != 0) return dtb;
  // Fall back to UserDirectoryTableBase (KPTI user-mode CR3).
  if (g_UserDirectoryTableBaseOffset == 0) {
    if (!InitOffsetsByVersion()) return 0;
  }
  return *(volatile UINT64*)((UINT_PTR)Process +
                             g_UserDirectoryTableBaseOffset);
}

NTSTATUS ReadProcessMemory(PEPROCESS Process, UINT64 VirtualAddress,
                           PVOID Buffer, SIZE_T Size) {
  if (Process == NULL || Buffer == NULL) return STATUS_INVALID_PARAMETER;
  UINT64 dtb = GetProcessCr3(Process);
  if (dtb == 0) return STATUS_INVALID_PARAMETER;

  UINT8* dst = (UINT8*)Buffer;
  SIZE_T offset = 0;
  while (offset < Size) {
    SIZE_T remaining = Size - offset;
    UINT64 va = VirtualAddress + offset;
    SIZE_T chunk = PMEM_PAGE_SIZE - (SIZE_T)(va & (PMEM_PAGE_SIZE - 1));
    if (chunk > remaining) chunk = remaining;

    UINT64 phys = TranslateLinearAddress(dtb, va);
    if (phys == 0) return STATUS_PARTIAL_COPY;

    SIZE_T done = 0;
    NTSTATUS status = ReadPhysical(phys, dst + offset, chunk, &done);
    if (!NT_SUCCESS(status)) return status;
    offset += chunk;
  }
  return STATUS_SUCCESS;
}

NTSTATUS WriteProcessMemory(PEPROCESS Process, UINT64 VirtualAddress,
                            const void* Buffer, SIZE_T Size) {
  if (Process == NULL || Buffer == NULL) return STATUS_INVALID_PARAMETER;
  UINT64 dtb = GetProcessCr3(Process);
  if (dtb == 0) return STATUS_INVALID_PARAMETER;

  const UINT8* src = (const UINT8*)Buffer;
  SIZE_T offset = 0;
  while (offset < Size) {
    SIZE_T remaining = Size - offset;
    UINT64 va = VirtualAddress + offset;
    SIZE_T chunk = PMEM_PAGE_SIZE - (SIZE_T)(va & (PMEM_PAGE_SIZE - 1));
    if (chunk > remaining) chunk = remaining;

    UINT64 phys = TranslateLinearAddress(dtb, va);
    if (phys == 0) return STATUS_PARTIAL_COPY;

    NTSTATUS status = WritePhysical(phys, src + offset, chunk);
    if (!NT_SUCCESS(status)) return status;
    offset += chunk;
  }
  return STATUS_SUCCESS;
}

NTSTATUS CopyVirtualMemory(PEPROCESS FromProcess, UINT64 FromAddress,
                           PEPROCESS ToProcess, UINT64 ToAddress, SIZE_T Size) {
  if (FromProcess == NULL || ToProcess == NULL || Size == 0)
    return STATUS_INVALID_PARAMETER;

  UINT64 fromDtb = GetProcessCr3(FromProcess);
  UINT64 toDtb = GetProcessCr3(ToProcess);
  if (fromDtb == 0 || toDtb == 0) return STATUS_INVALID_PARAMETER;

  UINT8* scratch =
      (UINT8*)_ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                               PMEM_PAGE_SIZE, 0x446C6148);
  if (scratch == NULL) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  NTSTATUS status = STATUS_SUCCESS;
  SIZE_T offset = 0;

  while (offset < Size) {
    SIZE_T remaining = Size - offset;
    UINT64 fva = FromAddress + offset;
    UINT64 tva = ToAddress + offset;

    SIZE_T chunk = PMEM_PAGE_SIZE - (SIZE_T)(fva & (PMEM_PAGE_SIZE - 1));
    SIZE_T chunk2 = PMEM_PAGE_SIZE - (SIZE_T)(tva & (PMEM_PAGE_SIZE - 1));
    if (chunk2 < chunk) chunk = chunk2;
    if (chunk > remaining) chunk = remaining;

    UINT64 fphys = TranslateLinearAddress(fromDtb, fva);
    if (fphys == 0) {
      status = STATUS_PARTIAL_COPY;
      goto Cleanup;
    }

    SIZE_T done = 0;
    status = ReadPhysical(fphys, scratch, chunk, &done);
    if (!NT_SUCCESS(status)) {
      goto Cleanup;
    }

    UINT64 tphys = TranslateLinearAddress(toDtb, tva);
    if (tphys == 0) {
      status = STATUS_PARTIAL_COPY;
      goto Cleanup;
    }

    status = WritePhysical(tphys, scratch, chunk);
    if (!NT_SUCCESS(status)) {
      goto Cleanup;
    }

    offset += chunk;
  }

Cleanup:
  RtlSecureZeroMemory(scratch, PMEM_PAGE_SIZE);
  _ExFreePoolWithTag(scratch, 0x446C6148);

  return status;
}
