// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;  // offset 0x48
  UNICODE_STRING BaseDllName;  // offset 0x58
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

static PVOID g_NtoskrnlBase = NULL;

static BOOLEAN g_NtoskrnlResolved = FALSE;

static PVOID FindExportedSymbol(_In_ PVOID ImageBase, _In_ PCCH ExportName);

#pragma pack(push, 1)
typedef struct _MY_IDTR {
  USHORT Limit;
  ULONGLONG Base;
} MY_IDTR;

typedef struct _MY_KIDTENTRY64 {
  USHORT OffsetLow;
  USHORT Selector;
  UCHAR IstIndex;        /* IST + 3 reserved bits */
  UCHAR TypeAttributes;  /* Type + DPL + P */
  USHORT OffsetMiddle;
  ULONG OffsetHigh;
  ULONG Reserved;
} MY_KIDTENTRY64;
#pragma pack(pop)

static ULONGLONG FindIdtBaseFromKpcr(void) {
  return __readgsqword(0x38);
}

static ULONGLONG SearchBytes(ULONGLONG start, ULONGLONG maxLen,
                             const UCHAR* pat, SIZE_T len, UCHAR wildcard,
                             int dir) {
  for (ULONGLONG i = 0; i < maxLen; i++) {
    ULONGLONG addr = (dir > 0) ? (start + i) : (start - i);
    ULONGLONG p = addr;
    UINT matches = 1;
    for (SIZE_T j = 0; j < len; j++) {
      if (pat[j] != wildcard && (*(UCHAR*)p) != pat[j]) {
        matches = 0;
        break;
      }
      p += (ULONGLONG)dir;
    }
    if (matches) return addr;
  }
  return 0;
}

static ULONGLONG SearchInImage(ULONGLONG start, ULONGLONG maxLen,
                               const UCHAR* pat, SIZE_T len, UCHAR wildcard,
                               int dir) {
    return SearchBytes(start, maxLen, pat, len, wildcard, dir);
}

static ULONGLONG IdtHandlerOffset(MY_KIDTENTRY64* pIdt, UCHAR index) {
  return ((ULONGLONG)pIdt[index].OffsetLow) |
         ((ULONGLONG)pIdt[index].OffsetMiddle << 16) |
         ((ULONGLONG)pIdt[index].OffsetHigh << 32);
}

static PVOID FindNtoskrnlByIdt(void) {
  ULONGLONG idtBase = FindIdtBaseFromKpcr();
  if (idtBase == 0) return NULL;

  MY_KIDTENTRY64* pIdt = (MY_KIDTENTRY64*)idtBase;
  if (pIdt == NULL) return NULL;

  ULONGLONG handler = IdtHandlerOffset(pIdt, 0x00);
  if (handler == 0) return NULL;

  const UCHAR patJump[] = {0x0F, 0xAE, 0xE8, 0xE9};
  ULONGLONG jumpStart = SearchInImage(handler, 0x1000, patJump,
                                      sizeof(patJump), 0, +1);
  if (jumpStart != 0) {
    ULONGLONG e9 = jumpStart + 0x03;
    LONG disp = *(LONG*)(e9 + 0x01);
    handler = e9 + 0x05 + (LONG64)disp;
  }

  ULONGLONG rdata = 0;
  {
    const UCHAR patRdata1[] = {0x48, 0x8D, 0x35, 0xAA, 0xAA, 0xAA,
                               0xAA, 0x48, 0x8B, 0x44, 0xC6};
    ULONGLONG leaStart = SearchInImage(handler, 0x400000, patRdata1,
                                       sizeof(patRdata1), 0xAA, +1);
    if (leaStart) {
      LONG disp = *(LONG*)(leaStart + 0x03);
      rdata = leaStart + 0x07 + (LONG64)disp;
    }
  }
  if (rdata == 0) {
    // lea rax,[rip+disp32] ; mov qword ptr [r11-18h], 440042h ...
    const UCHAR patRdata2[] = {0x48, 0x8D, 0x05, 0xAA, 0xAA, 0xAA,
                               0xAA, 0x49, 0xC7, 0x43, 0xAA, 0xAA,
                               0xAA, 0xAA, 0xAA, 0x49};
    ULONGLONG leaStart = SearchInImage(handler, 0x400000, patRdata2,
                                       sizeof(patRdata2), 0xAA, +1);
    if (leaStart) {
      LONG disp = *(LONG*)(leaStart + 0x03);
      rdata = leaStart + 0x07 + (LONG64)disp;
    }
  }
  if (rdata == 0) return NULL;

  ULONGLONG scan = (rdata & ~(ULONGLONG)0xFFF) + 0x1000;
  for (;;) {
    scan -= 0x1000;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)scan;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)(scan + (dos->e_lfanew & 0xFFFF));
    if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
    if (nt->FileHeader.NumberOfSections < 0x18)
      continue;  // ntoskrnl has so fvcking many sections
    return (PVOID)scan;
  }
}

static PVOID FindNtoskrnlBase(/*_In_ PDRIVER_OBJECT DriverObject*/) {
  if (g_NtoskrnlResolved) return g_NtoskrnlBase;
  /*
  if (DriverObject != NULL && DriverObject->DriverSection != NULL) {
    PMY_LDR_DATA_TABLE_ENTRY self =
        (PMY_LDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PLIST_ENTRY head = &self->InLoadOrderLinks;
    for (PLIST_ENTRY entry = head->Flink; entry != head;
         entry = entry->Flink) {
      PMY_LDR_DATA_TABLE_ENTRY mod =
          CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY,
                            InLoadOrderLinks);
      if (mod->BaseDllName.Buffer == NULL) continue;
      // L"ntoskrnl.exe" 12*WCHAR
      if (mod->BaseDllName.Length != 12 * sizeof(WCHAR)) continue;
      if (kwcsicmp(mod->BaseDllName.Buffer, L"ntoskrnl.exe") != 0) continue;
      g_NtoskrnlBase = mod->DllBase;
      break;
    }
  }
  */

  // fallback
  if (g_NtoskrnlBase == NULL) {
    g_NtoskrnlBase = FindNtoskrnlByIdt();
  }

  g_NtoskrnlResolved = TRUE;
  return g_NtoskrnlBase;
}

static PVOID FindExportedSymbol(_In_ PVOID ImageBase,
                                _In_ PCCH ExportName) {
  if (ImageBase == NULL || ExportName == NULL) return NULL;

  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

  PIMAGE_NT_HEADERS nt =
      (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

  IMAGE_DATA_DIRECTORY expDir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL;

  PIMAGE_EXPORT_DIRECTORY exp =
      (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageBase + expDir.VirtualAddress);

  PDWORD nameRvas = (PDWORD)((PUCHAR)ImageBase + exp->AddressOfNames);
  PWORD ordinals = (PWORD)((PUCHAR)ImageBase + exp->AddressOfNameOrdinals);
  PDWORD functionRvas = (PDWORD)((PUCHAR)ImageBase + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; i++) {
    PCCH name = (PCCH)((PUCHAR)ImageBase + nameRvas[i]);
    if (kstricmp(name, ExportName) == 0) {
      DWORD ordinal = ordinals[i];
      return (PVOID)((PUCHAR)ImageBase + functionRvas[ordinal]);
    }
  }
  return NULL;
}

PVOID FindKernelProcAddress(_In_ PCCH ExportName) {
  if (g_NtoskrnlBase == NULL) return NULL;
  return FindExportedSymbol(g_NtoskrnlBase, ExportName);
}

fn_KeAcquireSpinLockAtDpcLevel _KeAcquireSpinLockAtDpcLevel;
fn_KeReleaseSpinLockFromDpcLevel _KeReleaseSpinLockFromDpcLevel;
fn_IofCompleteRequest _IofCompleteRequest;
fn_IoReleaseRemoveLockEx _IoReleaseRemoveLockEx;
fn_IoCreateDriver _IoCreateDriver;
fn_ObReferenceObjectByName _ObReferenceObjectByName;
fn_ObfReferenceObject _ObfReferenceObject;
fn_ObfDereferenceObject _ObfDereferenceObject;
fn_MmMapLockedPagesSpecifyCache _MmMapLockedPagesSpecifyCache;
fn_MmIsAddressValid _MmIsAddressValid;
fn_MmAllocateContiguousMemory _MmAllocateContiguousMemory;
fn_MmFreeContiguousMemory _MmFreeContiguousMemory;
fn_PsLookupProcessByProcessId _PsLookupProcessByProcessId;
fn_IoCreateSymbolicLink _IoCreateSymbolicLink;
fn_IoDeleteDevice _IoDeleteDevice;
fn_IoDeleteSymbolicLink _IoDeleteSymbolicLink;
fn_ExAllocatePool2 _ExAllocatePool2;
fn_ExFreePoolWithTag _ExFreePoolWithTag;
fn_ZwClose _ZwClose;
fn_ZwOpenKey _ZwOpenKey;
fn_ZwQueryValueKey _ZwQueryValueKey;
POBJECT_TYPE* _IoDriverObjectType;
PLIST_ENTRY _PsLoadedModuleList;
USHORT _NtBuildNumber;

NTSTATUS ResolveImports(/*_In_ PDRIVER_OBJECT DriverObject*/) {
  if (FindNtoskrnlBase(/*DriverObject*/) == NULL) {
    return STATUS_NOT_FOUND;
  }

  static PCCH func_names[] = {
      "KeAcquireSpinLockAtDpcLevel",
      "KeReleaseSpinLockFromDpcLevel",
      "IofCompleteRequest",
      "IoReleaseRemoveLockEx",
      "IoCreateDriver",
      "ObReferenceObjectByName",
      "ObfReferenceObject",
      "ObfDereferenceObject",
      "MmMapLockedPagesSpecifyCache",
      "MmIsAddressValid",
      "MmAllocateContiguousMemory",
      "MmFreeContiguousMemory",
      "PsLookupProcessByProcessId",
      "IoCreateSymbolicLink",
      "IoDeleteDevice",
      "IoDeleteSymbolicLink",
      "ExAllocatePool2",
      "ExFreePoolWithTag",
      "ZwClose",
      "ZwOpenKey",
      "ZwQueryValueKey",
  };
  PVOID* func_slots[] = {
      (PVOID*)&_KeAcquireSpinLockAtDpcLevel,
      (PVOID*)&_KeReleaseSpinLockFromDpcLevel,
      (PVOID*)&_IofCompleteRequest,
      (PVOID*)&_IoReleaseRemoveLockEx,
      (PVOID*)&_IoCreateDriver,
      (PVOID*)&_ObReferenceObjectByName,
      (PVOID*)&_ObfReferenceObject,
      (PVOID*)&_ObfDereferenceObject,
      (PVOID*)&_MmMapLockedPagesSpecifyCache,
      (PVOID*)&_MmIsAddressValid,
      (PVOID*)&_MmAllocateContiguousMemory,
      (PVOID*)&_MmFreeContiguousMemory,
      (PVOID*)&_PsLookupProcessByProcessId,
      (PVOID*)&_IoCreateSymbolicLink,
      (PVOID*)&_IoDeleteDevice,
      (PVOID*)&_IoDeleteSymbolicLink,
      (PVOID*)&_ExAllocatePool2,
      (PVOID*)&_ExFreePoolWithTag,
      (PVOID*)&_ZwClose,
      (PVOID*)&_ZwOpenKey,
      (PVOID*)&_ZwQueryValueKey,
  };

  for (ULONG i = 0; i < RTL_NUMBER_OF(func_names); i++) {
    PVOID address = FindKernelProcAddress(func_names[i]);
    if (address == NULL) {
      return STATUS_NOT_FOUND;
    }
    *func_slots[i] = address;
  }

  PVOID data_address = FindKernelProcAddress("IoDriverObjectType");
  if (data_address == NULL) {
    return STATUS_NOT_FOUND;
  }
  _IoDriverObjectType = *(POBJECT_TYPE**)data_address;

  PVOID list_address = FindKernelProcAddress("PsLoadedModuleList");
  if (list_address == NULL) {
    return STATUS_NOT_FOUND;
  }
  _PsLoadedModuleList = *(PLIST_ENTRY*)list_address;

  PVOID build_address = FindKernelProcAddress("NtBuildNumber");
  if (build_address == NULL) {
    return STATUS_NOT_FOUND;
  }
  _NtBuildNumber = (USHORT)(*(ULONG*)build_address & 0xFFFF);

  return STATUS_SUCCESS;
}
