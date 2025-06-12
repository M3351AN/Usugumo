#pragma once
#include <windef.h>
typedef int BOOL;
typedef ULONG_PTR QWORD;

#define RAISE_IRQL(a, b) *(b) = KfRaiseIrql(a)

#define DRIVER_READVM 0xCAFE1
#define DRIVER_WRITEVM 0xCAFE2
#define HID 0xCAFE3
#define DLL_BASE 0xCAFE4

static const UINT64 kMask = 0xFFFFFFFFFFF000;

static const ULONG kIoctlCallDriver =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[16];
  PVOID Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  PVOID Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PVOID ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID AtlThunkSListPtr;
  PVOID IFEOKey;
  PVOID CrossProcessFlags;
  PVOID KernelCallbackTable;
  ULONG SystemReserved;
  ULONG AtlThunkSListPtr32;
  PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#pragma pack(push, 1)
typedef struct _FixedStr64 {
  UINT64 blocks[4];
} FixedStr64;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct _Requests {
  // function requests
  int request_key;

  // memory read/write
  UINT64 src_pid;
  UINT64 src_addr;
  UINT64 dst_pid;
  UINT64 dst_addr;
  size_t size;

  // mouse_event
  DWORD dwFlags;
  DWORD dx;
  DWORD dy;
  DWORD dwData;
  ULONG_PTR dwExtraInfo;

  // return value
  UINT64 dll_base;

  // dllbase request
  FixedStr64 dll_name;
  SIZE_T dll_name_length;
} Requests;
#pragma pack(pop)