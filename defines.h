// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _DEFINES_H_
#define _DEFINES_H_
#include <windef.h>

typedef int BOOL;
typedef ULONG_PTR QWORD;

#define RAISE_IRQL(a, b) *(b) = KfRaiseIrql(a)
#define SDDL_STRING L"D:P(A;;GA;;;WD)"

#define MOUSEEVENTF_MOVE 0x0001       /* mouse move */
#define MOUSEEVENTF_LEFTDOWN 0x0002   /* left button down */
#define MOUSEEVENTF_LEFTUP 0x0004     /* left button up */
#define MOUSEEVENTF_RIGHTDOWN 0x0008  /* right button down */
#define MOUSEEVENTF_RIGHTUP 0x0010    /* right button up */
#define MOUSEEVENTF_MIDDLEDOWN 0x0020 /* middle button down */
#define MOUSEEVENTF_MIDDLEUP 0x0040   /* middle button up */
#define MOUSEEVENTF_XDOWN 0x0080      /* x button down */
#define MOUSEEVENTF_XUP 0x0100        /* x button down */
#define MOUSEEVENTF_WHEEL 0x0800      /* wheel button rolled */
#define MOUSEEVENTF_ABSOLUTE 0x8000

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

#pragma warning(disable : 4201)
typedef struct _MOUSE_INPUT_DATA {
  USHORT UnitId;
  USHORT Flags;
  union {
    ULONG Buttons;
    struct {
      USHORT ButtonFlags;
      USHORT ButtonData;
    };
  };
  ULONG RawButtons;
  LONG LastX;
  LONG LastY;
  ULONG ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

typedef VOID (*MouseClassServiceCallbackFn)(PDEVICE_OBJECT DeviceObject,
                                            PMOUSE_INPUT_DATA InputDataStart,
                                            PMOUSE_INPUT_DATA InputDataEnd,
                                            PULONG InputDataConsumed);

typedef struct _MOUSE_OBJECT {
  PDEVICE_OBJECT mouse_device;
  MouseClassServiceCallbackFn service_callback;
  BOOL use_mouse;
} MOUSE_OBJECT, *PMOUSE_OBJECT;

#endif
