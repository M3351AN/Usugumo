// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_REQUEST_DEFINE_H_
#define _USUGUMO_REQUEST_DEFINE_H_
#ifdef __cplusplus
extern "C" {
#endif

#define DRIVER_READVM 0xCAFE1
#define DRIVER_WRITEVM 0xCAFE2
#define HID 0xCAFE3
#define DLL_BASE 0xCAFE4
#define DLL_SIZE 0xCAFE5
#define PROCESS_PID 0xCAFE6

static const ULONG kIoctlCallDriver =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

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
  UINT64 return_value;

  // base/pid request
  FixedStr64 module_name;
  SIZE_T name_length;
} Requests;
#pragma pack(pop)

#ifdef __cplusplus
}  // extern "C"
#endif
#endif