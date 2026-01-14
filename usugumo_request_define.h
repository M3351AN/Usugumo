// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_REQUEST_DEFINE_H_
#define _USUGUMO_REQUEST_DEFINE_H_
#ifdef __cplusplus
extern "C" {
#endif
#ifndef CTL_CODE
#include <winioctl.h>
#endif  // !CTL_CODE

#define USUGUMO_PROBE 0x0CAFEFEED
#define USUGUMO_READ 0x1CAFEFEED
#define USUGUMO_WRITE 0x2CAFEFEED
#define USUGUMO_MOUSE 0x3CAFEFEED
#define USUGUMO_KEYBD 0x4CAFEFEED
#define USUGUMO_MODULE_BASE 0x5CAFEFEED
#define USUGUMO_MODULE_SIZE 0x6CAFEFEED
#define USUGUMO_PID 0x7CAFEFEED
#define USUGUMO_ANTI_CAPTURE 0x8CAFEFEED

static const unsigned long kIoctlCallDriver =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x721, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>
#else
#include <windows.h>
#endif

#define TICKS_PER_SECOND 10000000LL  // 100NS

__forceinline unsigned __int64 GetTimestamp(void) {
#ifdef _KERNEL_MODE
  LARGE_INTEGER time;
  KeQuerySystemTime(&time);
  return time.QuadPart;
#else
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return ((LONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
#endif
}

__forceinline BOOLEAN IsTimestampValid(unsigned __int64 ts,
                                       LONGLONG tolerance_seconds) {
  unsigned __int64 current = GetTimestamp();
  unsigned __int64 tolerance_ticks = tolerance_seconds * TICKS_PER_SECOND;

  if (ts > current) {
    return (ts - current) <= tolerance_ticks;
  } else {
    return (current - ts) <= tolerance_ticks;
  }
}

#pragma pack(push, 1)
typedef struct _FixedStr64 {
  unsigned __int64 blocks[8];
} FixedStr64;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct _Requests {
  // function requests
  unsigned __int64 request_key;

  // return value
  unsigned __int64 return_value;

  // memory read/write
  unsigned __int64 request_pid;
  unsigned __int64 request_addr;
  unsigned __int64 target_pid;
  unsigned __int64 target_addr;
  unsigned __int64 mem_size;

  // mouse_event
  unsigned long dwFlags;
  unsigned long dx;
  unsigned long dy;
  unsigned long dwData;
  unsigned __int64 dwExtraInfo;

  // keybd_event
  unsigned short bVK;
  unsigned short bScan;

  // base/pid request
  unsigned __int64 name_length;
  FixedStr64 name_str;

  // anti capture
  HWND window_handle;
  unsigned int protect_flags;

  unsigned __int64 time_stamp;
  unsigned __int64 secure_key;
  unsigned __int64 check_sum;
} Requests, *PRequests;
#pragma pack(pop)

#ifdef __cplusplus
}  // extern "C"
#endif
#endif
