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

#define USUGUMO_SIGNATURE 0xA5ULL
#define USUGUMO_SIGNATURE_SHIFT 56
#define USUGUMO_FUNC_BITS 0x000000000000FFFFULL
#define USUGUMO_SIGNATURE_MASK (USUGUMO_SIGNATURE << USUGUMO_SIGNATURE_SHIFT)

#define USUGUMO_PROBE (0x01ULL << 0)
#define USUGUMO_READ (0x01ULL << 1)
#define USUGUMO_WRITE (0x01ULL << 2)
#define USUGUMO_MOUSE (0x01ULL << 3)
#define USUGUMO_KEYBD (0x01ULL << 4)
#define USUGUMO_MODULE_BASE (0x01ULL << 5)
#define USUGUMO_MODULE_SIZE (0x01ULL << 6)
#define USUGUMO_PID (0x01ULL << 7)
#define USUGUMO_ANTI_CAPTURE (0x01ULL << 8)

#define USUGUMO_SUPPORTED_MASK                                     \
  (USUGUMO_PROBE | USUGUMO_READ | USUGUMO_WRITE | USUGUMO_MOUSE |  \
   USUGUMO_KEYBD | USUGUMO_MODULE_BASE | USUGUMO_MODULE_SIZE |     \
   USUGUMO_PID | USUGUMO_ANTI_CAPTURE)

static const unsigned long kIoctlCallDriver =
    CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0x721, METHOD_BUFFERED,
             FILE_READ_ACCESS | FILE_WRITE_ACCESS);

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
