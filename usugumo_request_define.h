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

#define USUGUMO_PROBE 0xCAFE0
#define USUGUMO_READ 0xCAFE1
#define USUGUMO_WRITE 0xCAFE2
#define USUGUMO_MOUSE 0xCAFE3
#define USUGUMO_MODULE_BASE 0xCAFE4
#define USUGUMO_MODULE_SIZE 0xCAFE5
#define USUGUMO_PID 0xCAFE6

static const unsigned long kIoctlCallDriver =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x721, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

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
  unsigned __int64 screen_width;
  unsigned __int64 screen_height;
  unsigned __int64 cursor_x;
  unsigned __int64 cursor_y;

  // base/pid request
  unsigned __int64 name_length;
  FixedStr64 name_str;
} Requests;
#pragma pack(pop)

#ifdef __cplusplus
}  // extern "C"
#endif
#endif
