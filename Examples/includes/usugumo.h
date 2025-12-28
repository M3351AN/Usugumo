// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_H_
#define _USUGUMO_H_
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "../../usugumo_request_define.h"

class UsugumoDriver {
 public:
  UsugumoDriver()
      : driver_handle_(INVALID_HANDLE_VALUE),
        target_process_id_(0),
        current_process_id_(0) {}

  ~UsugumoDriver() {
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(driver_handle_);
    }
  }

  bool Initialize(uint64_t process_id) {
    driver_handle_ = CreateFileA("\\\\.\\Usugum0", GENERIC_READ, 0, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      target_process_id_ = process_id;
      current_process_id_ = GetCurrentProcessId();
      return true;
    }
    return false;
  }

  bool Initialize(const wchar_t* process_name) {
    driver_handle_ = CreateFileA("\\\\.\\Usugum0", GENERIC_READ, 0, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD pid = GetProcessIdByName(process_name);
    if (pid == 0) {
      return false;
    }
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      target_process_id_ = pid;
      current_process_id_ = GetCurrentProcessId();
      return true;
    }
    return false;
  }

  bool DriverProbe() {
    Requests request = {};
    request.request_key = kProbe;
    DWORD bytes_returned;
    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      return request.return_value;
    }

    return false;
  }

  uint64_t GetDllSize(const char* dll_name) {
    Requests request = {};
    request.request_key = kDllSize;
    request.target_pid = target_process_id_;

    size_t original_len = strlen(dll_name);
    if (original_len > 64) original_len = 64;
    request.name_length = original_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(dll_name, &fixed_str);
    request.name_str = fixed_str;

    DWORD bytes_returned;

    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      return request.return_value;
    }

    return 0;
  }

  uint64_t GetDllBaseAddress(const char* dll_name) {
    Requests request = {};
    request.request_key = kDllBase;
    request.target_pid = target_process_id_;

    size_t original_len = strlen(dll_name);
    if (original_len > 64) original_len = 64;
    request.name_length = original_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(dll_name, &fixed_str);
    request.name_str = fixed_str;

    DWORD bytes_returned;

    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      return request.return_value;
    }

    return 0;
  }

  bool ReadMemoryKm(uintptr_t address, void* buffer, size_t size) {
    return ReadVirtualMemory(target_process_id_, address,
                             reinterpret_cast<uintptr_t>(buffer), size);
  }

  bool WriteMemoryKm(uintptr_t address, const void* buffer, size_t size) {
    return WriteVirtualMemory(target_process_id_, address,
                              reinterpret_cast<uintptr_t>(buffer), size);
  }
  void MouseEvent(DWORD flags, DWORD x, DWORD y, DWORD data,
                  ULONG_PTR extra_info) {
    LONG dx = (LONG)x;
    LONG dy = (LONG)y;

    Requests request = {};
    request.request_key = kMouse;
    request.dwFlags = flags;
    request.dx = dx;
    request.dy = dy;
    request.dwData = data;
    request.dwExtraInfo = extra_info;

    DeviceIoControl(driver_handle_, kIoctlCallDriver, &request, sizeof(request),
                    nullptr, 0, nullptr, nullptr);
  }

  void MouseLeftDown() { MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); }

  void MouseLeftUp() { MouseEvent(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); }

  void MouseMove(DWORD x, DWORD y) {
    if (dpi_ == 0) dpi_ = GetSystemDPI();
    DWORD dx = (x * 100 + dpi_ / 2) / dpi_;
    DWORD dy = (y * 100 + dpi_ / 2) / dpi_;
    MouseEvent(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
  }

  void SetCursorPos(DWORD x, DWORD y) {
    int screen_width = GetSystemMetrics(SM_CXSCREEN) - 1;
    int screen_height = GetSystemMetrics(SM_CYSCREEN) - 1;
    int virtual_x = (x * 65535) / screen_width;
    int virtual_y = (y * 65535) / screen_height;
    MouseEvent(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, virtual_x, virtual_y, 0,
               0);
  }

 private:
  enum RequestCode {
    kProbe = USUGUMO_PROBE,
    kReadVM = USUGUMO_READ,
    kWriteVM = USUGUMO_WRITE,
    kMouse = USUGUMO_MOUSE,
    kDllBase = USUGUMO_MODULE_BASE,
    kDllSize = USUGUMO_MODULE_SIZE,
    kPID = USUGUMO_PID
  };
  HANDLE driver_handle_;
  uint64_t target_process_id_;
  uint64_t current_process_id_;
  int dpi_ = 0;

  static int GetSystemDPI() {
    HDC hdc = GetDC(nullptr);
    int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    ReleaseDC(nullptr, hdc);
    return dpi;
  }

  void EncodeFixedStr64(const char* str, FixedStr64* fixed_str) {
    size_t len = strlen(str);
    if (len > 64) {
      len = 64;
    }

    memset(fixed_str->blocks, 0, sizeof(fixed_str->blocks));

    for (size_t i = 0; i < len; i++) {
      size_t block_index = i / 8;
      size_t pos_in_block = i % 8;
      int shift = 8 * (7 - pos_in_block);
      fixed_str->blocks[block_index] |=
          (static_cast<uint64_t>(static_cast<unsigned char>(str[i])) << shift);
    }
  }

  bool ReadVirtualMemory(uint64_t target_pid, uint64_t target_addr,
                         uint64_t request_addr, size_t size) {
    if (target_pid == 0 || target_addr == 0) return false;

    Requests request = {};
    request.request_key = kReadVM;
    request.request_pid = current_process_id_;
    request.request_addr = request_addr;
    request.target_pid = target_pid;
    request.target_addr = target_addr;
    request.mem_size = size;

    DWORD bytes_returned;

    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      return request.return_value;
    }
    return false;
  }

  bool WriteVirtualMemory(uint64_t target_pid, uint64_t target_addr,
                          uint64_t request_addr, size_t size) {
    if (target_pid == 0 || target_addr == 0) return false;

    Requests request = {};
    request.request_key = kWriteVM;
    request.request_pid = current_process_id_;
    request.request_addr = request_addr;
    request.target_pid = target_pid;
    request.target_addr = target_addr;
    request.mem_size = size;

    DWORD bytes_returned;

    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      return request.return_value;
    }
    return false;
  }

  DWORD GetProcessIdByName(const wchar_t* process_name) {
    char ansi_process_name[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, process_name, -1, ansi_process_name,
                        MAX_PATH, nullptr, nullptr);

    Requests request = {};
    request.request_key = kPID;

    size_t name_len = strlen(ansi_process_name);
    if (name_len > 64) name_len = 64;
    request.name_length = name_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(ansi_process_name, &fixed_str);
    request.name_str = fixed_str;

    DWORD bytes_returned = 0;
    DWORD found_pid = 0;
    if (DeviceIoControl(driver_handle_, kIoctlCallDriver, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytes_returned, nullptr)) {
      found_pid = static_cast<DWORD>(request.return_value);
    }
    return found_pid;
  }
};

#endif
