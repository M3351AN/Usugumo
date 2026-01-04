// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_H_
#define _USUGUMO_H_
#include <Windows.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

#include "../../usugumo_request_define.h"

constexpr inline size_t kFixedStr64MaxLength = 64uz;
constexpr inline LPCSTR kDriverDevice = "\\\\.\\Usugum0";
constexpr inline uint64_t kSecureKey = 0xBEEFDEADFEEDCAFEULL;

using ProcessId = uint64_t;
using VirtualAddress = uintptr_t;
using MemorySize = size_t;
using DpiValue = int;
using ByteBuffer = std::byte*;
using ConstByteBuffer = const std::byte*;

class UsugumoDriver {
 public:
  UsugumoDriver() noexcept
      : driver_handle_(INVALID_HANDLE_VALUE),
        target_process_id_(0),
        current_process_id_(0),
        dpi_(0) {}

  ~UsugumoDriver() noexcept {
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(driver_handle_);
    }
  }

  UsugumoDriver(const UsugumoDriver&) = delete;
  UsugumoDriver& operator=(const UsugumoDriver&) = delete;

  UsugumoDriver(UsugumoDriver&& other) noexcept {
    *this = std::move(other);
  }

  UsugumoDriver& operator=(UsugumoDriver&& other) noexcept {
    if (this != &other) {
      driver_handle_ = other.driver_handle_;
      target_process_id_ = other.target_process_id_;
      current_process_id_ = other.current_process_id_;
      dpi_ = other.dpi_;

      other.driver_handle_ = INVALID_HANDLE_VALUE;
      other.target_process_id_ = 0;
      other.current_process_id_ = 0;
      other.dpi_ = 0;
    }
    return *this;
  }

  bool Initialize(ProcessId process_id) noexcept {
    if (!OpenDriverHandle()) {
      return false;
    }

    target_process_id_ = process_id;
    current_process_id_ = GetCurrentProcessId();
    return true;
  }

  bool Initialize(std::wstring_view process_name) noexcept {
    if (!OpenDriverHandle()) {
      return false;
    }

    const auto pid_opt = GetProcessIdByName(process_name);
    if (!pid_opt.has_value()) {
      return false;
    }

    target_process_id_ = *pid_opt;
    current_process_id_ = GetCurrentProcessId();
    return true;
  }

  bool DriverProbe() noexcept {
    if (!OpenDriverHandle()) {
      return false;
    }

    Requests request = {};
    request.request_key = USUGUMO_PROBE;

    SendIoctlRequest(request);
    return request.return_value != 0;
  }

  uint64_t GetDllSize(std::string_view dll_name) noexcept {
    return GetDllInfo<USUGUMO_MODULE_SIZE>(dll_name);
  }

  uint64_t GetDllBaseAddress(std::string_view dll_name) noexcept {
    return GetDllInfo<USUGUMO_MODULE_BASE>(dll_name);
  }

  bool ReadMemoryKm(VirtualAddress address, void* buffer, MemorySize size) noexcept {
    return ReadVirtualMemory(target_process_id_, address,
                             reinterpret_cast<VirtualAddress>(buffer), size);
  }

  bool WriteMemoryKm(VirtualAddress address, const void* buffer, MemorySize size) noexcept {
    return WriteVirtualMemory(target_process_id_, address,
                              reinterpret_cast<VirtualAddress>(buffer), size);
  }
  void MouseEvent(DWORD flags, DWORD x, DWORD y, DWORD data,
                  ULONG_PTR extra_info) noexcept {
    LONG dx = (LONG)x;
    LONG dy = (LONG)y;

    Requests request = {};
    request.request_key = USUGUMO_MOUSE;
    request.dwFlags = flags;
    request.dx = dx;
    request.dy = dy;
    request.dwData = data;
    request.dwExtraInfo = extra_info;

    SendIoctlRequest(request);
  }

  void MouseLeftDown() noexcept { MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); }

  void MouseLeftUp() noexcept { MouseEvent(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); }

  void MouseMove(DWORD x, DWORD y) noexcept {
    if (dpi_ == 0) {
      dpi_ = GetSystemDPI();
    }
    const DWORD dx = (x * 100u + dpi_ / 2) / dpi_;
    const DWORD dy = (y * 100u + dpi_ / 2) / dpi_;
    MouseEvent(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
  }

  void SetCursorPos(DWORD x, DWORD y) noexcept {
    const int screen_width = GetSystemMetrics(SM_CXSCREEN) - 1;
    const int screen_height = GetSystemMetrics(SM_CYSCREEN) - 1;
    const int virtual_x = (x * 65535u) / screen_width;
    const int virtual_y = (y * 65535u) / screen_height;
    MouseEvent(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, virtual_x, virtual_y, 0,
               0);
  }

  void KeybdEvent(BYTE vk, BYTE scan, DWORD flags,
                           ULONG_PTR extra_info) noexcept {
    Requests request = {};
    request.request_key = USUGUMO_KEYBD;
    request.bVK = vk;
    request.bScan = scan;
    request.dwFlags = flags;
    request.dwExtraInfo = extra_info;

    SendIoctlRequest(request);
  }

  void AntiCapture(HWND window_handle, bool status = true) noexcept {
    Requests request = {};
    request.request_key = USUGUMO_ANTI_CAPTURE;
    request.window_handle = window_handle;
    request.protect_flags = status ? 0xFFFFFFFFu : 0x00000000u;

    SendIoctlRequest(request);
  }

  HANDLE GetDriverHandle() const noexcept { return  driver_handle_; }
  ProcessId GetProcessId() const noexcept { return target_process_id_; }
 private:
  HANDLE driver_handle_;
  ProcessId target_process_id_;
  ProcessId current_process_id_;
  DpiValue dpi_;

unsigned __int64 CalculateRequestsChecksum(Requests* pRequest) {
  if (pRequest == NULL) {
    return 0;
  }
  // CRC64-ECMA
  const unsigned __int64 CRC64_POLYNOMIAL = 0x42F0E1EBA9EA3693ULL;
  static unsigned __int64 crc64_table[256] = {0};
  static BOOLEAN table_initialized = FALSE;

  if (!table_initialized) {
    for (unsigned int i = 0; i < 256; i++) {
      unsigned __int64 crc = (unsigned __int64)i;
      for (int j = 0; j < 8; j++) {
        if (crc & 1) {
          crc = (crc >> 1) ^ CRC64_POLYNOMIAL;
        } else {
          crc >>= 1;
        }
      }
      crc64_table[i] = crc;
    }
    table_initialized = TRUE;
  }

  unsigned __int64 validDataLen =
      sizeof(Requests) - sizeof(pRequest->check_sum);
  const unsigned char* pData = (const unsigned char*)pRequest;

  unsigned __int64 crc64 = 0xFFFFFFFFFFFFFFFFULL;
  for (unsigned __int64 i = 0; i < validDataLen; i++) {
    crc64 = crc64_table[(crc64 ^ pData[i]) & 0xFF] ^ (crc64 >> 8);
  }
  crc64 ^= 0xFFFFFFFFFFFFFFFFULL;
  return crc64;
}

  void SendIoctlRequest(Requests& request) noexcept {
    if (driver_handle_ == INVALID_HANDLE_VALUE) {
      return;
    }
    request.time_stamp = GetTimestamp();
    request.secure_key = kSecureKey;
    request.check_sum = CalculateRequestsChecksum(&request);
    DWORD bytes_returned = 0;
    DeviceIoControl(
        driver_handle_,
        kIoctlCallDriver,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytes_returned,
        nullptr
    );
  }

  template <uint64_t RequestKey>
  uint64_t GetDllInfo(std::string_view dll_name) noexcept {
    if (driver_handle_ == INVALID_HANDLE_VALUE) {
      return 0;
    }

    Requests request = {};
    request.request_key = RequestKey;
    request.target_pid = target_process_id_;

    const auto name_len = std::clamp(dll_name.size(), 0uz, kFixedStr64MaxLength);
    request.name_length = name_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(dll_name, &fixed_str);
    request.name_str = fixed_str;

    SendIoctlRequest(request);
    return request.return_value;
  }

  bool OpenDriverHandle() noexcept {
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      return true;
    }

    driver_handle_ = CreateFileA(kDriverDevice, GENERIC_READ, 0, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return driver_handle_ != INVALID_HANDLE_VALUE;
  }

  static DpiValue GetSystemDPI() noexcept {
    if (HDC hdc = GetDC(nullptr); hdc != nullptr) {
      const DpiValue dpi = GetDeviceCaps(hdc, LOGPIXELSX);
      ReleaseDC(nullptr, hdc);
      return dpi;
    }
    return 96;
  }

  void EncodeFixedStr64(std::string_view str, FixedStr64* fixed_str) noexcept {
    assert(fixed_str != nullptr);

    const auto str_len = std::clamp(str.size(), 0uz, kFixedStr64MaxLength);
    std::memset(fixed_str->blocks, 0, sizeof(fixed_str->blocks));

    for (size_t i = 0; i < str_len; ++i) {
      const size_t block_index = i / 8uz;
      const size_t pos_in_block = i % 8uz;
      const int shift = 8 * (7 - static_cast<int>(pos_in_block));
      const uint64_t char_val = static_cast<uint64_t>(static_cast<unsigned char>(str[i]));
      fixed_str->blocks[block_index] |= (char_val << shift);
    }
  }

  bool ReadVirtualMemory(ProcessId target_pid, VirtualAddress target_addr,
                         VirtualAddress request_addr, MemorySize size) noexcept {
    if (target_pid == 0 || target_addr == 0 || size == 0) {
      return false;
    }

    Requests request = {};
    request.request_key = USUGUMO_READ;
    request.request_pid = current_process_id_;
    request.request_addr = request_addr;
    request.target_pid = target_pid;
    request.target_addr = target_addr;
    request.mem_size = size;

    SendIoctlRequest(request);
    return request.return_value != 0;
  }

  bool WriteVirtualMemory(ProcessId target_pid, VirtualAddress target_addr,
                          VirtualAddress request_addr, MemorySize size) noexcept {
    if (target_pid == 0 || target_addr == 0 || size == 0) {
      return false;
    }

    Requests request = {};
    request.request_key = USUGUMO_WRITE;
    request.request_pid = current_process_id_;
    request.request_addr = request_addr;
    request.target_pid = target_pid;
    request.target_addr = target_addr;
    request.mem_size = size;

    SendIoctlRequest(request);
    return request.return_value != 0;
  }

  std::optional<DWORD> GetProcessIdByName(std::wstring_view process_name) noexcept {
    char ansi_process_name[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, process_name.data(), static_cast<int>(process_name.size()),
                        ansi_process_name, MAX_PATH, nullptr, nullptr);

    Requests request = {};
    request.request_key = USUGUMO_PID;

    const auto name_len = std::clamp(strlen(ansi_process_name), 0uz, kFixedStr64MaxLength);
    request.name_length = name_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(ansi_process_name, &fixed_str);
    request.name_str = fixed_str;

    SendIoctlRequest(request);
    const DWORD pid = static_cast<DWORD>(request.return_value);
    return pid != 0 ? std::optional<DWORD>(pid) : std::nullopt;
  }
};

#endif
