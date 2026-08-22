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
#include <unordered_map>

#include "./usugumo_request_define.h"

constexpr inline size_t kFixedStr64MaxLength = 64uz;
constexpr inline size_t kObfuscatedNameLen = 16;
constexpr inline LPCWSTR kObfuscatedChars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr inline uint64_t kSecureKey = 0xBEEFDEADFEEDCAFEULL;

using ProcessId = uint64_t;
using VirtualAddress = uintptr_t;
using MemorySize = size_t;
using DpiValue = int;
using ByteBuffer = std::byte*;
using ConstByteBuffer = const std::byte*;

inline void UsugumoSha256(const std::byte* data, size_t length,
                          std::byte* digest) {
  static constexpr uint32_t kK[64] = {
      0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL, 0x3956C25BUL,
      0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL, 0xD807AA98UL, 0x12835B01UL,
      0x243185BEUL, 0x550C7DC3UL, 0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL,
      0xC19BF174UL, 0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
      0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL, 0x983E5152UL,
      0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL, 0xC6E00BF3UL, 0xD5A79147UL,
      0x06CA6351UL, 0x14292967UL, 0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL,
      0x53380D13UL, 0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
      0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL, 0xD192E819UL,
      0xD6990624UL, 0xF40E3585UL, 0x106AA070UL, 0x19A4C116UL, 0x1E376C08UL,
      0x2748774CUL, 0x34B0BCB5UL, 0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL,
      0x682E6FF3UL, 0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
      0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL};

  auto rotr = [](uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
  };
  auto load_be = [](const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
  };

  uint32_t state[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
                       0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL};
  auto compress = [&](const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be(block + i * 4);
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
      uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = h + s1 + ch + kK[i] + w[i];
      uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  };

  const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
  size_t full = length / 64;
  for (size_t i = 0; i < full; i++) {
    compress(p);
    p += 64;
  }
  size_t rem = length % 64;
  uint8_t last[64];
  size_t ri = 0;
  for (; ri < rem; ri++) last[ri] = p[ri];
  last[ri++] = 0x80;
  uint64_t bit_len = static_cast<uint64_t>(length) * 8;
  if (ri > 56) {
    for (; ri < 64; ri++) last[ri] = 0;
    compress(last);
    for (ri = 0; ri < 56; ri++) last[ri] = 0;
  } else {
    for (; ri < 56; ri++) last[ri] = 0;
  }
  for (int i = 0; i < 8; i++) last[56 + i] = static_cast<uint8_t>(bit_len >> (56 - i * 8));
  compress(last);

  uint8_t* out = reinterpret_cast<uint8_t*>(digest);
  for (int i = 0; i < 8; i++) {
    out[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
    out[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
    out[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
    out[i * 4 + 3] = static_cast<uint8_t>(state[i]);
  }
}

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

  UsugumoDriver(UsugumoDriver&& other) noexcept { *this = std::move(other); }

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

    SendRequest(request);
    return request.return_value != 0;
  }

  uint64_t GetDllSize(std::string_view dll_name) noexcept {
    return GetDllInfo<USUGUMO_MODULE_SIZE>(dll_name);
  }

  uint64_t GetDllBaseAddress(std::string_view dll_name) noexcept {
    return GetDllInfo<USUGUMO_MODULE_BASE>(dll_name);
  }

  bool ReadMemoryKm(VirtualAddress address, void* buffer,
                    MemorySize size) noexcept {
    return ReadVirtualMemory(target_process_id_, address,
                             reinterpret_cast<VirtualAddress>(buffer), size);
  }

  bool WriteMemoryKm(VirtualAddress address, const void* buffer,
                     MemorySize size) noexcept {
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

    SendRequest(request);
  }

  void MouseLeftDown() noexcept {
    MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
  }

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

    SendRequest(request);
  }

  void AntiCapture(HWND window_handle, bool status = true) noexcept {
    Requests request = {};
    request.request_key = USUGUMO_ANTI_CAPTURE;
    request.window_handle = window_handle;
    request.protect_flags = status ? 0xFFFFFFFFu : 0x00000000u;

    SendRequest(request);
    // user-mode operations
    static std::unordered_map<HWND, LONG_PTR> old_ex_style;
    if (old_ex_style.find(window_handle) == old_ex_style.end()) {
        old_ex_style[window_handle] = GetWindowLongPtr(window_handle, GWL_EXSTYLE);
    }

    if (!status) {
        SetWindowLongPtr(window_handle, GWL_EXSTYLE, old_ex_style[window_handle]);
    }
    else {
        LONG_PTR ex_style = GetWindowLongPtr(window_handle, GWL_EXSTYLE);
        ex_style |= WS_EX_TOOLWINDOW;
        ex_style &= ~WS_EX_APPWINDOW;
        SetWindowLongPtr(window_handle, GWL_EXSTYLE, ex_style);
    }
    SetWindowPos(window_handle, NULL, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
  }

  HANDLE GetDriverHandle() const noexcept { return driver_handle_; }
  ProcessId GetProcessId() const noexcept { return target_process_id_; }

 private:
  HANDLE driver_handle_;
  ProcessId target_process_id_;
  ProcessId current_process_id_;
  DpiValue dpi_;
  wchar_t driver_device_path_[256] = {0};

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

  void SendRequest(Requests& request) noexcept {
    if (driver_handle_ == INVALID_HANDLE_VALUE) {
      return;
    }
    request.request_key |= USUGUMO_SIGNATURE_MASK;
    request.time_stamp = GetTimestamp();
    request.secure_key = kSecureKey;
    request.check_sum = CalculateRequestsChecksum(&request);
    
    DWORD dwWritten = 0, dwRead = 0;
    WriteFile(driver_handle_, &request, sizeof(Requests), &dwWritten, nullptr);
    if (dwWritten == sizeof(Requests)) {
      ReadFile(driver_handle_, &request, sizeof(Requests), &dwRead, nullptr);
    }
  }

  template <uint64_t RequestKey>
  uint64_t GetDllInfo(std::string_view dll_name) noexcept {
    if (driver_handle_ == INVALID_HANDLE_VALUE) {
      return 0;
    }

    Requests request = {};
    request.request_key = RequestKey;
    request.target_pid = target_process_id_;

    const auto name_len =
        std::clamp(dll_name.size(), 0uz, kFixedStr64MaxLength);
    request.name_length = name_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(dll_name, &fixed_str);
    request.name_str = fixed_str;

    SendRequest(request);
    return request.return_value;
  }

  bool GetBootVolumeSerial(char* out, size_t out_len) noexcept {
    if (!out || out_len < 9) return false;
    out[0] = '\0';

    char win_dir[MAX_PATH];
    if (!GetSystemWindowsDirectoryA(win_dir, MAX_PATH)) return false;

    char root[4];
    root[0] = win_dir[0];
    root[1] = win_dir[1];
    root[2] = win_dir[2];
    root[3] = '\0';

    DWORD serial = 0;
    if (!GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr,
                               nullptr, 0)) {
      return false;
    }

    static const char kHex[] = "0123456789ABCDEF";
    DWORD sn = serial;
    for (int i = 7; i >= 0; i--) {
      out[i] = kHex[sn & 0xF];
      sn >>= 4;
    }
    out[8] = '\0';
    return true;
  }

  bool GenerateObfuscatedName(const char* serial, size_t serial_len,
                              wchar_t* out, size_t out_len) noexcept {
    if (!out || out_len <= kObfuscatedNameLen || !serial || serial_len == 0) {
      return false;
    }
    if (serial_len > 8) serial_len = 8;

    static const char kSuffix[] = "Usugumo";
    std::byte input[8 + (sizeof(kSuffix) - 1)];
    for (size_t i = 0; i < serial_len; i++) {
      input[i] = static_cast<std::byte>(serial[i]);
    }
    for (size_t i = 0; i < sizeof(kSuffix) - 1; i++) {
      input[serial_len + i] = static_cast<std::byte>(kSuffix[i]);
    }

    std::byte digest[32];
    UsugumoSha256(input, serial_len + sizeof(kSuffix) - 1, digest);
    for (size_t i = 0; i < kObfuscatedNameLen; i++) {
      out[i] = kObfuscatedChars[static_cast<size_t>(digest[i]) % 36];
    }
    out[kObfuscatedNameLen] = L'\0';
    return true;
  }

  bool OpenDriverHandle() noexcept {
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
      return true;
    }

    char serial[128];
    if (!GetBootVolumeSerial(serial, ARRAYSIZE(serial))) {
      return false;
    }
    const size_t serial_len = strlen(serial);
    if (serial_len == 0) return false;

    wchar_t obfuscated[kObfuscatedNameLen + 1];
    if (!GenerateObfuscatedName(serial, serial_len, obfuscated,
                                kObfuscatedNameLen + 1)) {
      std::memset(serial, 0, sizeof(serial));
      return false;
    }
    std::memset(serial, 0, sizeof(serial));

    swprintf_s(driver_device_path_, ARRAYSIZE(driver_device_path_),
               L"\\\\.\\%s", obfuscated);
    std::memset(obfuscated, 0, sizeof(obfuscated));

    driver_handle_ = CreateFileW(
        driver_device_path_, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
        nullptr);
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
      const uint64_t char_val =
          static_cast<uint64_t>(static_cast<unsigned char>(str[i]));
      fixed_str->blocks[block_index] |= (char_val << shift);
    }
  }

  bool ReadVirtualMemory(ProcessId target_pid, VirtualAddress target_addr,
                         VirtualAddress request_addr,
                         MemorySize size) noexcept {
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

    SendRequest(request);
    return request.return_value != 0;
  }

  bool WriteVirtualMemory(ProcessId target_pid, VirtualAddress target_addr,
                          VirtualAddress request_addr,
                          MemorySize size) noexcept {
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

    SendRequest(request);
    return request.return_value != 0;
  }

  std::optional<DWORD> GetProcessIdByName(
      std::wstring_view process_name) noexcept {
    char ansi_process_name[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, process_name.data(),
                        static_cast<int>(process_name.size()),
                        ansi_process_name, MAX_PATH, nullptr, nullptr);

    Requests request = {};
    request.request_key = USUGUMO_PID;

    const auto name_len =
        std::clamp(strlen(ansi_process_name), 0uz, kFixedStr64MaxLength);
    request.name_length = name_len;

    FixedStr64 fixed_str;
    EncodeFixedStr64(ansi_process_name, &fixed_str);
    request.name_str = fixed_str;

    SendRequest(request);
    const DWORD pid = static_cast<DWORD>(request.return_value);
    return pid != 0 ? std::optional<DWORD>(pid) : std::nullopt;
  }
};

#endif
