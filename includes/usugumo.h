// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_H_
#define _USUGUMO_H_
#include "./wsk_client.h"
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
      : target_process_id_(0),
        current_process_id_(0),
        dpi_(0) {}

  ~UsugumoDriver() noexcept { connection_.Close(); }

  UsugumoDriver(const UsugumoDriver&) = delete;
  UsugumoDriver& operator=(const UsugumoDriver&) = delete;

  UsugumoDriver(UsugumoDriver&& other) noexcept { *this = std::move(other); }

  UsugumoDriver& operator=(UsugumoDriver&& other) noexcept {
    if (this != &other) {
      target_process_id_ = other.target_process_id_;
      current_process_id_ = other.current_process_id_;
      dpi_ = other.dpi_;

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
    driver_protocol_version_ = static_cast<uint16_t>(
        (request.return_value >> USUGUMO_PROTOCOL_VERSION_SHIFT) &
        USUGUMO_PROTOCOL_VERSION_MASK);
    supported_functions_ = static_cast<uint16_t>(
        request.return_value & USUGUMO_FUNC_BITS);
    return supported_functions_ != 0;
  }

  bool IsProtocolMismatch() const noexcept {
    return driver_protocol_version_ > USUGUMO_PROTOCOL_VERSION;
  }
  uint16_t GetDriverProtocolVersion() const noexcept {
    return driver_protocol_version_;
  }
  uint16_t GetSupportedFunctions() const noexcept { return supported_functions_; }

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
    request.request_pid = current_process_id_;
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

  bool IsConnected() const noexcept { return connection_.IsConnected(); }
  uint16_t GetPort() const noexcept { return used_port_; }
  ProcessId GetProcessId() const noexcept { return target_process_id_; }

  usugumo_wsk::WskConnection::LastError GetLastTransportError() const noexcept {
    return connection_.GetLastError();
  }
  int GetLastWsaError() const noexcept { return connection_.GetLastWsaError(); }
  const char* DescribeLastTransportError() const noexcept {
    return usugumo_wsk::WskConnection::DescribeError(connection_.GetLastError());
  }
  uint16_t GetDerivedPort() const noexcept { return usugumo_wsk::DerivePort(); }

 private:
  usugumo_wsk::WskConnection connection_;
  ProcessId target_process_id_;
  ProcessId current_process_id_;
  DpiValue dpi_;
  uint16_t used_port_ = 0;
  uint16_t driver_protocol_version_ = 0;
  uint16_t supported_functions_ = 0;
  uint16_t response_version_ = 0;

  static unsigned __int64 Crc64(const std::byte* data, size_t length) noexcept {
    constexpr unsigned __int64 kPoly = 0x85E1C3D753D46D27ULL;
    static unsigned __int64 table[256] = {0};
    static bool initialized = false;
    if (!initialized) {
      for (unsigned i = 0; i < 256; i++) {
        unsigned __int64 c = i;
        for (int j = 0; j < 8; j++) {
          if (c & 1) {
            c ^= kPoly;
          }
          c >>= 1;
        }
        table[i] = c;
      }
      initialized = true;
    }
    unsigned __int64 crc = 0xFFFFFFFFFFFFFFFFULL;
    for (size_t i = 0; i < length; i++) {
      crc = table[(crc ^ static_cast<unsigned char>(data[i])) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
  }

  bool EncodeRequest(const Requests& request, std::string& out) noexcept {
    out = SerializeRequest(request, 0);
    const unsigned __int64 sum = Crc64(reinterpret_cast<const std::byte*>(out.data()),
                                       out.size());
    out = SerializeRequest(request, sum);
    return !out.empty();
  }

  static uint32_t Xxh32(std::string_view input) noexcept {
    constexpr uint32_t kP1 = 0x9E3779B1u, kP2 = 0x85EBCA77u, kP3 = 0xC2B2AE3Du,
                       kP4 = 0x27D4EB2Fu, kP5 = 0x165667B1u;
    const auto rotl = [](uint32_t x, int r) {
      return (x << r) | (x >> (32 - r));
    };
    const auto rd32 = [](const unsigned char* p) {
      return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
             (static_cast<uint32_t>(p[2]) << 16) |
             (static_cast<uint32_t>(p[3]) << 24);
    };
    const auto round = [&](uint32_t acc, uint32_t v) {
      return rotl(acc + v * kP2, 13) * kP1;
    };

    const auto* b = reinterpret_cast<const unsigned char*>(input.data());
    const size_t len = input.size();
    size_t i = 0;
    uint32_t h;
    if (len >= 16) {
      uint32_t v1 = kP1 + kP2, v2 = kP2, v3 = 0, v4 = 0u - kP1;
      while (i + 16 <= len) {
        v1 = round(v1, rd32(b + i));
        v2 = round(v2, rd32(b + i + 4));
        v3 = round(v3, rd32(b + i + 8));
        v4 = round(v4, rd32(b + i + 12));
        i += 16;
      }
      h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    } else {
      h = kP5;
    }
    h += static_cast<uint32_t>(len);
    while (i + 4 <= len) {
      h = rotl(h + rd32(b + i) * kP3, 17) * kP4;
      i += 4;
    }
    while (i < len) {
      h = rotl(h + static_cast<uint32_t>(b[i]) * kP5, 11) * kP1;
      i += 1;
    }
    h ^= h >> 15;
    h *= kP2;
    h ^= h >> 13;
    h *= kP3;
    h ^= h >> 16;
    return h;
  }

  static std::string WireKey(std::string_view name) noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    const uint32_t tag = Xxh32(name);
    std::string out(8, '0');
    for (int i = 0; i < 8; i++) {
      out[i] = kHex[(tag >> (28 - 4 * i)) & 0xF];
    }
    return out;
  }

  static void AppendField(std::string& s, std::string_view key,
                          unsigned __int64 value) noexcept {
    s.append(WireKey(key));
    s.push_back('=');
    s.append(std::to_string(value));
    s.push_back('\n');
  }

  static std::string SerializeRequest(const Requests& r,
                                      unsigned __int64 checksum) noexcept {
    std::string s;
    s.reserve(320);
    AppendField(s, "v", USUGUMO_PROTOCOL_VERSION);
    AppendField(s, "fn", r.request_key & USUGUMO_FUNC_BITS);
    AppendField(s, "ret", r.return_value);
    AppendField(s, "ck", checksum);
    AppendField(s, "ts", r.time_stamp);
    AppendField(s, "sk", r.secure_key);
    if (r.request_pid != 0) {
      AppendField(s, "rpid", r.request_pid);
    }
    if (r.request_addr != 0) {
      AppendField(s, "raddr", r.request_addr);
    }
    if (r.target_pid != 0) {
      AppendField(s, "tpid", r.target_pid);
    }
    if (r.target_addr != 0) {
      AppendField(s, "taddr", r.target_addr);
    }
    if (r.mem_size != 0) {
      AppendField(s, "sz", r.mem_size);
    }
    if (r.dwFlags != 0) {
      AppendField(s, "fl", r.dwFlags);
    }
    if (r.dx != 0) {
      AppendField(s, "dx", r.dx);
    }
    if (r.dy != 0) {
      AppendField(s, "dy", r.dy);
    }
    if (r.dwData != 0) {
      AppendField(s, "dd", r.dwData);
    }
    if (r.dwExtraInfo != 0) {
      AppendField(s, "ex", r.dwExtraInfo);
    }
    if (r.bVK != 0) {
      AppendField(s, "vk", r.bVK);
    }
    if (r.bScan != 0) {
      AppendField(s, "sc", r.bScan);
    }
    if (r.window_handle != 0) {
      AppendField(s, "wh", reinterpret_cast<uintptr_t>(r.window_handle));
    }
    if (r.protect_flags != 0) {
      AppendField(s, "pf", r.protect_flags);
    }
    if (r.name_length != 0) {
      char decoded[65] = {0};
      const size_t n = r.name_length > 64 ? 64 : static_cast<size_t>(r.name_length);
      for (size_t i = 0; i < n; i++) {
        const unsigned shift = static_cast<unsigned>(8 * (7 - (i % 8)));
        decoded[i] = static_cast<char>((r.name_str.blocks[i / 8] >> shift) & 0xFF);
      }
      s.append(WireKey("nm"));
      s.push_back('=');
      for (size_t i = 0; i < n; i++) {
        const unsigned char c = static_cast<unsigned char>(decoded[i]);
        if (c >= 0x20 && c != 0x7F) {
          s.push_back(static_cast<char>(c));
        }
      }
      s.push_back('\n');
    }
    return s;
  }

  static bool FindValue(const std::string& body, std::string_view name,
                        std::string_view* out) noexcept {
    const std::string prefix = WireKey(name) + "=";
    size_t pos = 0;
    while (pos < body.size()) {
      size_t end = body.find('\n', pos);
      if (end == std::string::npos) {
        end = body.size();
      }
      if (end - pos >= prefix.size() &&
          body.compare(pos, prefix.size(), prefix) == 0) {
        *out = std::string_view(body).substr(pos + prefix.size(),
                                             end - pos - prefix.size());
        return true;
      }
      pos = end + 1;
    }
    return false;
  }

  static bool TryGetU64(const std::string& body, std::string_view key,
                        unsigned __int64* out) noexcept {
    std::string_view value;
    if (!FindValue(body, key, &value) || value.empty()) {
      return false;
    }
    unsigned __int64 n = 0;
    for (char c : value) {
      if (c < '0' || c > '9') {
        return false;
      }
      n = n * 10 + static_cast<unsigned __int64>(c - '0');
    }
    *out = n;
    return true;
  }

  void DecodeResponse(const std::string& body, Requests* out) noexcept {
    out->return_value = 0;
    unsigned __int64 v = 0;
    if (TryGetU64(body, "ret", &v)) {
      out->return_value = v;
    }
    if (TryGetU64(body, "v", &v)) {
      response_version_ = static_cast<uint16_t>(v);
    }
    if (TryGetU64(body, "ck", &v)) {
      out->check_sum = v;
    }
    if (TryGetU64(body, "ts", &v)) {
      out->time_stamp = v;
    }
  }

  void SendRequest(Requests& request) noexcept {
    if (!connection_.IsConnected()) {
      return;
    }
    request.request_key |= USUGUMO_SIGNATURE_MASK;
    request.time_stamp = GetTimestamp();
    request.secure_key = kSecureKey;

    std::string payload;
    if (!EncodeRequest(request, payload)) {
      connection_.Close();
      return;
    }

    std::array<std::byte, 4> prefix = {};
    const uint32_t len = static_cast<uint32_t>(payload.size());
    prefix[0] = static_cast<std::byte>(len & 0xFF);
    prefix[1] = static_cast<std::byte>((len >> 8) & 0xFF);
    prefix[2] = static_cast<std::byte>((len >> 16) & 0xFF);
    prefix[3] = static_cast<std::byte>((len >> 24) & 0xFF);
    if (!connection_.SendAll(prefix.data(), prefix.size())) {
      connection_.Close();
      return;
    }
    if (!connection_.SendAll(payload.data(), payload.size())) {
      connection_.Close();
      return;
    }

    std::array<std::byte, 4> reply_prefix = {};
    if (!connection_.ReceiveAll(reply_prefix.data(), reply_prefix.size())) {
      connection_.Close();
      return;
    }
    const uint32_t reply_len = static_cast<uint32_t>(reply_prefix[0]) |
                               (static_cast<uint32_t>(reply_prefix[1]) << 8) |
                               (static_cast<uint32_t>(reply_prefix[2]) << 16) |
                               (static_cast<uint32_t>(reply_prefix[3]) << 24);
    if (reply_len == 0 || reply_len > 1024) {
      connection_.Close();
      return;
    }

    std::string reply(reply_len, '\0');
    if (!connection_.ReceiveAll(reply.data(), reply.size())) {
      connection_.Close();
      return;
    }

    Requests response = {};
    DecodeResponse(reply, &response);
    request = response;
  }

  template <uint64_t RequestKey>
  uint64_t GetDllInfo(std::string_view dll_name) noexcept {
    if (!connection_.IsConnected()) {
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
    if (connection_.IsConnected()) {
      return true;
    }
    if (!connection_.Connect()) {
      return false;
    }
    used_port_ = usugumo_wsk::DerivePort();
    return true;
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
