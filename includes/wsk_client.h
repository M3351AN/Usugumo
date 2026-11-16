// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_WSK_CLIENT_H_
#define _USUGUMO_WSK_CLIENT_H_

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace usugumo_wsk {

constexpr inline uint16_t kPortBase = 20000;
constexpr inline uint16_t kPortRange = 10000;

inline void Sha256(const std::byte* data, size_t length, std::byte* digest) {
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

  auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
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
      h = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
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

inline bool GetBootVolumeSerial(char* out, size_t out_len) noexcept {
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
  if (!GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr, nullptr,
                             0)) {
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

inline uint16_t DerivePort() noexcept {
  char serial[128] = {0};
  if (!GetBootVolumeSerial(serial, sizeof(serial))) return 0;
  const size_t serial_len = strlen(serial);
  if (serial_len == 0) return 0;

  static const char kSuffix[] = "UsugumoPort";
  std::byte input[8 + sizeof(kSuffix) - 1];
  size_t slen = serial_len > 8 ? 8 : serial_len;
  for (size_t i = 0; i < slen; i++) {
    input[i] = static_cast<std::byte>(serial[i]);
  }
  for (size_t i = 0; i < sizeof(kSuffix) - 1; i++) {
    input[slen + i] = static_cast<std::byte>(kSuffix[i]);
  }

  std::byte digest[32];
  Sha256(input, slen + sizeof(kSuffix) - 1, digest);
  std::memset(serial, 0, sizeof(serial));

  const uint16_t raw =
      (static_cast<uint16_t>(digest[0]) << 8) | static_cast<uint16_t>(digest[1]);
  return static_cast<uint16_t>(kPortBase + (raw % kPortRange));
}

class WskConnection {
 public:
  enum class LastError {
    kNone = 0,
    kWsaStartup,
    kPortDerive,
    kSocket,
    kConnectRefused,
    kConnectTimeout,
    kConnectOther,
    kSend,
    kReceive,
  };

  WskConnection() noexcept : socket_(INVALID_SOCKET), connected_(false) {}

  ~WskConnection() noexcept { Close(); }

  WskConnection(const WskConnection&) = delete;
  WskConnection& operator=(const WskConnection&) = delete;

  LastError GetLastError() const noexcept { return last_error_; }
  int GetLastWsaError() const noexcept { return last_wsa_error_; }

  static const char* DescribeError(LastError e) noexcept {
    switch (e) {
      case LastError::kNone: return "none";
      case LastError::kWsaStartup: return "WSAStartup failed";
      case LastError::kPortDerive: return "port derivation failed";
      case LastError::kSocket: return "socket() failed";
      case LastError::kConnectRefused:
        return "connection refused - driver not loaded or not listening on the derived port";
      case LastError::kConnectTimeout:
        return "connection timed out - a filter or firewall is dropping loopback";
      case LastError::kConnectOther: return "connect() failed";
      case LastError::kSend: return "send failed - driver closed the connection";
      case LastError::kReceive: return "recv failed - driver closed or rejected the request";
    }
    return "unknown";
  }

  bool Connect() noexcept {
    if (connected_) return true;
    last_error_ = LastError::kNone;
    last_wsa_error_ = 0;

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
      last_error_ = LastError::kWsaStartup;
      return false;
    }
    wsa_started_ = true;

    const uint16_t port = DerivePort();
    if (port == 0) {
      last_error_ = LastError::kPortDerive;
      Close();
      return false;
    }

    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
      last_error_ = LastError::kSocket;
      last_wsa_error_ = WSAGetLastError();
      Close();
      return false;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
      last_error_ = LastError::kSocket;
      last_wsa_error_ = WSAGetLastError();
      Close();
      return false;
    }

    if (connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ==
        SOCKET_ERROR) {
      last_wsa_error_ = WSAGetLastError();
      if (last_wsa_error_ == WSAECONNREFUSED) {
        last_error_ = LastError::kConnectRefused;
      } else if (last_wsa_error_ == WSAETIMEDOUT) {
        last_error_ = LastError::kConnectTimeout;
      } else {
        last_error_ = LastError::kConnectOther;
      }
      Close();
      return false;
    }

    connected_ = true;
    return true;
  }

  void Close() noexcept {
    if (socket_ != INVALID_SOCKET) {
      closesocket(socket_);
      socket_ = INVALID_SOCKET;
    }
    if (wsa_started_) {
      WSACleanup();
      wsa_started_ = false;
    }
    connected_ = false;
  }

  bool IsConnected() const noexcept { return connected_; }

  bool SendAll(const void* data, size_t length) noexcept {
    if (!connected_) return false;
    const char* p = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < length) {
      const int n = send(socket_, p + sent, static_cast<int>(length - sent), 0);
      if (n <= 0) {
        last_error_ = LastError::kSend;
        last_wsa_error_ = WSAGetLastError();
        return false;
      }
      sent += static_cast<size_t>(n);
    }
    return true;
  }

  bool ReceiveAll(void* data, size_t length) noexcept {
    if (!connected_) return false;
    char* p = static_cast<char*>(data);
    size_t received = 0;
    while (received < length) {
      const int n = recv(socket_, p + received,
                         static_cast<int>(length - received), 0);
      if (n <= 0) {
        last_error_ = LastError::kReceive;
        last_wsa_error_ = n == 0 ? 0 : WSAGetLastError();
        return false;
      }
      received += static_cast<size_t>(n);
    }
    return true;
  }

  bool RoundTrip(const void* request, void* response,
                 size_t length) noexcept {
    if (!SendAll(request, length)) return false;
    return ReceiveAll(response, length);
  }

 private:
  SOCKET socket_;
  bool connected_;
  bool wsa_started_ = false;
  LastError last_error_ = LastError::kNone;
  int last_wsa_error_ = 0;
};

}  // namespace usugumo_wsk

#endif  // !_USUGUMO_WSK_CLIENT_H_


