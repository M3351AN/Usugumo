// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _OPERATION_H_
#define _OPERATION_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <intrin.h>
#include <immintrin.h> 
#ifdef USING_USUGUMO
#include "./usugumo.h"
#else
#include "./native.h"
#endif

class PatternScanner {
 public:
  struct PatternByte {
    uint8_t value;
    bool wildcard;
  };

  static std::vector<PatternByte> ParsePattern(const std::string& pattern) noexcept {
    std::vector<PatternByte> bytes;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
      PatternByte pb;
      if (token == "??" || token == "?") {
        pb.value = 0;
        pb.wildcard = true;
      } else {
        pb.value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
        pb.wildcard = false;
      }
      bytes.push_back(pb);
    }

    return bytes;
  }

  static std::vector<PatternByte> ParsePattern(std::string_view pattern) noexcept {
    std::vector<PatternByte> bytes;
    std::string token;
    size_t pos = 0;
    size_t len = pattern.size();

    while (pos < len) {
      while (pos < len && isspace(static_cast<unsigned char>(pattern[pos]))) {
        pos++;
      }
      if (pos >= len) {
        break;
      }
      size_t end_pos = pos;
      while (end_pos < len && !isspace(static_cast<unsigned char>(pattern[end_pos]))) {
        end_pos++;
      }
      token = std::string(pattern.substr(pos, end_pos - pos));
      pos = end_pos;

      PatternByte pb;
      if (token == "??" || token == "?") {
        pb.value = 0;
        pb.wildcard = true;
      } else {
        pb.value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
        pb.wildcard = false;
      }
      bytes.push_back(pb);
    }

    return bytes;
  }

  static void ConvertPatternToBytesAndMask(
      const std::vector<PatternByte>& pattern,
      std::vector<uint8_t>& pattern_bytes, std::vector<bool>& mask) noexcept {
    pattern_bytes.clear();
    mask.clear();

    for (const auto& pb : pattern) {
      pattern_bytes.push_back(pb.value);
      mask.push_back(!pb.wildcard);
    }
  }

  static bool MemoryCompare(const uint8_t* data, const uint8_t* pattern,
                            const std::vector<bool>& mask, size_t length) noexcept {
    for (size_t i = 0; i < length; i++) {
      if (mask[i] && data[i] != pattern[i]) {
        return false;
      }
    }
    return true;
  }
};

constexpr inline size_t CHUNK_SIZE = 4096uz;
using Address = uintptr_t;
using SizeType = size_t;

#ifdef USING_USUGUMO

class Operation : public UsugumoDriver {
private:
  static bool SupportsSSE2() {
    static bool supported = []() {
        int info[4];
        __cpuid(info, 1);
        return (info[3] & (1 << 26)) != 0;
    }();
    return supported;
  }

  static bool SupportsAVX2() {
    static bool supported = []() {
        int info[4];
        __cpuid(info, 7);
        return (info[1] & (1 << 5)) != 0;
    }();
    return supported;
  }
public:
  bool Init(uint64_t process_id) noexcept { return Initialize(process_id); }
  bool Init(std::wstring_view process_name) noexcept { return Initialize(process_name); }

  template <typename T>
  bool Read(Address address, T* value) noexcept {
    return ReadMemoryKm(address, value, sizeof(T));
  }

  bool ReadSize(Address address, void* buffer, SizeType size) noexcept {
    return ReadMemoryKm(address, buffer, size);
  }

  template <typename T>
  bool Write(Address address, const T& value, int size) noexcept {
    return WriteMemoryKm(address, &value, size);
  }

  bool GetModuleInfo(std::string_view module_name, uint64_t* base_address,
                     uint64_t* module_size) noexcept {
    uint64_t base = GetDllBaseAddress(module_name.data());
    uint64_t size = GetDllSize(module_name.data());

    if (base_address) *base_address = base;
    if (module_size) *module_size = size;

    return (base != 0 && size != 0);
  }

  Address PatternScan(Address start, Address end,
                      std::string_view pattern) noexcept {
    if (start >= end) return 0;

    auto pattern_bytes = PatternScanner::ParsePattern(pattern);
    if (pattern_bytes.empty()) return 0;

    SizeType pattern_length = pattern_bytes.size();
    SizeType size = end - start;

    std::unique_ptr<uint8_t[]> buffer(
        new uint8_t[CHUNK_SIZE + pattern_length - 1]);

    std::vector<uint8_t> pattern_data;
    std::vector<bool> mask;
    PatternScanner::ConvertPatternToBytesAndMask(pattern_bytes, pattern_data,
                                                 mask);

    for (SizeType offset = 0; offset < size; offset += CHUNK_SIZE) {
      SizeType bytes_to_read =
          std::min(CHUNK_SIZE + pattern_length - 1, size - offset);
      Address current_address = start + offset;

      if (!ReadSize(current_address, buffer.get(), bytes_to_read)) {
        continue;
      }

      SizeType search_limit = bytes_to_read - pattern_length;
      for (SizeType i = 0; i <= search_limit; i++) {
        if (PatternScanner::MemoryCompare(buffer.get() + i, pattern_data.data(),
                                          mask, pattern_length)) {
          return current_address + i;
        }
      }
    }

    return 0;
  }

  Address PatternScanSize(Address start, SizeType size,
                          std::string_view pattern) noexcept {
    return PatternScan(start, start + size, pattern);
  }

  Address PatternScanMultiple(Address start, Address end,
                              const std::vector<std::string>& patterns) noexcept {
    for (const auto& pattern : patterns) {
      Address result = PatternScan(start, end, pattern);
      if (result != 0) {
        return result;
      }
    }
    return 0;
  }

};

#else

class Operation : public Native {
private:
  static bool SupportsSSE2() {
    static bool supported = []() {
        int info[4];
        __cpuid(info, 1);
        return (info[3] & (1 << 26)) != 0;
    }();
    return supported;
  }

  static bool SupportsAVX2() {
    static bool supported = []() {
        int info[4];
        __cpuid(info, 7);
        return (info[1] & (1 << 5)) != 0;
    }();
    return supported;
  }
public:
  bool Init(uint64_t process_id) noexcept { return Initialize(process_id); }
  bool Init(std::wstring_view process_name) noexcept {
    return Initialize(process_name.data(), PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                        PROCESS_VM_WRITE |
                                        PROCESS_QUERY_INFORMATION);
  }

  template <typename T>
  bool Read(Address address, T* value) noexcept {
    return ReadMemoryNt(address, value, sizeof(T));
  }

  bool ReadSize(Address address, void* buffer, SizeType size) noexcept {
    return ReadMemoryNt(address, buffer, size);
  }

  template <typename T>
  bool Write(Address address, const T& value, int size) noexcept {
    return WriteMemoryNt(address, &value, size);
  }

  bool GetModuleInfo(std::string_view module_name, uint64_t* base_address,
                     uint64_t* module_size) noexcept {
    uint64_t base = GetDllBaseAddress(module_name.data());
    uint64_t size = GetDllSize(module_name.data());

    if (base_address) *base_address = base;
    if (module_size) *module_size = size;

    return (base != 0 && size != 0);
  }

  Address PatternScan(Address start, Address end,
                    std::string_view pattern) noexcept {
    if (start >= end) return 0;

    auto pattern_bytes = PatternScanner::ParsePattern(pattern);
    if (pattern_bytes.empty()) return 0;

    SizeType pattern_length = pattern_bytes.size();
    SizeType size = end - start;

    std::vector<uint8_t> pattern_data(pattern_length);
    std::vector<uint8_t> mask_bytes(pattern_length);
    for (size_t i = 0; i < pattern_length; ++i) {
        pattern_data[i] = pattern_bytes[i].value;
        mask_bytes[i] = pattern_bytes[i].wildcard ? 0x00 : 0xFF;
    }

    std::unique_ptr<uint8_t[]> buffer(
        new uint8_t[CHUNK_SIZE + pattern_length - 1]);

    auto scalar_compare = [&](const uint8_t* data, size_t len) -> bool {
        for (size_t i = 0; i < len; ++i) {
            if (mask_bytes[i] && data[i] != pattern_data[i])
                return false;
        }
        return true;
    };

    bool use_avx2 = SupportsAVX2();
    bool use_sse2 = SupportsSSE2();

    for (SizeType offset = 0; offset < size; offset += CHUNK_SIZE) {
        SizeType bytes_to_read =
            std::min(CHUNK_SIZE + pattern_length - 1, size - offset);
        if (bytes_to_read < pattern_length) continue;

        Address current_address = start + offset;
        if (!ReadSize(current_address, buffer.get(), bytes_to_read))
            continue;

        SizeType search_limit = bytes_to_read - pattern_length;

        for (SizeType i = 0; i <= search_limit; ++i) {
            const uint8_t* data_ptr = buffer.get() + i;

            if (use_avx2 && pattern_length >= 32) {
                bool match = true;
                size_t j = 0;
                for (; j + 31 < pattern_length; j += 32) {
                    __m256i d = _mm256_loadu_si256((__m256i*)(data_ptr + j));
                    __m256i p = _mm256_loadu_si256((__m256i*)(pattern_data.data() + j));
                    __m256i m = _mm256_loadu_si256((__m256i*)(mask_bytes.data() + j));
                    __m256i cmp = _mm256_cmpeq_epi8(
                        _mm256_and_si256(d, m),
                        _mm256_and_si256(p, m)
                    );
                    int mask = _mm256_movemask_epi8(cmp);
                    if (mask != 0xFFFFFFFF) { match = false; break; }
                }
                if (match && j < pattern_length)
                    match = scalar_compare(data_ptr + j, pattern_length - j);
                if (match) return current_address + i;
            }
            else if (use_sse2 && pattern_length >= 16) {
                bool match = true;
                size_t j = 0;
                for (; j + 15 < pattern_length; j += 16) {
                    __m128i d = _mm_loadu_si128((__m128i*)(data_ptr + j));
                    __m128i p = _mm_loadu_si128((__m128i*)(pattern_data.data() + j));
                    __m128i m = _mm_loadu_si128((__m128i*)(mask_bytes.data() + j));
                    __m128i cmp = _mm_cmpeq_epi8(
                        _mm_and_si128(d, m),
                        _mm_and_si128(p, m)
                    );
                    int mask = _mm_movemask_epi8(cmp);
                    if (mask != 0xFFFF) { match = false; break; }
                }
                if (match && j < pattern_length)
                    match = scalar_compare(data_ptr + j, pattern_length - j);
                if (match) return current_address + i;
            }
            else {
                if (scalar_compare(data_ptr, pattern_length))
                    return current_address + i;
            }
        }
    }
    return 0;
  }

  Address PatternScanSize(Address start, SizeType size,
                          std::string_view pattern) noexcept {
    return PatternScan(start, start + size, pattern);
  }

  Address PatternScanMultiple(Address start, Address end,
                              const std::vector<std::string>& patterns) noexcept {
    for (const auto& pattern : patterns) {
      Address result = PatternScan(start, end, pattern);
      if (result != 0) {
        return result;
      }
    }
    return 0;
  }

};

#endif  // USING_USUGUMO

#endif
