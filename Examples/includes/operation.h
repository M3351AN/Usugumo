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

  static std::vector<PatternByte> ParsePattern(const std::string& pattern) {
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

  static std::vector<PatternByte> ParsePattern(std::string_view pattern) {
    return ParsePattern(std::string(pattern));
  }

  static void ConvertPatternToBytesAndMask(
      const std::vector<PatternByte>& pattern,
      std::vector<uint8_t>& pattern_bytes, std::vector<bool>& mask) {
    pattern_bytes.clear();
    mask.clear();

    for (const auto& pb : pattern) {
      pattern_bytes.push_back(pb.value);
      mask.push_back(!pb.wildcard);
    }
  }

static bool MemoryCompare(const uint8_t* data, const uint8_t* pattern,
                            const std::vector<bool>& mask, size_t length) {
    for (size_t i = 0; i < length; i++) {
      if (mask[i] && data[i] != pattern[i]) {
        return false;
      }
    }
    return true;
  }
};

#ifdef USING_USUGUMO

class Operation : public UsugumoDriver {
 public:
  bool Init(uint64_t process_id) { return Initialize(process_id); }
  bool Init(const wchar_t* process_name) { return Initialize(process_name); }

  template <typename T>
  bool Read(uintptr_t address, T* value) {
    return ReadMemoryKm(address, value, sizeof(T));
  }

  bool ReadSize(uintptr_t address, void* buffer, size_t size) {
    return ReadMemoryKm(address, buffer, size);
  }

  template <typename T>
  bool Write(uintptr_t address, const T& value, int size) {
    return WriteMemoryKm(address, &value, size);
  }

  bool GetModuleInfo(const char* module_name, uint64_t* base_address,
                     uint64_t* module_size) {
    uint64_t base = GetDllBaseAddress(module_name);
    uint64_t size = GetDllSize(module_name);

    if (base_address) *base_address = base;
    if (module_size) *module_size = size;

    return (base != 0 && size != 0);
  }

  // Pattern scan 功能 - 在指定绝对地址范围内扫描
  uintptr_t PatternScan(uintptr_t start, uintptr_t end,
                        const std::string& pattern) {
    if (start >= end) return 0;

    auto pattern_bytes = PatternScanner::ParsePattern(pattern);
    if (pattern_bytes.empty()) return 0;

    size_t pattern_length = pattern_bytes.size();
    size_t size = end - start;

    const size_t CHUNK_SIZE = 4096;
    std::unique_ptr<uint8_t[]> buffer(
        new uint8_t[CHUNK_SIZE + pattern_length - 1]);

    std::vector<uint8_t> pattern_data;
    std::vector<bool> mask;
    PatternScanner::ConvertPatternToBytesAndMask(pattern_bytes, pattern_data,
                                                 mask);

    for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
      size_t bytes_to_read =
          std::min(CHUNK_SIZE + pattern_length - 1, size - offset);
      uintptr_t current_address = start + offset;

      if (!ReadSize(current_address, buffer.get(), bytes_to_read)) {
        continue;
      }

      size_t search_limit = bytes_to_read - pattern_length;
      for (size_t i = 0; i <= search_limit; i++) {
        if (PatternScanner::MemoryCompare(buffer.get() + i, pattern_data.data(),
                                          mask, pattern_length)) {
          return current_address + i;
        }
      }
    }

    return 0;
  }

  uintptr_t PatternScanSize(uintptr_t start, size_t size,
                            const std::string& pattern) {
    return PatternScan(start, start + size, pattern);
  }

  uintptr_t PatternScanMultiple(uintptr_t start, uintptr_t end,
                                const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
      uintptr_t result = PatternScan(start, end, pattern);
      if (result != 0) {
        return result;
      }
    }
    return 0;
  }

};

#else

class Operation : public Native {
 public:
  bool Init(uint64_t process_id) { return Initialize(process_id); }
  bool Init(const wchar_t* process_name) {
    return Initialize(process_name, PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                        PROCESS_VM_WRITE |
                                        PROCESS_QUERY_INFORMATION);
  }

  template <typename T>
  bool Read(uintptr_t address, T* value) {
    return ReadMemoryNt(address, value, sizeof(T));
  }

  bool ReadSize(uintptr_t address, void* buffer, size_t size) {
    return ReadMemoryNt(address, buffer, size);
  }

  template <typename T>
  bool Write(uintptr_t address, const T& value, int size) {
    return WriteMemoryNt(address, &value, size);
  }

  bool GetModuleInfo(const char* module_name, uint64_t* base_address,
                     uint64_t* module_size) {
    uint64_t base = GetDllBaseAddress(module_name);
    uint64_t size = GetDllSize(module_name);

    if (base_address) *base_address = base;
    if (module_size) *module_size = size;

    return (base != 0 && size != 0);
  }

  uintptr_t PatternScan(uintptr_t start, uintptr_t end,
                        const std::string& pattern) {
    if (start >= end) return 0;

    auto pattern_bytes = PatternScanner::ParsePattern(pattern);
    if (pattern_bytes.empty()) return 0;

    size_t pattern_length = pattern_bytes.size();
    size_t size = end - start;

    const size_t CHUNK_SIZE = 4096;
    std::unique_ptr<uint8_t[]> buffer(
        new uint8_t[CHUNK_SIZE + pattern_length - 1]);

    std::vector<uint8_t> pattern_data;
    std::vector<bool> mask;
    PatternScanner::ConvertPatternToBytesAndMask(pattern_bytes, pattern_data,
                                                 mask);

    for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
      size_t bytes_to_read =
          std::min(CHUNK_SIZE + pattern_length - 1, size - offset);

      if (bytes_to_read < pattern_length) {
        continue;
      }

      uintptr_t current_address = start + offset;

      if (!ReadSize(current_address, buffer.get(), bytes_to_read)) {
        continue;
      }

      size_t search_limit = bytes_to_read - pattern_length;
      for (size_t i = 0; i <= search_limit; i++) {
        if (PatternScanner::MemoryCompare(buffer.get() + i, pattern_data.data(),
                                          mask, pattern_length)) {
          return current_address + i;
        }
      }
    }

    return 0;
  }

  uintptr_t PatternScanSize(uintptr_t start, size_t size,
                            const std::string& pattern) {
    return PatternScan(start, start + size, pattern);
  }

  uintptr_t PatternScanMultiple(uintptr_t start, uintptr_t end,
                                const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
      uintptr_t result = PatternScan(start, end, pattern);
      if (result != 0) {
        return result;
      }
    }
    return 0;
  }

};

#endif  // USING_USUGUMO

#endif
