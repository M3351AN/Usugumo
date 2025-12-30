// Copyright (c) 2026 渟雲. All rights reserved.
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <memory>

using Address = uintptr_t;
using SizeType = size_t;
using Dword64 = DWORD64;
using VolatileDword64Ptr = volatile Dword64*;

constexpr inline Address TARGET_BASE_ADDRESS = 0xDEAD0000ULL;
constexpr inline SizeType ALLOC_MEM_SIZE = sizeof(Dword64);
constexpr inline Dword64 INIT_VAR_VALUE = 0x114514ULL;
constexpr inline SizeType PATTERN_LENGTH = 12u;
constexpr inline DWORD MEM_PROTECTION = PAGE_READWRITE;
constexpr inline DWORD MEM_ALLOC_FLAGS = MEM_COMMIT | MEM_RESERVE;

struct VirtualMemDeleter {
    void operator()(BYTE* p) const noexcept {
        if (p != nullptr) {
            VirtualFree(p, 0, MEM_RELEASE);
        }
    }
};

using UniqueVirtualMemPtr = std::unique_ptr<BYTE, VirtualMemDeleter>;

int main() {
    UniqueVirtualMemPtr allocatedMem(
        reinterpret_cast<BYTE*>(
            VirtualAlloc(
                reinterpret_cast<LPVOID>(TARGET_BASE_ADDRESS),
                ALLOC_MEM_SIZE,
                MEM_ALLOC_FLAGS,
                MEM_PROTECTION
            )
        ),
        VirtualMemDeleter()
    );

    if (!allocatedMem) {
        std::cerr << "Failed to allocate first memory block" << std::endl;
        system("pause");
        return 1;
    }

    VolatileDword64Ptr fixedVar = reinterpret_cast<VolatileDword64Ptr>(allocatedMem.get());
    *fixedVar = INIT_VAR_VALUE;

    static const unsigned char pattern[PATTERN_LENGTH] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xDE, 0xAD,
        0xBE, 0xFF, 0x11, 0x22, 0x33, 0x44
    };

    std::cout << "\nTarget var at 0x" << std::hex << std::uppercase
              << reinterpret_cast<Address>(fixedVar)
              << " = 0x" << *fixedVar
              << std::nouppercase << std::dec << std::endl;

    std::cout << "Target pattern at 0x" << std::hex << std::uppercase
              << reinterpret_cast<Address>(&pattern)
              << " = ";
    for (SizeType i = 0; i < PATTERN_LENGTH; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << std::uppercase
                  << static_cast<int>(pattern[i]) << " ";
    }
    std::cout << std::nouppercase << std::dec << std::endl;

    while (true) {
        std::cout << "\nTarget var at 0x" << std::hex << std::uppercase
                  << reinterpret_cast<Address>(fixedVar)
                  << " = 0x" << *fixedVar
                  << std::nouppercase << std::dec << std::endl;

        system("pause");
    }

    return 0;
}
