// Copyright (c) 2026 渟雲. All rights reserved.
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>

const DWORD64 TARGET_BASE_ADDRESS = 0xDEAD0000;

int main() {
    LPVOID allocated = VirtualAlloc(
        (LPVOID)TARGET_BASE_ADDRESS,
        sizeof(DWORD64),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!allocated) {
        std::cerr << "Failed to allocate first memory block" << std::endl;
        system("pause");
        return 1;
    }
    
    volatile DWORD64* fixedVar = (volatile DWORD64*)allocated;
    *fixedVar = 0x114514;

    static const unsigned char pattern[12] = {0xAA, 0xBB, 0xCC, 0xDD, 0xDE, 0xAD, 0xBE, 0xFF, 0x11, 0x22, 0x33, 0x44};

    std::cout << "\nTarget var at 0x" << std::hex << (DWORD64)fixedVar 
              << " = 0x" << *fixedVar << std::dec << std::endl;
    
    std::cout << "Target pattern at 0x" << std::hex << (DWORD64)&pattern 
              << " = ";
    for (int i = 0; i < 12; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex 
                  << (int)(unsigned char)pattern[i] << " ";
    }
    std::cout << std::dec << std::endl;
    
    while (true) {
        std::cout << "\nTarget var at 0x" << std::hex << (DWORD64)fixedVar 
                  << " = 0x" << *fixedVar << std::dec << std::endl;

        system("pause");
    }

    // cleanup, never get here tho.
    VirtualFree(allocated, 0, MEM_RELEASE);
    return 0;
}
