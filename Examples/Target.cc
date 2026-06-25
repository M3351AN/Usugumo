// Copyright (c) 2026 渟雲. All rights reserved.
#include <windows.h>
#include <iostream>
#include <iomanip>

using Address = uintptr_t;
using Dword64 = DWORD64;

volatile Dword64 g_targetVar = 0x114514ULL;

int main() {
    std::cout << "\nTarget var at 0x" << std::hex << std::uppercase
              << reinterpret_cast<Address>(&g_targetVar)
              << " = 0x" << g_targetVar
              << std::nouppercase << std::dec << std::endl;

    while (true) {
        std::cout << "\nTarget var at 0x" << std::hex << std::uppercase
                  << reinterpret_cast<Address>(&g_targetVar)
                  << " = 0x" << g_targetVar
                  << std::nouppercase << std::dec << std::endl;
        system("pause");
    }

    return 0;
}