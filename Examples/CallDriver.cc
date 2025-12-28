// Copyright (c) 2026 渟雲. All rights reserved.
#include <Windows.h>
#include <string>
#include <iostream>

#include "./includes/operation.h"

int main() {
    Operation op;
    
    if (!op.Init(L"Target.exe")) {
        printf("Failed to initialize\n");
        system("pause");
        return 1;
    }
#ifdef USING_USUGUMO
    if (!op.DriverProbe()) {
        printf("Driver probe failed\n");
        system("pause");
        return 1;
    }
    printf("Driver probe success\n");
#else
    printf("Using native api\n");
#endif
    uint64_t base_address = 0;
    uint64_t module_size = 0;
    if (!op.GetModuleInfo("Target.exe", &base_address, &module_size)) {
        printf("Failed to get module info\n");
        system("pause");
        return 1;
    }
    
    printf("Module base: 0x%llX, size: 0x%llX\n", base_address, module_size);

    std::string pattern = "AA BB CC DD ?? ?? ?? ?? 11 22 33 44";
    uintptr_t found = op.PatternScanSize(base_address, module_size, pattern);
    printf("Pattern 'AA BB CC DD ?? ?? ?? ?? 11 22 33 44' found at: 0x%llX\n", found);

    uint64_t target_var = 0;
    if (!op.Read<uint64_t>(0xDEAD0000, &target_var)) {
        printf("Failed to read memory\n");
    } else {
        printf("Read target_var = 0x%llX at 0x%llX\n", target_var, 0xDEAD0000ULL);
    }
    
    uint64_t new_value = 0x1919810;
    if (!op.Write<uint64_t>(0xDEAD0000, new_value, sizeof(uint64_t))) {
        printf("Failed to write memory\n");
    } else {
        printf("Written 0x%llX to 0x%llX\n", new_value, 0xDEAD0000ULL);
    }
    
    if (op.Read<uint64_t>(0xDEAD0000, &target_var)) {
        printf("Read back target_var = 0x%llX\n", target_var);
    }
    
    printf("Waiting 3 second then mouse left down...\n");
    Sleep(3000);
    
    op.MouseLeftDown();
    printf("Waiting 1 second then mouse left up...\n");
    Sleep(1000);
    op.MouseLeftUp();
    
    printf("Waiting 3 second then move mouse (100, -100)...\n");
    Sleep(3000);
    op.MouseMove(100, -100);
    
    printf("Waiting 3 second then set cursor position (500, 500)...\n");
    Sleep(3000);
    op.SetCursorPos(500, 500);
    
    printf("Done\n");
    system("pause");
    return 0;
}