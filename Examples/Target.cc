#include <windows.h>
#include <iostream>
#include <iomanip>

const DWORD64 TARGET_BASE_ADDRESS = 0xDEAD0000;

int main() {
    LPVOID allocated = VirtualAlloc(
        (LPVOID)TARGET_BASE_ADDRESS,
        sizeof(DWORD64),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!allocated) {
        return 1;
    }

    volatile DWORD64* fixedVar = (volatile DWORD64*)allocated;
    
    *fixedVar = 0x114514;

    std::cout << "\nTarget var at 0x" << std::hex << (DWORD64)fixedVar 
              << " = 0x" << std::hex << *fixedVar << std::dec << "\n";

    system("pause");

    VirtualFree(allocated, 0, MEM_RELEASE);
    return 0;
}