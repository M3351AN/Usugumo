// Copyright (c) 2026 渟雲. All rights reserved.
#include <Windows.h>
#include <string>
#include <iostream>
#include <thread>
#include <atomic>

#include "./includes/operation.h"

struct WindowData {
    HWND hwnd = nullptr;
    std::atomic<bool> windowReady{false};
    std::atomic<bool> windowRunning{true};
    HANDLE windowReadyEvent = nullptr;
};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

DWORD WINAPI WindowThreadProc(LPVOID lpParameter) {
    WindowData* windowData = static_cast<WindowData*>(lpParameter);
    const char CLASS_NAME[] = "TestWindowClass";
    
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassA(&wc)) {
        printf("Failed to register window class in thread. Error: %lu\n", GetLastError());
        windowData->windowReady = false;
        if (windowData->windowReadyEvent) {
            SetEvent(windowData->windowReadyEvent);
        }
        return 1;
    }
    
    HWND hwnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "Test Window",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwnd) {
        printf("Failed to create window in thread. Error: %lu\n", GetLastError());
        windowData->windowReady = false;
        if (windowData->windowReadyEvent) {
            SetEvent(windowData->windowReadyEvent);
        }
        return 1;
    }
    
    windowData->hwnd = hwnd;
    windowData->windowReady = true;
    if (windowData->windowReadyEvent) {
        SetEvent(windowData->windowReadyEvent);
    }
    
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    
    MSG msg;
    while (windowData->windowRunning) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                break;
            }
            
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            Sleep(1);
        }
    }
    
    if (IsWindow(hwnd)) {
        DestroyWindow(hwnd);
    }

    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    UnregisterClassA(CLASS_NAME, GetModuleHandle(NULL));
    
    return 0;
}

HANDLE CreateWindowThread(WindowData& windowData) {
    windowData.windowReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!windowData.windowReadyEvent) {
        printf("Failed to create window ready event. Error: %lu\n", GetLastError());
        return NULL;
    }
    
    DWORD threadId;
    HANDLE threadHandle = CreateThread(
        NULL,
        0,
        WindowThreadProc,
        &windowData,
        0,
        &threadId
    );
    
    if (!threadHandle) {
        printf("Failed to create window thread. Error: %lu\n", GetLastError());
        CloseHandle(windowData.windowReadyEvent);
        windowData.windowReadyEvent = nullptr;
        return NULL;
    }
    
    WaitForSingleObject(windowData.windowReadyEvent, 5000);
    
    if (!windowData.windowReady) {
        printf("Window creation failed or timeout.\n");
        windowData.windowRunning = false;
        WaitForSingleObject(threadHandle, 1000);
        CloseHandle(threadHandle);
        CloseHandle(windowData.windowReadyEvent);
        windowData.windowReadyEvent = nullptr;
        return NULL;
    }
    
    printf("Window created successfully in thread. HWND: 0x%p\n", windowData.hwnd);
    
    return threadHandle;
}

int main() {
    WindowData windowData;
    
    HANDLE windowThread = CreateWindowThread(windowData);
    if (!windowThread) {
        printf("Failed to create window thread.\n");
        system("pause");
        return 1;
    }
    
    Operation op;
    
#ifdef USING_USUGUMO
    if (!op.DriverProbe()) {
        printf("Driver probe failed\n");
        windowData.windowRunning = false;
        PostThreadMessage(GetThreadId(windowThread), WM_QUIT, 0, 0);
        WaitForSingleObject(windowThread, 1000);
        CloseHandle(windowThread);
        if (windowData.windowReadyEvent) {
            CloseHandle(windowData.windowReadyEvent);
        }
        system("pause");
        return 1;
    }
    printf("Driver probe success\n");
#else
    printf("Using native api\n");
#endif

    if (!op.Init(L"Target.exe")) {
        printf("Failed to initialize\n");
        windowData.windowRunning = false;
        PostThreadMessage(GetThreadId(windowThread), WM_QUIT, 0, 0);
        WaitForSingleObject(windowThread, 1000);
        CloseHandle(windowThread);
        if (windowData.windowReadyEvent) {
            CloseHandle(windowData.windowReadyEvent);
        }
        system("pause");
        return 1;
    }
    uint64_t base_address = 0;
    uint64_t module_size = 0;
    if (!op.GetModuleInfo("Target.exe", &base_address, &module_size)) {
        printf("Failed to get module info\n");
        windowData.windowRunning = false;
        PostThreadMessage(GetThreadId(windowThread), WM_QUIT, 0, 0);
        WaitForSingleObject(windowThread, 1000);
        CloseHandle(windowThread);
        if (windowData.windowReadyEvent) {
            CloseHandle(windowData.windowReadyEvent);
        }
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

    printf("Waiting 1 second then press VK_LWIN...\n");
    Sleep(1000);
    op.KeybdEvent(VK_LWIN, 0, 0, 0);
    Sleep(100);
    op.KeybdEvent(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);

    printf("Waiting 1 second then anti capture test window...\n");
    Sleep(1000);
    
    if (windowData.hwnd && IsWindow(windowData.hwnd)) {
        op.AntiCapture(windowData.hwnd);
        printf("Anti capture applied to window.\n");
    } else {
        printf("Window handle is invalid.\n");
    }

    printf("Waiting input then undo anti capture test window...\n");
    system("pause");
    
    if (windowData.hwnd && IsWindow(windowData.hwnd)) {
        op.AntiCapture(windowData.hwnd, false);
        printf("Anti capture removed from window.\n");
    }

    printf("Waiting 3 second then destroy test window...\n");
    Sleep(3000);
    
    windowData.windowRunning = false;
    if (windowData.hwnd && IsWindow(windowData.hwnd)) {
        PostMessage(windowData.hwnd, WM_CLOSE, 0, 0);
    }
    
    WaitForSingleObject(windowThread, 5000);
    
    printf("Done\n");
    
    CloseHandle(windowThread);
    if (windowData.windowReadyEvent) {
        CloseHandle(windowData.windowReadyEvent);
    }
    
    system("pause");
    return 0;
}
