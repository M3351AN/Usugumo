// Copyright (c) 2026 渟雲. All rights reserved.

#pragma once
#ifndef _WINDOW_HELPER_H_
#define _WINDOW_HELPER_H_

#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <memory>
#include <string_view>

using WindowHandle = HWND;
using ThreadHandle = HANDLE;
using EventHandle = HANDLE;
using Address = uintptr_t;
using SizeType = size_t;

constexpr inline DWORD WINDOW_CREATION_TIMEOUT = 5000u;
constexpr inline DWORD THREAD_WAIT_TIMEOUT = 1000u;
constexpr inline DWORD DESTROY_WINDOW_TIMEOUT = 5000u;
constexpr inline UINT WINDOW_WIDTH = 200u;
constexpr inline UINT WINDOW_HEIGHT = 150u;
constexpr inline std::string_view WINDOW_CLASS_NAME = "TestWindowClass";
constexpr inline std::string_view WINDOW_TITLE = "Test";

struct HandleDeleter {
    void operator()(HANDLE h) const noexcept {
        if (h != nullptr && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
};

using UniqueThreadPtr = std::unique_ptr<void, HandleDeleter>;
using UniqueEventPtr = std::unique_ptr<void, HandleDeleter>;

struct WindowData {
    WindowHandle hwnd = nullptr;
    std::atomic<bool> windowReady{false};
    std::atomic<bool> windowRunning{true};
    UniqueEventPtr windowReadyEvent;
};

inline LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    WindowData* windowData = reinterpret_cast<WindowData*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (uMsg) {
        case WM_CREATE: {
            CREATESTRUCT* createStruct = reinterpret_cast<CREATESTRUCT*>(lParam);
            WindowData* data = reinterpret_cast<WindowData*>(createStruct->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
            return 0;
        }

        case WM_SYSCOMMAND: {
            if (wParam == SC_CLOSE) {
                if (windowData && windowData->windowRunning.load()) {
                    return 0;
                }
            }
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }

        case WM_CLOSE: {
            if (windowData && windowData->windowRunning.load()) {
                return 0;
            }
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }

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

inline DWORD WINAPI WindowThreadProc(LPVOID lpParameter) noexcept {
    WindowData* windowData = static_cast<WindowData*>(lpParameter);
    if (!windowData) {
        return 1;
    }

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = WINDOW_CLASS_NAME.data();
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassA(&wc)) {
        printf("Failed to register window class in thread. Error: %lu\n", GetLastError());
        windowData->windowReady = false;
        if (windowData->windowReadyEvent) {
            SetEvent(windowData->windowReadyEvent.get());
        }
        return 1;
    }
    
    WindowHandle hwnd = CreateWindowExA(
        0,
        WINDOW_CLASS_NAME.data(),
        WINDOW_TITLE.data(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL,
        NULL,
        GetModuleHandle(NULL),
        windowData
    );
    
    if (!hwnd) {
        printf("Failed to create window in thread. Error: %lu\n", GetLastError());
        windowData->windowReady = false;
        if (windowData->windowReadyEvent) {
            SetEvent(windowData->windowReadyEvent.get());
        }
        return 1;
    }
    
    windowData->hwnd = hwnd;
    windowData->windowReady = true;
    if (windowData->windowReadyEvent) {
        SetEvent(windowData->windowReadyEvent.get());
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
    
    UnregisterClassA(WINDOW_CLASS_NAME.data(), GetModuleHandle(NULL));
    
    return 0;
}

inline UniqueThreadPtr CreateWindowThread(WindowData& windowData) noexcept {
    windowData.windowReadyEvent = UniqueEventPtr(
        CreateEvent(NULL, TRUE, FALSE, NULL),
        HandleDeleter()
    );
    if (!windowData.windowReadyEvent) {
        printf("Failed to create window ready event. Error: %lu\n", GetLastError());
        return nullptr;
    }
    
    DWORD threadId;
    ThreadHandle threadHandle = CreateThread(
        NULL,
        0,
        WindowThreadProc,
        &windowData,
        0,
        &threadId
    );
    
    if (!threadHandle) {
        printf("Failed to create window thread. Error: %lu\n", GetLastError());
        windowData.windowReadyEvent.reset();
        return nullptr;
    }
    
    WaitForSingleObject(windowData.windowReadyEvent.get(), WINDOW_CREATION_TIMEOUT);
    
    if (!windowData.windowReady) {
        printf("Window creation failed or timeout.\n");
        windowData.windowRunning = false;
        WaitForSingleObject(threadHandle, THREAD_WAIT_TIMEOUT);
        CloseHandle(threadHandle);
        windowData.windowReadyEvent.reset();
        return nullptr;
    }
    
    printf("Window created successfully in thread. HWND: 0x%p\n", windowData.hwnd);
    
    return UniqueThreadPtr(threadHandle, HandleDeleter());
}


inline void StopWindowThread(WindowData& windowData, const UniqueThreadPtr& thread) noexcept {
    windowData.windowRunning = false;
    DWORD threadId = GetThreadId(reinterpret_cast<HANDLE>(thread.get()));
    if (threadId != 0) {
        PostThreadMessage(threadId, WM_QUIT, 0, 0);
    }
    WaitForSingleObject(thread.get(), THREAD_WAIT_TIMEOUT);
}

#endif  // !_WINDOW_HELPER_H_
