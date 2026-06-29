// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _MOUSE_INPUT_INJECTION_H_
#define _MOUSE_INPUT_INJECTION_H_

#include <Windows.h>
#include <iostream>

class MouseInterface {
private:
    using NtUserInjectMouseInput_t = bool (*)(MOUSEINPUT*, int);
    NtUserInjectMouseInput_t nt_user_inject_mouse_input_ = nullptr;
    bool initialized_ = false;

    MouseInterface() {
        HMODULE win32u_module = LoadLibraryW(L"win32u.dll");
        if (win32u_module) {
            nt_user_inject_mouse_input_ =
                reinterpret_cast<NtUserInjectMouseInput_t>(
                    GetProcAddress(win32u_module, "NtUserInjectMouseInput"));
            if (nt_user_inject_mouse_input_) {
                initialized_ = true;
            } else {
                std::cerr << "[-] Could not locate NtUserInjectMouseInput\n";
            }
        } else {
            std::cerr << "[-] Could not load win32u.dll\n";
        }
    }

public:
    MouseInterface(const MouseInterface&) = delete;
    MouseInterface& operator=(const MouseInterface&) = delete;
    MouseInterface(MouseInterface&&) = delete;
    MouseInterface& operator=(MouseInterface&&) = delete;

    static MouseInterface& getInstance() {
        static MouseInterface instance;
        return instance;
    }

    inline bool sendEvent(const MOUSEINPUT& info) {
        if (initialized_ && nt_user_inject_mouse_input_) {
            return nt_user_inject_mouse_input_(
                const_cast<MOUSEINPUT*>(&info), 1);
        }
        return false;
    }
};
namespace {
inline void my_mouse_event(DWORD dw_flags, LONG dx, LONG dy, DWORD dw_data,
                           ULONG_PTR dw_extra_info) {
    MOUSEINPUT event = {};
    event.dx = dx;
    event.dy = dy;
    event.mouseData = dw_data;
    event.dwFlags = dw_flags;
    event.time = 0;
    event.dwExtraInfo = dw_extra_info;

    MouseInterface::getInstance().sendEvent(event);
}
}
#endif // _MOUSE_INPUT_INJECTION_H_
