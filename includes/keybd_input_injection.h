// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _KEYBD_INPUT_INJECTION_H_
#define _KEYBD_INPUT_INJECTION_H_

#include <Windows.h>
#include <iostream>

class KeyboardInterface {
private:
    using NtUserInjectKeyboardInput_t = void (WINAPI*)(KEYBDINPUT*, int);
    NtUserInjectKeyboardInput_t nt_user_inject_keyboard_input_ = nullptr;
    bool initialized_ = false;

    KeyboardInterface() {
        HMODULE win32u_module = LoadLibraryW(L"win32u.dll");
        if (win32u_module) {
            nt_user_inject_keyboard_input_ =
                reinterpret_cast<NtUserInjectKeyboardInput_t>(
                    GetProcAddress(win32u_module, "NtUserInjectKeyboardInput"));
            if (nt_user_inject_keyboard_input_) {
                initialized_ = true;
            } else {
                std::cerr << "[-] Could not locate NtUserInjectKeyboardInput\n";
            }
        } else {
            std::cerr << "[-] Could not load win32u.dll\n";
        }
    }

public:
    KeyboardInterface(const KeyboardInterface&) = delete;
    KeyboardInterface& operator=(const KeyboardInterface&) = delete;
    KeyboardInterface(KeyboardInterface&&) = delete;
    KeyboardInterface& operator=(KeyboardInterface&&) = delete;

    static KeyboardInterface& getInstance() {
        static KeyboardInterface instance;
        return instance;
    }

    inline bool sendEvent(const KEYBDINPUT& info) {
        if (initialized_ && nt_user_inject_keyboard_input_) {
            nt_user_inject_keyboard_input_(const_cast<KEYBDINPUT*>(&info), 1);
            return true;
        }
        return false;
    }
};
namespace {
inline void my_keybd_event(BYTE vk, BYTE scan, DWORD flags,
                           ULONG_PTR dw_extra_info) {
    KEYBDINPUT event = {};
    event.wVk = vk;
    event.wScan = scan;
    event.dwFlags = flags;
    event.time = 0;
    event.dwExtraInfo = dw_extra_info;

    KeyboardInterface::getInstance().sendEvent(event);
}
}
#endif // _KEYBD_INPUT_INJECTION_H_