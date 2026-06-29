// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _KEYBD_INPUT_INJECTION_H_
#define _KEYBD_INPUT_INJECTION_H_
#include <Windows.h>

#include <iostream>

class KeyboardInterface {
 private:
  using NtUserInjectKeyboardInput_t = void(WINAPI*)(KEYBDINPUT*, int);
  NtUserInjectKeyboardInput_t nt_user_inject_keyboard_input_ = nullptr;

 public:
  KeyboardInterface() {
    LoadLibraryW(L"user32.dll");
    HMODULE win32u_module = LoadLibraryW(L"win32u.dll");
    if (!win32u_module) {
      std::cerr << "[-] Could not load win32u.dll\n";
      return;
    }
    nt_user_inject_keyboard_input_ =
        reinterpret_cast<NtUserInjectKeyboardInput_t>(
            GetProcAddress(win32u_module, "NtUserInjectKeyboardInput"));
    if (!nt_user_inject_keyboard_input_) {
      std::cerr << "[-] Could not locate NtUserInjectKeyboardInput\n";
    }
  }

  inline bool sendEvent(const KEYBDINPUT& info) {
    if (nt_user_inject_keyboard_input_) {
      nt_user_inject_keyboard_input_(const_cast<KEYBDINPUT*>(&info), 1);
      return true;
    }
    return false;
  }
};

inline void my_keybd_event(BYTE vk, BYTE scan, DWORD flags,
                           ULONG_PTR dw_extra_info) {
  static KeyboardInterface keyboard_interface;

  KEYBDINPUT event = {};
  event.wVk = vk;
  event.wScan = scan;
  event.dwFlags = flags;
  event.time = 0;
  event.dwExtraInfo = dw_extra_info;

  keyboard_interface.sendEvent(event);
}
#endif
