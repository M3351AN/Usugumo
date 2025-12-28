// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _MOUSE_INPUT_INJECTION_H_
#define _MOUSE_INPUT_INJECTION_H_
#include <Windows.h>

#include <iostream>

struct InjectedInputMouseInfo {
  int move_direction_x;
  int move_direction_y;
  DWORD mouse_data;
  DWORD mouse_options;
  unsigned int time_offset;
  ULONG_PTR extra_info;
};

class MouseInterface {
 private:
  bool (*nt_user_inject_mouse_input_)(InjectedInputMouseInfo*, int) = nullptr;

 public:
  MouseInterface() {
    LoadLibraryW(L"user32.dll");
    HMODULE win32u_module = LoadLibraryW(L"win32u.dll");
    if (!win32u_module) {
      std::cerr << "[-] Could not load win32u.dll\n";
      return;
    }
    nt_user_inject_mouse_input_ =
        reinterpret_cast<bool (*)(InjectedInputMouseInfo*, int)>(
            GetProcAddress(win32u_module, "NtUserInjectMouseInput"));
    if (!nt_user_inject_mouse_input_) {
      std::cerr << "[-] Could not locate NtUserInjectMouseInput\n";
    }
  }

  inline bool sendEvent(const InjectedInputMouseInfo& info) {
    if (nt_user_inject_mouse_input_) {
      return nt_user_inject_mouse_input_(
          const_cast<InjectedInputMouseInfo*>(&info), 1);
    }
    return false;
  }
};

inline void my_mouse_event(DWORD dw_flags, DWORD dx, DWORD dy, DWORD dw_data,
                           ULONG_PTR dw_extra_info) {
  static MouseInterface mouse_interface;

  InjectedInputMouseInfo event = {};
  event.move_direction_x = static_cast<int>(dx);
  event.move_direction_y = static_cast<int>(dy);
  event.mouse_data = dw_data;
  event.mouse_options = dw_flags;
  event.extra_info = dw_extra_info;

  mouse_interface.sendEvent(event);
}
#endif
