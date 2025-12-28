// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _NATIVE_H_
#define _NATIVE_H_
#include <TlHelp32.h>
#include <Windows.h>
#include <psapi.h>

#include <cstdint>
#include <string>

#include "./mouse_input_injection.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID {
  PVOID UniqueProcess;
  PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE ProcessHandle,
                                        ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes,
                                        PCLIENT_ID ClientId);

typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle,
                                               PVOID BaseAddress, PVOID Buffer,
                                               ULONG NumberOfBytesToRead,
                                               PULONG NumberOfBytesRead);

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID BaseAddress, PVOID Buffer,
                                                ULONG NumberOfBytesToWrite,
                                                PULONG NumberOfBytesWritten);

typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection);

inline static OBJECT_ATTRIBUTES InitObjectAttributes(
    PUNICODE_STRING name, ULONG attributes, HANDLE hRoot,
    PSECURITY_DESCRIPTOR security) noexcept {
  OBJECT_ATTRIBUTES object;

  object.Length = sizeof(OBJECT_ATTRIBUTES);
  object.ObjectName = name;
  object.Attributes = attributes;
  object.RootDirectory = hRoot;
  object.SecurityDescriptor = security;

  return object;
}

inline static HANDLE NtOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                   DWORD dwProcessId) noexcept {
  HANDLE hProcess = 0;
  _NtOpenProcess pNtOpenProcess = (_NtOpenProcess)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
  CLIENT_ID clientId = {(PVOID)(ULONG_PTR)dwProcessId, NULL};
  OBJECT_ATTRIBUTES objAttr = InitObjectAttributes(NULL, 0, NULL, NULL);
  pNtOpenProcess(&hProcess, dwDesiredAccess, &objAttr, &clientId);
  return hProcess;
}

inline static pNtReadVirtualMemory NtReadVirtualMemory = []() {
  return reinterpret_cast<pNtReadVirtualMemory>(
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"));
}();
inline static pNtWriteVirtualMemory NtWriteVirtualMemory = []() {
  return reinterpret_cast<pNtWriteVirtualMemory>(
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
}();
inline static pNtProtectVirtualMemory NtProtectVirtualMemory = []() {
  return reinterpret_cast<pNtProtectVirtualMemory>(
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"));
}();

class Native {
 public:
  Native() : target_process_handle_(nullptr), target_process_id_(0) {}

  ~Native() {
    if (target_process_handle_) {
      CloseHandle(target_process_handle_);
    }
  }

  bool Initialize(uint64_t process_id,
                  DWORD desired_access = PROCESS_ALL_ACCESS) {
    target_process_id_ = static_cast<DWORD>(process_id);
    target_process_handle_ =
        NtOpenProcess(desired_access, FALSE, target_process_id_);
    return target_process_handle_ != nullptr;
  }

  bool Initialize(const wchar_t* process_name,
                  DWORD desired_access = PROCESS_ALL_ACCESS) {
    DWORD pid = GetProcessIdByName(process_name);
    if (pid == 0) {
      return false;
    }
    return Initialize(static_cast<uint64_t>(pid), desired_access);
  }

  // too complex stuff, I dont like it.
  struct SafeULONG {
    ULONG value;  // We just need this
    ULONG reserved;
  };

  bool ReadMemoryNt(uintptr_t address, void* buffer, size_t size) {
    if (!target_process_handle_) return false;

    alignas(8) SafeULONG bytes_wrapper = {0, 0};
    NTSTATUS status = NtReadVirtualMemory(
        target_process_handle_, reinterpret_cast<PVOID>(address), buffer,
        static_cast<ULONG>(size), &(bytes_wrapper.value));
    return NT_SUCCESS(status) &&
           static_cast<size_t>(bytes_wrapper.value) == size;
  }

  bool WriteMemoryNt(uintptr_t address, const void* buffer, size_t size) {
    if (!target_process_handle_ || !buffer || size == 0) {
      return false;
    }

    PVOID pBaseAddr = reinterpret_cast<PVOID>(address);
    SIZE_T sSize = static_cast<SIZE_T>(size);
    ULONG oldProtect = 0;

    NTSTATUS status_protect =
        NtProtectVirtualMemory(target_process_handle_, &pBaseAddr, &sSize,
                               PAGE_READWRITE, &oldProtect);

    if (!NT_SUCCESS(status_protect)) {
      return false;
    }

    alignas(8) SafeULONG bytes_wrapper = {0, 0};
    NTSTATUS status_write = NtWriteVirtualMemory(
        target_process_handle_, reinterpret_cast<PVOID>(address),
        const_cast<PVOID>(buffer), static_cast<ULONG>(size),
        &(bytes_wrapper.value));

    ULONG temp = 0;
    NtProtectVirtualMemory(target_process_handle_, &pBaseAddr, &sSize,
                           oldProtect, &temp);

    return NT_SUCCESS(status_write) &&
           static_cast<size_t>(bytes_wrapper.value) == size;
  }

  uint64_t GetDllBaseAddress(const char* dll_name) {
    if (!target_process_handle_) return 0;

    HMODULE modules[1024];
    DWORD needed;

    if (EnumProcessModules(target_process_handle_, modules, sizeof(modules),
                           &needed)) {
      int module_count = needed / sizeof(HMODULE);

      for (int i = 0; i < module_count; i++) {
        char module_name[MAX_PATH];
        if (GetModuleFileNameExA(target_process_handle_, modules[i],
                                 module_name, sizeof(module_name))) {
          std::string name(module_name);
          size_t pos = name.find_last_of("\\/");
          if (pos != std::string::npos) {
            name = name.substr(pos + 1);
          }

          if (_stricmp(name.c_str(), dll_name) == 0) {
            return reinterpret_cast<uint64_t>(modules[i]);
          }
        }
      }
    }

    return 0;
  }

  uint64_t GetDllSize(const char* dll_name) {
    if (!target_process_handle_) return 0;

    HMODULE modules[1024];
    DWORD needed;

    if (EnumProcessModules(target_process_handle_, modules, sizeof(modules),
                           &needed)) {
      int module_count = needed / sizeof(HMODULE);

      for (int i = 0; i < module_count; i++) {
        char module_name[MAX_PATH];
        if (GetModuleFileNameExA(target_process_handle_, modules[i],
                                 module_name, sizeof(module_name))) {
          std::string name(module_name);
          size_t pos = name.find_last_of("\\/");
          if (pos != std::string::npos) {
            name = name.substr(pos + 1);
          }

          if (_stricmp(name.c_str(), dll_name) == 0) {
            MODULEINFO module_info;
            if (GetModuleInformation(target_process_handle_, modules[i],
                                     &module_info, sizeof(module_info))) {
              return module_info.SizeOfImage;
            }
          }
        }
      }
    }

    return 0;
  }

  void MouseEvent(DWORD flags, DWORD x, DWORD y, DWORD data,
                  ULONG_PTR extra_info) {
    LONG dx = (LONG)x;
    LONG dy = (LONG)y;

    my_mouse_event(flags, dx, dy, data, extra_info);
  }

  void MouseLeftDown() { MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); }

  void MouseLeftUp() { MouseEvent(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); }

  void MouseMove(DWORD x, DWORD y) {
    if (dpi_ == 0) dpi_ = GetSystemDPI();
    DWORD dx = (x * 100 + dpi_ / 2) / dpi_;
    DWORD dy = (y * 100 + dpi_ / 2) / dpi_;
    MouseEvent(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
  }

  void SetCursorPos(DWORD x, DWORD y) {
    int screen_width = GetSystemMetrics(SM_CXSCREEN) - 1;
    int screen_height = GetSystemMetrics(SM_CYSCREEN) - 1;
    int virtual_x = (x * 65535) / screen_width;
    int virtual_y = (y * 65535) / screen_height;
    MouseEvent(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, virtual_x, virtual_y, 0,
               0);
  }

  HANDLE GetProcessHandle() const { return target_process_handle_; }
  DWORD GetProcessId() const { return target_process_id_; }

  void AntiCapture(HWND window_handle, bool status = true) {
    if (status){
      SetWindowDisplayAffinity(window_handle, WDA_EXCLUDEFROMCAPTURE);
    } else {
      SetWindowDisplayAffinity(window_handle, WDA_NONE);
    }
  }

 private:
  HANDLE target_process_handle_;
  DWORD target_process_id_;
  int dpi_ = 0;

  static int GetSystemDPI() {
    HDC hdc = GetDC(nullptr);
    int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    ReleaseDC(nullptr, hdc);
    return dpi;
  }

  static DWORD GetProcessIdByName(const wchar_t* process_name) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
      return 0;
    }

    if (!Process32FirstW(snapshot, &pe32)) {
      CloseHandle(snapshot);
      return 0;
    }

    DWORD pid = 0;
    do {
      if (_wcsicmp(pe32.szExeFile, process_name) == 0) {
        pid = pe32.th32ProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return pid;
  }
};

#endif
