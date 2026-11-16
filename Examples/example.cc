// Copyright (c) 2026 渟雲. All rights reserved.

// One example, three builds:
//   DRIVER  - links usugumo_driver.lib
//   NATIVE  - links usugumo_native.lib
//   DYNAMIC - loads usugumo_driver.dll or usugumo_native.dll at run time

#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#include "./window_helper.h"

#if defined(USING_USUGUMO) && defined(DYNAMIC)
#define USE_DRIVER_BACKEND 1
#define ASK_BACKEND 0

#define USUGUMO_STATUS_OK 0
#define USUGUMO_TRANSPORT_CONNECT_REFUSED 4
#define USUGUMO_TRANSPORT_RECEIVE 8

const char* usugumo_client_transport_error_text(int32_t code);
#elif defined(USING_USUGUMO)
#include "../includes/usugumo_client.h"
#define USE_DRIVER_BACKEND 1
#define ASK_BACKEND 0
#elif defined(DYNAMIC)
#define USE_DRIVER_BACKEND 0
#define ASK_BACKEND 1

#define USUGUMO_STATUS_OK 0
#define USUGUMO_TRANSPORT_CONNECT_REFUSED 4
#define USUGUMO_TRANSPORT_RECEIVE 8

const char* usugumo_client_transport_error_text(int32_t code);
#else
#include "../includes/usugumo_client.h"
#define USE_DRIVER_BACKEND 0
#define ASK_BACKEND 0
#endif

using Address = uintptr_t;
using SizeType = size_t;

constexpr inline uint64_t TEST_WRITE_VALUE = 0x1919810ULL;
constexpr inline std::wstring_view TARGET_PROCESS_NAME = L"target.exe";
// only for my build, you should make your own pattern
constexpr inline std::string_view TARGET_PATTERN = "48 8B 15 ? ? ? ? 48 89 C1";

namespace {

struct Api {
  void* module = nullptr;
  bool is_driver = false;

  int (*use_driver)(void) = nullptr;
  int (*use_native)(void) = nullptr;
  void (*shutdown)(void) = nullptr;
  const char* (*backend_name)(void) = nullptr;

  int (*init_name)(const char*, uint32_t) = nullptr;
  int (*probe)(void) = nullptr;
  int (*is_connected)(void) = nullptr;
  uint16_t (*port)(void) = nullptr;
  int (*transport_error)(void) = nullptr;
  int (*wsa_error)(void) = nullptr;
  const char* (*transport_error_text)(int32_t) = nullptr;

  uint64_t (*process_handle)(void) = nullptr;
  int32_t (*read)(uint64_t, void*, size_t) = nullptr;
  int32_t (*write)(uint64_t, const void*, size_t) = nullptr;
  uint64_t (*module_base)(const char*) = nullptr;
  uint64_t (*module_size)(const char*) = nullptr;
  uint64_t (*pattern_scan)(uint64_t, size_t, const char*) = nullptr;

  int32_t (*mouse_event)(uint32_t, int32_t, int32_t, uint32_t, uint64_t) = nullptr;
  int32_t (*keybd_event)(uint8_t, uint8_t, uint32_t, uint64_t) = nullptr;
  int32_t (*mouse_move)(uint32_t, uint32_t) = nullptr;
  int32_t (*set_cursor_pos)(uint32_t, uint32_t) = nullptr;
  int32_t (*anti_capture)(uint64_t, int32_t) = nullptr;
};

#ifdef DYNAMIC

template <typename T>
bool Bind(HMODULE module, const char* symbol, T* slot) {
  *slot = reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(module, symbol)));
  if (*slot == nullptr) {
    printf("[-] %s is missing from the library\n", symbol);
    return false;
  }
  return true;
}

bool LoadApi(Api& api, bool use_driver) {
  api.is_driver = use_driver;
  api.module = LoadLibraryA(use_driver ? "usugumo_driver.dll" : "usugumo_native.dll");
  if (api.module == nullptr) {
    printf("[-] LoadLibrary failed, error %lu\n", GetLastError());
    return false;
  }
  printf("Backend library: %s\n", use_driver ? "usugumo_driver.dll" : "usugumo_native.dll");

  HMODULE m = static_cast<HMODULE>(api.module);
  const bool ok =
      Bind(m, use_driver ? "usugumo_client_use_driver" : "usugumo_client_use_native",
           use_driver ? &api.use_driver : &api.use_native) &&
      Bind(m, "usugumo_client_shutdown", &api.shutdown) &&
      Bind(m, "usugumo_client_backend_name", &api.backend_name) &&
      Bind(m, "usugumo_client_init_name", &api.init_name) &&
      Bind(m, "usugumo_client_probe", &api.probe) &&
      Bind(m, "usugumo_client_is_connected", &api.is_connected) &&
      Bind(m, "usugumo_client_port", &api.port) &&
      Bind(m, "usugumo_client_transport_error", &api.transport_error) &&
      Bind(m, "usugumo_client_wsa_error", &api.wsa_error) &&
      Bind(m, "usugumo_client_transport_error_text", &api.transport_error_text) &&
      Bind(m, "usugumo_client_process_handle", &api.process_handle) &&
      Bind(m, "usugumo_client_read", &api.read) &&
      Bind(m, "usugumo_client_write", &api.write) &&
      Bind(m, "usugumo_client_module_base", &api.module_base) &&
      Bind(m, "usugumo_client_module_size", &api.module_size) &&
      Bind(m, "usugumo_client_pattern_scan", &api.pattern_scan) &&
      Bind(m, "usugumo_client_mouse_event", &api.mouse_event) &&
      Bind(m, "usugumo_client_keybd_event", &api.keybd_event) &&
      Bind(m, "usugumo_client_mouse_move", &api.mouse_move) &&
      Bind(m, "usugumo_client_set_cursor_pos", &api.set_cursor_pos) &&
      Bind(m, "usugumo_client_anti_capture", &api.anti_capture);
  return ok;
}

void UnloadApi(Api& api) {
  if (api.module != nullptr) {
    FreeLibrary(static_cast<HMODULE>(api.module));
  }
}

#else

bool LoadApi(Api& api, bool use_driver) {
  api.is_driver = use_driver;
  api.use_driver = usugumo_client_use_driver;
  api.use_native = usugumo_client_use_native;
  api.shutdown = usugumo_client_shutdown;
  api.backend_name = usugumo_client_backend_name;
  api.init_name = usugumo_client_init_name;
  api.probe = usugumo_client_probe;
  api.is_connected = usugumo_client_is_connected;
  api.port = usugumo_client_port;
  api.transport_error = usugumo_client_transport_error;
  api.wsa_error = usugumo_client_wsa_error;
  api.transport_error_text = usugumo_client_transport_error_text;
  api.process_handle = usugumo_client_process_handle;
  api.read = usugumo_client_read;
  api.write = usugumo_client_write;
  api.module_base = usugumo_client_module_base;
  api.module_size = usugumo_client_module_size;
  api.pattern_scan = usugumo_client_pattern_scan;
  api.mouse_event = usugumo_client_mouse_event;
  api.keybd_event = usugumo_client_keybd_event;
  api.mouse_move = usugumo_client_mouse_move;
  api.set_cursor_pos = usugumo_client_set_cursor_pos;
  api.anti_capture = usugumo_client_anti_capture;
  return true;
}

void UnloadApi(Api&) {}

#endif

int Fail(WindowData& windowData, const UniqueThreadPtr& thread, const char* message) {
  printf("%s\n", message);
  StopWindowThread(windowData, thread);
  system("pause");
  return 1;
}

}  // namespace

int main() {
  WindowData windowData;
  UniqueThreadPtr windowThread = CreateWindowThread(windowData);
  if (!windowThread) {
    printf("Failed to create window thread.\n");
    system("pause");
    return 1;
  }

#if ASK_BACKEND
  printf("use driver? [y/N]: ");
  std::fflush(stdout);
  char choice[8] = {0};
  if (std::fgets(choice, sizeof(choice), stdin) == nullptr) {
    choice[0] = 0;
  }
  const bool want_driver = choice[0] == 'y' || choice[0] == 'Y';
#elif USE_DRIVER_BACKEND
  const bool want_driver = true;
#else
  const bool want_driver = false;
#endif

  Api api;
  if (!LoadApi(api, want_driver)) {
    StopWindowThread(windowData, windowThread);
    system("pause");
    return 1;
  }

  const int selected = want_driver ? api.use_driver() : api.use_native();
  if (selected != USUGUMO_STATUS_OK) {
    return Fail(windowData, windowThread, "Failed to select backend");
  }
  printf("Backend: %s\n", api.backend_name());

  if (!api.probe()) {
    if (want_driver) {
      printf("Driver probe failed\n");
      printf("  derived port : %u\n", static_cast<unsigned>(api.port()));
      printf("  transport    : %s\n", api.transport_error_text(api.transport_error()));
      printf("  WSA error    : %d\n", api.wsa_error());
      const int code = api.transport_error();
      if (code == USUGUMO_TRANSPORT_CONNECT_REFUSED) {
        printf("  hint         : the driver is not loaded, or it failed to start.\n");
        printf("                 check DriverEntry result and whether the port is listening:\n");
        printf("                 Get-NetTCPConnection -LocalPort %u -State Listen\n",
               static_cast<unsigned>(api.port()));
      } else if (code == USUGUMO_TRANSPORT_RECEIVE) {
        printf("  hint         : connected but the driver rejected the request;\n");
        printf("                 timestamp/CRC64/secure_key validation failed.\n");
      }
    }
    StopWindowThread(windowData, windowThread);
    UnloadApi(api);
    system("pause");
    return 1;
  }
  printf(want_driver ? "Driver probe success\n" : "Using native api\n");

  std::string targetProcessName(TARGET_PROCESS_NAME.begin(), TARGET_PROCESS_NAME.end());
  if (api.init_name(targetProcessName.c_str(), 0) != USUGUMO_STATUS_OK) {
    UnloadApi(api);
    return Fail(windowData, windowThread, "Failed to initialize");
  }
  if (want_driver) {
    printf("Driver TCP link established on port %u\n",
           static_cast<unsigned>(api.port()));
  } else {
    printf("Process handle created 0x%llX\n",
           static_cast<unsigned long long>(api.process_handle()));
  }

  uint64_t base_address = api.module_base(targetProcessName.c_str());
  uint64_t module_size = api.module_size(targetProcessName.c_str());
  if (base_address == 0 || module_size == 0) {
    UnloadApi(api);
    return Fail(windowData, windowThread, "Failed to get module info");
  }
  printf("Module base: 0x%llX, size: 0x%llX\n",
         static_cast<unsigned long long>(base_address),
         static_cast<unsigned long long>(module_size));

  Address pattern_addr =
      api.pattern_scan(base_address, static_cast<size_t>(module_size), TARGET_PATTERN.data());
  if (pattern_addr == 0) {
    UnloadApi(api);
    return Fail(windowData, windowThread, "Failed to find target pattern");
  }
  printf("Target pattern found at: 0x%llX\n", static_cast<unsigned long long>(pattern_addr));

  int32_t disp32 = 0;
  if (api.read(pattern_addr + 3, &disp32, sizeof(disp32)) != static_cast<int32_t>(sizeof(disp32))) {
    UnloadApi(api);
    return Fail(windowData, windowThread, "Failed to read displacement");
  }

  // here hard coded, you should using hde64 or zydis to decode the instruction length
  Address resolved_addr = pattern_addr + 7 + disp32;
  printf("Resolved target address: 0x%llX\n", static_cast<unsigned long long>(resolved_addr));

  uint64_t target_var = 0;
  if (api.read(resolved_addr, &target_var, sizeof(target_var)) !=
      static_cast<int32_t>(sizeof(target_var))) {
    printf("Failed to read memory\n");
  } else {
    printf("Read target_var = 0x%llX at 0x%llX\n",
           static_cast<unsigned long long>(target_var),
           static_cast<unsigned long long>(resolved_addr));
  }

  if (api.write(resolved_addr, &TEST_WRITE_VALUE, sizeof(TEST_WRITE_VALUE)) !=
      static_cast<int32_t>(sizeof(TEST_WRITE_VALUE))) {
    printf("Failed to write memory\n");
  } else {
    printf("Written 0x%llX to 0x%llX\n", static_cast<unsigned long long>(TEST_WRITE_VALUE),
           static_cast<unsigned long long>(resolved_addr));
  }

  if (api.read(resolved_addr, &target_var, sizeof(target_var)) ==
      static_cast<int32_t>(sizeof(target_var))) {
    printf("Read back target_var = 0x%llX\n", static_cast<unsigned long long>(target_var));
  }

  printf("Waiting 3 second then mouse left down...\n");
  Sleep(3000);
  api.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);

  printf("Waiting 1 second then mouse left up...\n");
  Sleep(1000);
  api.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

  printf("Waiting 3 second then move mouse (100, -100)...\n");
  Sleep(3000);
  api.mouse_move(100, static_cast<uint32_t>(-100));

  printf("Waiting 3 second then set cursor position (500, 500)...\n");
  Sleep(3000);
  api.set_cursor_pos(500, 500);

  printf("Waiting 1 second then press VK_LWIN...\n");
  Sleep(1000);
  api.keybd_event(VK_LWIN, 0, 0, 0);
  Sleep(100);
  api.keybd_event(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);

  printf("Waiting 1 second then anti capture test window...\n");
  Sleep(1000);

  if (windowData.hwnd && IsWindow(windowData.hwnd)) {
    api.anti_capture(reinterpret_cast<uint64_t>(windowData.hwnd), 1);
    printf("Anti capture applied to window.\n");
  } else {
    printf("Window handle is invalid.\n");
  }

  printf("Waiting input then undo anti capture test window...\n");
  system("pause");

  if (windowData.hwnd && IsWindow(windowData.hwnd)) {
    api.anti_capture(reinterpret_cast<uint64_t>(windowData.hwnd), 0);
    printf("Anti capture removed from window.\n");
  }

  printf("Waiting 3 second then destroy test window...\n");
  Sleep(3000);

  windowData.windowRunning = false;
  if (windowData.hwnd && IsWindow(windowData.hwnd)) {
    PostMessage(windowData.hwnd, WM_CLOSE, 0, 0);
  }

  WaitForSingleObject(windowThread.get(), DESTROY_WINDOW_TIMEOUT);

  printf("Done\n");

  api.shutdown();
  UnloadApi(api);

  system("pause");
  return 0;
}
