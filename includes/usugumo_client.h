// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _USUGUMO_CLIENT_H_
#define _USUGUMO_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum UsugumoTransportError {
  USUGUMO_TRANSPORT_NONE = 0,
  USUGUMO_TRANSPORT_WSA_STARTUP = 1,
  USUGUMO_TRANSPORT_PORT_DERIVE = 2,
  USUGUMO_TRANSPORT_SOCKET = 3,
  USUGUMO_TRANSPORT_CONNECT_REFUSED = 4,
  USUGUMO_TRANSPORT_CONNECT_TIMEOUT = 5,
  USUGUMO_TRANSPORT_CONNECT_OTHER = 6,
  USUGUMO_TRANSPORT_SEND = 7,
  USUGUMO_TRANSPORT_RECEIVE = 8,
  USUGUMO_TRANSPORT_FRAME = 9,
  USUGUMO_TRANSPORT_REJECTED = 10
} UsugumoTransportError;

#define USUGUMO_STATUS_OK 0

int32_t usugumo_client_use_driver(void);
int32_t usugumo_client_use_native(void);
void usugumo_client_shutdown(void);
int32_t usugumo_client_initialized(void);
const char* usugumo_client_backend_name(void);

int32_t usugumo_client_init_pid(uint64_t pid, uint32_t access);
int32_t usugumo_client_init_name(const char* name, uint32_t access);

#define USUGUMO_PROBE_HVCI_MASK (1ull << 32)

uint64_t usugumo_client_probe(void);
uint16_t usugumo_client_driver_version(void);
uint16_t usugumo_client_supported(void);
int32_t usugumo_client_is_connected(void);
uint16_t usugumo_client_port(void);

int32_t usugumo_client_transport_error(void);
int32_t usugumo_client_wsa_error(void);
const char* usugumo_client_transport_error_text(int32_t code);

uint64_t usugumo_client_target_pid(void);
uint64_t usugumo_client_process_handle(void);
int32_t usugumo_client_set_process_handle(uint64_t value);

int32_t usugumo_client_read(uint64_t address, void* buffer, size_t size);
int32_t usugumo_client_write(uint64_t address, const void* buffer, size_t size);

uint64_t usugumo_client_module_base(const char* module_name);
uint64_t usugumo_client_module_size(const char* module_name);
uint64_t usugumo_client_pattern_scan(uint64_t start, size_t size, const char* pattern);

int32_t usugumo_client_mouse_event(uint32_t flags, int32_t dx, int32_t dy, uint32_t data,
                                   uint64_t extra);
int32_t usugumo_client_keybd_event(uint8_t vk, uint8_t scan, uint32_t flags, uint64_t extra);
int32_t usugumo_client_mouse_move(uint32_t x, uint32_t y);
int32_t usugumo_client_set_cursor_pos(uint32_t x, uint32_t y);
int32_t usugumo_client_anti_capture(uint64_t window, int32_t enable);

uint64_t usugumo_client_secure_key(void);
uint32_t usugumo_client_protocol_version(void);
size_t usugumo_client_max_frame_size(void);

#ifdef __cplusplus
}
#endif

static inline int UseDriver(void) {
  return usugumo_client_use_driver() == USUGUMO_STATUS_OK;
}

static inline int UseNative(void) {
  return usugumo_client_use_native() == USUGUMO_STATUS_OK;
}

static inline int DriverProbe(void) {
  return usugumo_client_probe() != 0;
}

static inline int IsConnected(void) {
  return usugumo_client_is_connected() != 0;
}

static inline uint16_t GetPort(void) {
  return usugumo_client_port();
}

static inline uint64_t GetProcessHandle(void) {
  return usugumo_client_process_handle();
}

static inline int SetProcessHandle(uint64_t value) {
  return usugumo_client_set_process_handle(value);
}

static inline int Initialize(const char* process_name, uint32_t access) {
  return usugumo_client_init_name(process_name, access) == USUGUMO_STATUS_OK;
}

static inline int InitializeByPid(uint64_t pid, uint32_t access) {
  return usugumo_client_init_pid(pid, access) == USUGUMO_STATUS_OK;
}

static inline int ReadMemory(uint64_t address, void* buffer, size_t size) {
  return usugumo_client_read(address, buffer, size);
}

static inline int WriteMemory(uint64_t address, const void* buffer, size_t size) {
  return usugumo_client_write(address, buffer, size);
}

static inline uint64_t GetDllBaseAddress(const char* module_name) {
  return usugumo_client_module_base(module_name);
}

static inline uint64_t GetDllSize(const char* module_name) {
  return usugumo_client_module_size(module_name);
}

static inline uint64_t PatternScan(uint64_t start, size_t size, const char* pattern) {
  return usugumo_client_pattern_scan(start, size, pattern);
}

static inline void MouseEvent(uint32_t flags, int32_t dx, int32_t dy, uint32_t data,
                              uint64_t extra) {
  usugumo_client_mouse_event(flags, dx, dy, data, extra);
}

static inline void MouseLeftDown(void) {
  usugumo_client_mouse_event(0x0002u, 0, 0, 0, 0);
}

static inline void MouseLeftUp(void) {
  usugumo_client_mouse_event(0x0004u, 0, 0, 0, 0);
}

static inline void MouseMove(uint32_t x, uint32_t y) {
  usugumo_client_mouse_move(x, y);
}

static inline void SetCursorPos(uint32_t x, uint32_t y) {
  usugumo_client_set_cursor_pos(x, y);
}

static inline void KeybdEvent(uint8_t vk, uint8_t scan, uint32_t flags, uint64_t extra) {
  usugumo_client_keybd_event(vk, scan, flags, extra);
}

static inline void AntiCapture(uint64_t window, int enable) {
  usugumo_client_anti_capture(window, enable);
}

#ifdef __cplusplus

template <typename T>
static inline int ReadValue(uint64_t address, T* value) {
  return ReadMemory(address, static_cast<void*>(value), sizeof(T)) == (int32_t)sizeof(T);
}

template <typename T>
static inline int WriteValue(uint64_t address, const T* value) {
  return WriteMemory(address, static_cast<const void*>(value), sizeof(T)) == (int32_t)sizeof(T);
}

#else

#define ReadValue(address, value) \
  (ReadMemory((address), (void*)(value), sizeof(*(value))) == (int32_t)sizeof(*(value)))

#define WriteValue(address, value) \
  (WriteMemory((address), (const void*)(value), sizeof(*(value))) == (int32_t)sizeof(*(value)))

#endif
#endif
