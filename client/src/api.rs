// Copyright (c) 2026 渟雲. All rights reserved.

use std::ffi::{c_char, c_void};
use std::sync::Once;

use crate::backend::Backend;
use crate::protocol;
use crate::scan::{CHUNK_SIZE, Pattern, find_in_chunk};

#[cfg(all(target_os = "windows", target_env = "msvc", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn __chkstk() {}

#[link(name = "user32")]
unsafe extern "system" {
    fn GetSystemMetrics(index: i32) -> i32;
    fn GetDC(window: usize) -> usize;
    fn ReleaseDC(window: usize, dc: usize) -> i32;
}

#[link(name = "gdi32")]
unsafe extern "system" {
    fn GetDeviceCaps(dc: usize, index: i32) -> i32;
}

fn system_dpi() -> i32 {
    let dc = unsafe { GetDC(0) };
    if dc == 0 {
        return 96;
    }
    let dpi = unsafe { GetDeviceCaps(dc, 88) };
    unsafe {
        ReleaseDC(0, dc);
    }
    dpi
}

pub struct UsugumoClient {
    backend: Box<dyn Backend>,
    dpi: i32,
}

#[cfg(feature = "driver")]
fn make_default() -> UsugumoClient {
    UsugumoClient {
        backend: Box::new(crate::backend::driver::DriverBackend::new()),
        dpi: 0,
    }
}

#[cfg(all(not(feature = "driver"), feature = "native"))]
fn make_default() -> UsugumoClient {
    UsugumoClient {
        backend: Box::new(crate::backend::native_backend::NativeBackend::new()),
        dpi: 0,
    }
}

#[cfg(all(not(feature = "driver"), not(feature = "native")))]
struct NoBackend;

#[cfg(all(not(feature = "driver"), not(feature = "native")))]
impl Backend for NoBackend {
    fn name(&self) -> &'static str {
        "none"
    }
    fn init_pid(&mut self, _pid: u64, _access: u32) -> bool {
        false
    }
    fn init_name(&mut self, _name: &[u8], _access: u32) -> bool {
        false
    }
    fn probe(&mut self) -> bool {
        false
    }
    fn driver_version(&self) -> u16 {
        0
    }
    fn supported(&self) -> u16 {
        0
    }
    fn is_connected(&self) -> bool {
        false
    }
    fn port(&self) -> u16 {
        0
    }
    fn transport_error(&self) -> i32 {
        0
    }
    fn wsa_error(&self) -> i32 {
        0
    }
    fn target_pid(&self) -> u64 {
        0
    }
    fn process_handle(&self) -> u64 {
        0
    }
    fn set_process_handle(&mut self, _handle: u64) -> bool {
        false
    }
    fn read(&mut self, _a: u64, _b: *mut c_void, _s: usize) -> bool {
        false
    }
    fn write(&mut self, _a: u64, _b: *const c_void, _s: usize) -> bool {
        false
    }
    fn module_base(&mut self, _n: &[u8]) -> u64 {
        0
    }
    fn module_size(&mut self, _n: &[u8]) -> u64 {
        0
    }
    fn mouse_event(&mut self, _f: u32, _x: i32, _y: i32, _d: u32, _e: u64) -> bool {
        false
    }
    fn keybd_event(&mut self, _v: u8, _s: u8, _f: u32, _e: u64) -> bool {
        false
    }
    fn anti_capture(&mut self, _w: u64, _e: bool) -> bool {
        false
    }
}

#[cfg(all(not(feature = "driver"), not(feature = "native")))]
fn make_default() -> UsugumoClient {
    UsugumoClient {
        backend: Box::new(NoBackend),
        dpi: 0,
    }
}

static ONCE: Once = Once::new();
static mut INSTANCE: *mut UsugumoClient = core::ptr::null_mut();

fn instance() -> Option<&'static mut UsugumoClient> {
    ONCE.call_once(|| unsafe {
        INSTANCE = Box::into_raw(Box::new(make_default()));
    });
    unsafe {
        if INSTANCE.is_null() {
            None
        } else {
            Some(&mut *INSTANCE)
        }
    }
}

#[cfg(feature = "native")]
fn rebuild_native() {
    unsafe {
        if !INSTANCE.is_null() {
            drop(Box::from_raw(INSTANCE));
        }
        INSTANCE = Box::into_raw(Box::new(UsugumoClient {
            backend: Box::new(crate::backend::native_backend::NativeBackend::new()),
            dpi: 0,
        }));
    }
}

#[cfg(feature = "driver")]
fn rebuild_driver() {
    unsafe {
        if !INSTANCE.is_null() {
            drop(Box::from_raw(INSTANCE));
        }
        INSTANCE = Box::into_raw(Box::new(UsugumoClient {
            backend: Box::new(crate::backend::driver::DriverBackend::new()),
            dpi: 0,
        }));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_use_driver() -> i32 {
    #[cfg(feature = "driver")]
    {
        rebuild_driver();
        0
    }
    #[cfg(not(feature = "driver"))]
    {
        -3
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_use_native() -> i32 {
    #[cfg(feature = "native")]
    {
        rebuild_native();
        0
    }
    #[cfg(not(feature = "native"))]
    {
        -3
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_shutdown() {
    unsafe {
        if !INSTANCE.is_null() {
            drop(Box::from_raw(INSTANCE));
            INSTANCE = core::ptr::null_mut();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_initialized() -> i32 {
    instance().map(|_| 1).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_backend_name() -> *const c_char {
    match instance() {
        Some(c) => c.backend.name().as_ptr() as *const c_char,
        None => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_init_name(name: *const c_char, access: u32) -> i32 {
    let Some(client) = instance() else {
        return -2;
    };
    if name.is_null() {
        return -2;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(name) }
        .to_bytes()
        .to_vec();
    if client.backend.init_name(&bytes, access) {
        0
    } else {
        -2
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_init_pid(pid: u64, access: u32) -> i32 {
    let Some(client) = instance() else {
        return -2;
    };
    if client.backend.init_pid(pid, access) {
        0
    } else {
        -2
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_probe() -> i32 {
    match instance() {
        Some(c) => c.backend.probe() as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_driver_version() -> u16 {
    instance().map(|c| c.backend.driver_version()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_supported() -> u16 {
    instance().map(|c| c.backend.supported()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_is_connected() -> i32 {
    instance()
        .map(|c| c.backend.is_connected() as i32)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_port() -> u16 {
    instance().map(|c| c.backend.port()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_transport_error() -> i32 {
    instance().map(|c| c.backend.transport_error()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_wsa_error() -> i32 {
    instance().map(|c| c.backend.wsa_error()).unwrap_or(0)
}

static ERROR_TEXT: [&str; 11] = [
    "none\0",
    "WSAStartup failed\0",
    "port derivation failed\0",
    "socket() failed\0",
    "connection refused - driver not loaded or not listening on the derived port\0",
    "connection timed out - a filter or firewall is dropping loopback\0",
    "connect() failed\0",
    "send failed - driver closed the connection\0",
    "recv failed - driver closed or rejected the request\0",
    "protocol framing error - reply was malformed\0",
    "driver rejected the request - timestamp, CRC64 or secure key mismatch\0",
];

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_transport_error_text(code: i32) -> *const c_char {
    let idx = if (0..ERROR_TEXT.len() as i32).contains(&code) {
        code as usize
    } else {
        ERROR_TEXT.len() - 1
    };
    ERROR_TEXT[idx].as_ptr() as *const c_char
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_process_handle() -> u64 {
    instance().map(|c| c.backend.process_handle()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_set_process_handle(value: u64) -> i32 {
    match instance() {
        Some(c) => c.backend.set_process_handle(value) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_target_pid() -> u64 {
    instance().map(|c| c.backend.target_pid()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_read(address: u64, buffer: *mut c_void, size: usize) -> i32 {
    match instance() {
        Some(c) => c.backend.read(address, buffer, size) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_write(address: u64, buffer: *const c_void, size: usize) -> i32 {
    match instance() {
        Some(c) => c.backend.write(address, buffer, size) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_module_base(name: *const c_char) -> u64 {
    let Some(client) = instance() else {
        return 0;
    };
    if name.is_null() {
        return 0;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(name) }
        .to_bytes()
        .to_vec();
    client.backend.module_base(&bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_module_size(name: *const c_char) -> u64 {
    let Some(client) = instance() else {
        return 0;
    };
    if name.is_null() {
        return 0;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(name) }
        .to_bytes()
        .to_vec();
    client.backend.module_size(&bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_pattern_scan(
    start: u64,
    size: usize,
    pattern: *const c_char,
) -> u64 {
    let Some(client) = instance() else {
        return 0;
    };
    if pattern.is_null() || size == 0 || start == 0 {
        return 0;
    }
    let text = match unsafe { std::ffi::CStr::from_ptr(pattern) }.to_str() {
        Ok(t) => t,
        Err(_) => return 0,
    };
    let Some(parsed) = Pattern::parse(text) else {
        return 0;
    };
    let plen = parsed.len();
    let mut buffer = vec![0u8; CHUNK_SIZE + plen];
    let mut offset = 0usize;
    while offset < size {
        let want = std::cmp::min(CHUNK_SIZE + plen - 1, size - offset);
        if want < plen {
            break;
        }
        if client.backend.read(
            start + offset as u64,
            buffer.as_mut_ptr() as *mut c_void,
            want,
        ) as usize
            != want
        {
            offset += CHUNK_SIZE;
            continue;
        }
        if let Some(rel) = find_in_chunk(&buffer[..want], &parsed) {
            return start + offset as u64 + rel as u64;
        }
        offset += CHUNK_SIZE;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_mouse_event(
    flags: u32,
    dx: i32,
    dy: i32,
    data: u32,
    extra: u64,
) -> i32 {
    match instance() {
        Some(c) => c.backend.mouse_event(flags, dx, dy, data, extra) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_keybd_event(vk: u8, scan: u8, flags: u32, extra: u64) -> i32 {
    match instance() {
        Some(c) => c.backend.keybd_event(vk, scan, flags, extra) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_mouse_move(x: u32, y: u32) -> i32 {
    let Some(client) = instance() else {
        return 0;
    };
    if client.dpi == 0 {
        client.dpi = system_dpi();
    }
    let dpi = client.dpi.max(1) as u32;
    let dx = ((x * 100 + dpi / 2) / dpi) as i32;
    let dy = ((y * 100 + dpi / 2) / dpi) as i32;
    client.backend.mouse_event(0x0001, dx, dy, 0, 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_set_cursor_pos(x: u32, y: u32) -> i32 {
    let Some(client) = instance() else {
        return 0;
    };
    if x > i32::MAX as u32 || y > i32::MAX as u32 {
        return 0;
    }
    let width = unsafe { GetSystemMetrics(0) } - 1;
    let height = unsafe { GetSystemMetrics(1) } - 1;
    if width <= 0 || height <= 0 {
        return 0;
    }
    let vx = (x * 65535 / width as u32) as i32;
    let vy = (y * 65535 / height as u32) as i32;
    client.backend.mouse_event(0x0001 | 0x8000, vx, vy, 0, 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_anti_capture(window: u64, enable: i32) -> i32 {
    match instance() {
        Some(c) => c.backend.anti_capture(window, enable != 0) as i32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_secure_key() -> u64 {
    crate::SECURE_KEY
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_protocol_version() -> u32 {
    protocol::PROTOCOL_VERSION as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn usugumo_client_max_frame_size() -> usize {
    protocol::MAX_FRAME_SIZE
}
