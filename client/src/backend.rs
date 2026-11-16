// Copyright (c) 2026 渟雲. All rights reserved.

use std::ffi::c_void;

pub(crate) trait Backend: Send {
    fn name(&self) -> &'static str;
    fn init_pid(&mut self, pid: u64, access: u32) -> bool;
    fn init_name(&mut self, name: &[u8], access: u32) -> bool;
    fn probe(&mut self) -> bool;
    fn driver_version(&self) -> u16;
    fn supported(&self) -> u16;
    fn is_connected(&self) -> bool;
    fn port(&self) -> u16;
    fn transport_error(&self) -> i32;
    fn wsa_error(&self) -> i32;
    fn target_pid(&self) -> u64;
    fn process_handle(&self) -> u64;
    fn set_process_handle(&mut self, handle: u64) -> bool;
    fn read(&mut self, address: u64, buffer: *mut c_void, size: usize) -> u32;
    fn write(&mut self, address: u64, buffer: *const c_void, size: usize) -> u32;
    fn module_base(&mut self, name: &[u8]) -> u64;
    fn module_size(&mut self, name: &[u8]) -> u64;
    fn mouse_event(&mut self, flags: u32, dx: i32, dy: i32, data: u32, extra: u64) -> bool;
    fn keybd_event(&mut self, vk: u8, scan: u8, flags: u32, extra: u64) -> bool;
    fn anti_capture(&mut self, window: u64, enable: bool) -> bool;
}

#[cfg(feature = "driver")]
pub(crate) mod driver {
    use std::ffi::c_void;

    use crate::backend::Backend;
    use crate::session::Session;

    pub(crate) struct DriverBackend(Session);

    impl DriverBackend {
        pub(crate) fn new() -> Self {
            Self(Session::new())
        }
    }

    impl Backend for DriverBackend {
        fn name(&self) -> &'static str {
            "driver"
        }

        fn init_pid(&mut self, pid: u64, _access: u32) -> bool {
            if !self.0.ensure_connected() {
                return false;
            }
            self.0.set_target_pid(pid);
            true
        }

        fn init_name(&mut self, name: &[u8], _access: u32) -> bool {
            if !self.0.ensure_connected() {
                return false;
            }
            let pid = self.0.process_id_by_name(name);
            if pid == 0 {
                return false;
            }
            self.0.set_target_pid(pid);
            true
        }

        fn probe(&mut self) -> bool {
            if !self.0.ensure_connected() {
                return false;
            }
            self.0.probe()
        }
        fn driver_version(&self) -> u16 {
            self.0.driver_version()
        }
        fn supported(&self) -> u16 {
            self.0.supported()
        }
        fn is_connected(&self) -> bool {
            self.0.is_connected()
        }
        fn port(&self) -> u16 {
            self.0.port()
        }
        fn transport_error(&self) -> i32 {
            self.0.last_error() as i32
        }
        fn wsa_error(&self) -> i32 {
            self.0.last_wsa_error()
        }
        fn target_pid(&self) -> u64 {
            self.0.target_pid()
        }
        fn process_handle(&self) -> u64 {
            0
        }

        fn set_process_handle(&mut self, _handle: u64) -> bool {
            false
        }

        fn read(&mut self, address: u64, buffer: *mut c_void, size: usize) -> u32 {
            self.0.read_memory(address, buffer as u64, size)
        }

        fn write(&mut self, address: u64, buffer: *const c_void, size: usize) -> u32 {
            self.0.write_memory(address, buffer as u64, size)
        }

        fn module_base(&mut self, name: &[u8]) -> u64 {
            self.0.module_base(name)
        }

        fn module_size(&mut self, name: &[u8]) -> u64 {
            self.0.module_size(name)
        }

        fn mouse_event(&mut self, flags: u32, dx: i32, dy: i32, data: u32, extra: u64) -> bool {
            self.0.mouse_event(flags, dx, dy, data, extra)
        }

        fn keybd_event(&mut self, vk: u8, scan: u8, flags: u32, extra: u64) -> bool {
            self.0.keybd_event(vk, scan, flags, extra)
        }

        fn anti_capture(&mut self, window: u64, enable: bool) -> bool {
            self.0.anti_capture(window, enable)
        }
    }
}

#[cfg(feature = "native")]
pub(crate) mod native_backend {
    use std::ffi::c_void;

    use crate::backend::Backend;
    use crate::native::{Native, PROCESS_ALL_ACCESS, to_wide};

    pub(crate) struct NativeBackend(Native);

    impl NativeBackend {
        pub(crate) fn new() -> Self {
            Self(Native::new())
        }
    }

    fn mask(access: u32) -> u32 {
        if access == 0 {
            PROCESS_ALL_ACCESS
        } else {
            access
        }
    }

    impl Backend for NativeBackend {
        fn name(&self) -> &'static str {
            "native"
        }

        fn init_pid(&mut self, pid: u64, access: u32) -> bool {
            self.0.open_by_pid(pid, mask(access))
        }

        fn init_name(&mut self, name: &[u8], access: u32) -> bool {
            self.0.open_by_name(&to_wide(name), mask(access))
        }

        fn probe(&mut self) -> bool {
            true
        }
        fn driver_version(&self) -> u16 {
            0
        }
        fn supported(&self) -> u16 {
            0
        }
        fn is_connected(&self) -> bool {
            self.0.raw_handle() != 0
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
            self.0.pid()
        }
        fn process_handle(&self) -> u64 {
            self.0.raw_handle() as u64
        }

        fn set_process_handle(&mut self, handle: u64) -> bool {
            self.0.adopt_handle(handle as usize)
        }

        fn read(&mut self, address: u64, buffer: *mut c_void, size: usize) -> u32 {
            self.0.read(address, buffer, size)
        }

        fn write(&mut self, address: u64, buffer: *const c_void, size: usize) -> u32 {
            self.0.write(address, buffer, size)
        }

        fn module_base(&mut self, name: &[u8]) -> u64 {
            self.0.module_base(&to_wide(name))
        }

        fn module_size(&mut self, name: &[u8]) -> u64 {
            self.0.module_size(&to_wide(name))
        }

        fn mouse_event(&mut self, flags: u32, dx: i32, dy: i32, data: u32, extra: u64) -> bool {
            self.0.mouse_event(flags, dx, dy, data, extra)
        }

        fn keybd_event(&mut self, vk: u8, scan: u8, flags: u32, extra: u64) -> bool {
            self.0.keybd_event(vk, scan, flags, extra)
        }

        fn anti_capture(&mut self, window: u64, enable: bool) -> bool {
            self.0.anti_capture(window, enable)
        }
    }
}
