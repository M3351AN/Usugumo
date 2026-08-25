use core::ffi::c_void;

pub type nt_status = i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct unicode_string {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

unsafe impl Send for unicode_string {}
unsafe impl Sync for unicode_string {}

#[repr(C)]
pub struct device_object {
    pub _type: u16,
    pub _size: u16,
    pub _reference_count: u32,
    pub _driver_object: *mut c_void,
    pub _next_device: *mut c_void,
    pub _attached_device: *mut c_void,
    pub _current_irp: *mut c_void,
    pub _timer: *mut c_void,
    pub flags: u32,
    pub _characteristics: u32,
}

#[repr(C)]
pub struct driver_object {
    pub _type: u16,
    pub _size: u16,
    pub device_object: *mut device_object,
    pub _flags: u32,
    pub _driver_start: *mut c_void,
    pub _driver_size: u32,
    pub _driver_section: *mut c_void,
    pub _driver_extension: *mut c_void,
    pub _driver_name: unicode_string,
    pub _hardware_database: *mut c_void,
    pub _fast_io_dispatch: *mut c_void,
    pub _driver_init: *mut c_void,
    pub _driver_start_io: *mut c_void,
    pub driver_unload: Option<unload_fn>,
    pub major_function: [Option<dispatch_fn>; 28],
}

pub type dispatch_fn = unsafe extern "system" fn(*mut device_object, *mut c_void) -> nt_status;
pub type unload_fn = unsafe extern "system" fn(*mut driver_object);
pub type driver_init_fn =
    unsafe extern "system" fn(*mut driver_object, *mut unicode_string) -> nt_status;
pub type io_create_driver_fn =
    unsafe extern "system" fn(*mut unicode_string, driver_init_fn) -> nt_status;
