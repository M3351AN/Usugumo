use core::ffi::c_void;

use crate::types::{
    device_object, driver_object, io_create_driver_fn, nt_status, unicode_string,
};

unsafe extern "system" {
    pub fn ResolveImports() -> nt_status;
    pub fn InitPmemPages() -> nt_status;
    pub fn CleanupPmemPages();
    pub fn RandomEngineInit();
    pub fn GetBootVolumeSerial(out: *mut i8, out_len: u32) -> nt_status;
    pub fn GenerateObfuscatedName(
        serial: *const u8,
        serial_len: u32,
        out: *mut u16,
        out_len: u32,
    ) -> nt_status;
    pub fn WdmlibIoCreateDeviceSecureMeme(
        driver: *mut driver_object,
        device_extension_size: u32,
        device_name: *mut unicode_string,
        device_type: u32,
        device_characteristics: u32,
        exclusive: u8,
        default_sddl_string: *const unicode_string,
        device_class_guid: *const c_void,
        device_object: *mut *mut device_object,
    ) -> nt_status;
    pub fn RtlInitUnicodeStringMeme(dest: *mut unicode_string, source: *const u16);
    pub fn InitGreProtectSpriteContent() -> u8;
    pub fn MouseRelease();
    pub fn KeyboardRelease();
    pub fn DefaultDispatch(device: *mut device_object, irp: *mut c_void) -> nt_status;
    pub fn ReadDispatch(device: *mut device_object, irp: *mut c_void) -> nt_status;
    pub fn WriteDispatch(device: *mut device_object, irp: *mut c_void) -> nt_status;

    pub static _IoCreateDriver: Option<io_create_driver_fn>;
    pub static _IoCreateSymbolicLink:
        Option<unsafe extern "system" fn(*mut unicode_string, *mut unicode_string) -> nt_status>;
    pub static _IoDeleteSymbolicLink:
        Option<unsafe extern "system" fn(*mut unicode_string) -> nt_status>;
    pub static _ExAllocatePool2: Option<unsafe extern "system" fn(u64, usize, u32) -> *mut c_void>;
    pub static _ExFreePoolWithTag: Option<unsafe extern "system" fn(*mut c_void, u32)>;
    pub static _IoDeleteDevice:
        Option<unsafe extern "system" fn(*mut device_object) -> nt_status>;
}
