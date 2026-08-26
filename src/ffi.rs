// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

use crate::types::{DeviceObject, DriverObject, NtStatus, Requests, UnicodeString};

unsafe extern "system" {
    pub fn InitPmemPages() -> NtStatus;
    pub fn CleanupPmemPages();
    pub fn RandomEngineInit();
    pub fn GetBootVolumeSerial(out: *mut i8, out_len: u32) -> NtStatus;
    pub fn GenerateObfuscatedName(
        serial: *const u8,
        serial_len: u32,
        out: *mut u16,
        out_len: u32,
    ) -> NtStatus;
    pub fn WdmlibIoCreateDeviceSecureMeme(
        driver: *mut DriverObject,
        device_extension_size: u32,
        device_name: *mut UnicodeString,
        device_type: u32,
        device_characteristics: u32,
        exclusive: u8,
        default_sddl_string: *const UnicodeString,
        device_class_guid: *const c_void,
        device_object: *mut *mut DeviceObject,
    ) -> NtStatus;
    pub fn RtlInitUnicodeStringMeme(dest: *mut UnicodeString, source: *const u16);
    pub fn InitGreProtectSpriteContent() -> u8;
    pub fn MouseRelease();
    pub fn KeyboardRelease();
    pub fn RequestHandler(req: *mut Requests) -> u8;
}
