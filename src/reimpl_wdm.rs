// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

use crate::consts::STATUS_UNSUCCESSFUL;
use crate::imports::resolve_kernel_export;
use crate::types::{DeviceObject, DriverObject, NtStatus, UnicodeString};
use crate::xxh3::xxh3_64;

type FnIoCreateDeviceSecure = unsafe extern "system" fn(
    *mut DriverObject,
    u32,
    *mut UnicodeString,
    u32,
    u32,
    u8,
    *const UnicodeString,
    *const c_void,
    *mut *mut DeviceObject,
) -> NtStatus;

static mut G_WDMLIB_INITIALIZED: bool = false;
static mut IO_CREATE_DEVICE_SECURE: Option<FnIoCreateDeviceSecure> = None;

fn wdmlib_init() {
    unsafe {
        let create_addr = resolve_kernel_export(xxh3_64(b"IoCreateDeviceSecure"));
        IO_CREATE_DEVICE_SECURE = if create_addr.is_null() {
            None
        } else {
            Some(core::mem::transmute(create_addr))
        };
        G_WDMLIB_INITIALIZED = true;
    }
}

pub unsafe extern "system" fn wdmlib_io_create_device_secure(
    driver_object: *mut DriverObject,
    device_extension_size: u32,
    device_name: *mut UnicodeString,
    device_type: u32,
    device_characteristics: u32,
    exclusive: u8,
    default_sddl_string: *const UnicodeString,
    device_class_guid: *const c_void,
    device_object: *mut *mut DeviceObject,
) -> NtStatus {
    unsafe {
        if !G_WDMLIB_INITIALIZED {
            wdmlib_init();
        }
        match IO_CREATE_DEVICE_SECURE {
            Some(f) => f(
                driver_object,
                device_extension_size,
                device_name,
                device_type,
                device_characteristics,
                exclusive,
                default_sddl_string,
                device_class_guid,
                device_object,
            ),
            None => STATUS_UNSUCCESSFUL,
        }
    }
}
