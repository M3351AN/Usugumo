// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::ffi::*;
use crate::imports::{_IoDriverObjectType, _ObReferenceObjectByName, _ObfDereferenceObject};
use crate::request_handler::verify_secure_key;
use crate::types::{DeviceObject, DriverObject, NtStatus, Requests, UnicodeString};

#[repr(C)]
#[derive(Clone, Copy)]
struct KeyboardInputData {
    unit_id: u16,
    make_code: u16,
    flags: u16,
    reserved: u16,
    extra_information: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KeyboardObject {
    keyboard_device: *mut DeviceObject,
    service_callback: *mut c_void,
    class_driver_object: *mut DriverObject,
    hid_driver_object: *mut DriverObject,
    use_keyboard: u32,
}

type FnObReferenceObjectByName = unsafe extern "system" fn(
    *mut UnicodeString,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u8,
    *mut c_void,
    *mut *mut c_void,
) -> NtStatus;
type FnObfDereferenceObject = unsafe extern "system" fn(*mut c_void) -> isize;

static mut G_KEYBOARD_OBJECT: KeyboardObject = KeyboardObject {
    keyboard_device: null_mut(),
    service_callback: null_mut(),
    class_driver_object: null_mut(),
    hid_driver_object: null_mut(),
    use_keyboard: 0,
};

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const KERNEL_MODE: u8 = 0;
const DISPATCH_LEVEL: u8 = 2;
const KEY_MAKE: u16 = 0x0;
const KEY_BREAK: u16 = 0x1;
const KEY_E0: u16 = 0x2;
const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
const KEYEVENTF_KEYUP: u32 = 0x0002;
const KEYEVENTF_UNICODE: u32 = 0x0004;
const KEYEVENTF_SCANCODE: u32 = 0x0008;

const K_SCAN_TABLE: [u8; 256] = [
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x0E,
    0x0F,
    0x00,
    0x00,
    0x4C,
    0x1C,
    0x00,
    0x00,
    0x2A,
    0x1D,
    0x38,
    0x00,
    0x3A,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x39,
    0x49 | 0x80,
    0x51 | 0x80,
    0x4F | 0x80,
    0x47 | 0x80,
    0x4B | 0x80,
    0x48 | 0x80,
    0x4D | 0x80,
    0x50 | 0x80,
    0x00,
    0x00,
    0x00,
    0x37 | 0x80,
    0x52 | 0x80,
    0x53 | 0x80,
    0x00,
    0x0B,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x1E,
    0x30,
    0x2E,
    0x20,
    0x12,
    0x21,
    0x22,
    0x23,
    0x17,
    0x24,
    0x25,
    0x26,
    0x32,
    0x31,
    0x18,
    0x19,
    0x10,
    0x13,
    0x1F,
    0x14,
    0x16,
    0x2F,
    0x11,
    0x2D,
    0x15,
    0x2C,
    0x5B | 0x80,
    0x5C | 0x80,
    0x5D | 0x80,
    0x00,
    0x5F | 0x80,
    0x52,
    0x4F,
    0x50,
    0x51,
    0x4B,
    0x4C,
    0x4D,
    0x47,
    0x48,
    0x49,
    0x37,
    0x4E,
    0x4C,
    0x4A,
    0x53,
    0x35 | 0x80,
    0x3B,
    0x3C,
    0x3D,
    0x3E,
    0x3F,
    0x40,
    0x41,
    0x42,
    0x43,
    0x44,
    0x57,
    0x58,
    0x64,
    0x65,
    0x66,
    0x67,
    0x68,
    0x69,
    0x6A,
    0x6B,
    0x6C,
    0x6D,
    0x6E,
    0x76,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x45,
    0x46,
    0x7B,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x2A,
    0x36,
    0x1D,
    0x1D | 0x80,
    0x38,
    0x38 | 0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x27,
    0x0D,
    0x33,
    0x0C,
    0x34,
    0x35,
    0x29,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x1A,
    0x2B,
    0x1B,
    0x28,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
];

fn ob_reference_object_by_name(
    name: *mut UnicodeString,
    attributes: u32,
    object_type: *mut c_void,
    access_mode: u8,
    object: *mut *mut c_void,
) -> NtStatus {
    unsafe {
        if _ObReferenceObjectByName.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        let f: FnObReferenceObjectByName = core::mem::transmute(_ObReferenceObjectByName);
        f(
            name,
            attributes,
            null_mut(),
            0,
            object_type,
            access_mode,
            null_mut(),
            object,
        )
    }
}

fn ob_deref(obj: *mut c_void) {
    unsafe {
        if !_ObfDereferenceObject.is_null() {
            let f: FnObfDereferenceObject = core::mem::transmute(_ObfDereferenceObject);
            f(obj);
        }
    }
}

fn keyboard_open() -> bool {
    unsafe {
        if G_KEYBOARD_OBJECT.use_keyboard == 0 {
            let class_wide = obfstr::obfwide!("\\Driver\\kbdclass");
            let mut class_string = UnicodeString {
                length: (class_wide.len() * 2) as u16,
                maximum_length: (class_wide.len() * 2) as u16,
                buffer: class_wide.as_ptr() as *mut u16,
            };
            let kbdhid_wide = obfstr::obfwide!("\\Driver\\kbdhid");
            let i8042_wide = obfstr::obfwide!("\\Driver\\i8042prt");
            let mut keyboard_driver_names = [
                UnicodeString {
                    length: (kbdhid_wide.len() * 2) as u16,
                    maximum_length: (kbdhid_wide.len() * 2) as u16,
                    buffer: kbdhid_wide.as_ptr() as *mut u16,
                },
                UnicodeString {
                    length: (i8042_wide.len() * 2) as u16,
                    maximum_length: (i8042_wide.len() * 2) as u16,
                    buffer: i8042_wide.as_ptr() as *mut u16,
                },
            ];

            let mut class_driver_object: *mut DriverObject = null_mut();
            let mut hid_driver_object: *mut DriverObject = null_mut();
            let mut hid_device_object: *mut DeviceObject;
            let mut class_device_object: *mut DeviceObject;

            let mut status = ob_reference_object_by_name(
                &mut class_string,
                OBJ_CASE_INSENSITIVE,
                _IoDriverObjectType,
                KERNEL_MODE,
                (&mut class_driver_object as *mut *mut DriverObject) as *mut *mut c_void,
            );
            if status < 0 {
                G_KEYBOARD_OBJECT.use_keyboard = 0;
                return false;
            }

            let mut driver_idx = 0usize;
            while driver_idx < keyboard_driver_names.len() {
                status = ob_reference_object_by_name(
                    &mut keyboard_driver_names[driver_idx],
                    OBJ_CASE_INSENSITIVE,
                    _IoDriverObjectType,
                    KERNEL_MODE,
                    (&mut hid_driver_object as *mut *mut DriverObject) as *mut *mut c_void,
                );
                if status >= 0 {
                    break;
                }
                driver_idx += 1;
            }

            if status < 0 || hid_driver_object.is_null() {
                ob_deref(class_driver_object as *mut c_void);
                G_KEYBOARD_OBJECT.use_keyboard = 0;
                return false;
            }

            let mut port_device_object = (*hid_driver_object).device_object;
            G_KEYBOARD_OBJECT.service_callback = null_mut();
            G_KEYBOARD_OBJECT.keyboard_device = null_mut();

            while !port_device_object.is_null() && G_KEYBOARD_OBJECT.service_callback.is_null() {
                hid_device_object = port_device_object;
                while !hid_device_object.is_null() && G_KEYBOARD_OBJECT.service_callback.is_null() {
                    class_device_object = (*class_driver_object).device_object;
                    while !class_device_object.is_null()
                        && G_KEYBOARD_OBJECT.service_callback.is_null()
                    {
                        if G_KEYBOARD_OBJECT.keyboard_device.is_null()
                            && (*class_device_object).next_device.is_null()
                        {
                            G_KEYBOARD_OBJECT.keyboard_device = class_device_object;
                        }

                        let device_extension = (*hid_device_object).device_extension;
                        let device_ext_size = ((*hid_device_object).device_object_extension
                            as usize
                            - device_extension as usize)
                            / 4;

                        for i in 0..device_ext_size {
                            if *device_extension.add(i) as usize == class_device_object as usize
                                && *device_extension.add(i + 1) as usize
                                    > class_driver_object as usize
                            {
                                G_KEYBOARD_OBJECT.service_callback =
                                    *device_extension.add(i + 1) as *mut c_void;
                                break;
                            }
                        }
                        class_device_object = (*class_device_object).next_device;
                    }
                    hid_device_object = (*hid_device_object).attached_device;
                }
                port_device_object = (*port_device_object).next_device;
            }

            if G_KEYBOARD_OBJECT.keyboard_device.is_null() {
                let mut target_device_object = (*class_driver_object).device_object;
                while !target_device_object.is_null() {
                    if (*target_device_object).next_device.is_null() {
                        G_KEYBOARD_OBJECT.keyboard_device = target_device_object;
                        break;
                    }
                    target_device_object = (*target_device_object).next_device;
                }
            }

            G_KEYBOARD_OBJECT.class_driver_object = class_driver_object;
            G_KEYBOARD_OBJECT.hid_driver_object = hid_driver_object;
            G_KEYBOARD_OBJECT.use_keyboard = if !G_KEYBOARD_OBJECT.keyboard_device.is_null()
                && !G_KEYBOARD_OBJECT.service_callback.is_null()
            {
                1
            } else {
                0
            };
        }

        !G_KEYBOARD_OBJECT.keyboard_device.is_null()
            && !G_KEYBOARD_OBJECT.service_callback.is_null()
    }
}

pub fn keyboard_release() {
    unsafe {
        if !G_KEYBOARD_OBJECT.class_driver_object.is_null() {
            ob_deref(G_KEYBOARD_OBJECT.class_driver_object as *mut c_void);
            G_KEYBOARD_OBJECT.class_driver_object = null_mut();
        }
        if !G_KEYBOARD_OBJECT.hid_driver_object.is_null() {
            ob_deref(G_KEYBOARD_OBJECT.hid_driver_object as *mut c_void);
            G_KEYBOARD_OBJECT.hid_driver_object = null_mut();
        }
        G_KEYBOARD_OBJECT.use_keyboard = 0;
        G_KEYBOARD_OBJECT.keyboard_device = null_mut();
        G_KEYBOARD_OBJECT.service_callback = null_mut();
    }
}

fn keyboard_call(make_code: u16, flags: u16, extra_info: u32) {
    unsafe {
        if !keyboard_open() {
            return;
        }
        let mut kbd = KeyboardInputData {
            unit_id: 0,
            make_code,
            flags,
            reserved: 0,
            extra_information: extra_info,
        };
        let irql = KzRaiseIrqlMeme(DISPATCH_LEVEL);
        let mut input_data = 0u32;
        let end = (core::ptr::addr_of!(kbd) as *mut KeyboardInputData).add(1);
        KeyboardClassServiceCallbackMeme(
            G_KEYBOARD_OBJECT.keyboard_device as *mut c_void,
            core::ptr::addr_of_mut!(kbd) as *mut c_void,
            end as *mut c_void,
            &mut input_data,
        );
        KzLowerIrqlMeme(irql);
    }
}

fn vk_to_scan_code(vk: u16) -> u16 {
    if vk > 0xFF {
        return 0;
    }
    K_SCAN_TABLE[vk as usize] as u16
}

pub fn handle_keybd_event(request: *mut Requests) {
    unsafe {
        if request.is_null() {
            return;
        }
        if !verify_secure_key((*request).secure_key) {
            (*request).return_value = 0;
            return;
        }
        let dw_flags = (*request).dw_flags;
        let extra_info = (*request).dw_extra_info as u32;

        if dw_flags & KEYEVENTF_UNICODE != 0 {
            let unicode_char = (*request).b_vk;
            keyboard_call(unicode_char, KEY_MAKE, extra_info);
            keyboard_call(unicode_char, KEY_BREAK, extra_info);
            (*request).return_value = 1;
            return;
        }

        let make_code;
        let mut final_flags = if dw_flags & KEYEVENTF_KEYUP != 0 {
            KEY_BREAK
        } else {
            KEY_MAKE
        };

        if dw_flags & KEYEVENTF_SCANCODE != 0 {
            make_code = (*request).b_scan;
            if dw_flags & KEYEVENTF_EXTENDEDKEY != 0 {
                final_flags |= KEY_E0;
            }
        } else {
            let mapped = vk_to_scan_code((*request).b_vk);
            make_code = mapped & 0x7F;
            if (mapped & 0x80) != 0 || (dw_flags & KEYEVENTF_EXTENDEDKEY) != 0 {
                final_flags |= KEY_E0;
            }
        }

        keyboard_call(make_code, final_flags, extra_info);
        (*request).return_value = 1;
    }
}
