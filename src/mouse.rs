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
struct MouseInputData {
    unit_id: u16,
    flags: u16,
    buttons: u32,
    raw_buttons: u32,
    last_x: i32,
    last_y: i32,
    extra_information: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MouseObject {
    mouse_device: *mut DeviceObject,
    service_callback: *mut c_void,
    class_driver_object: *mut DriverObject,
    hid_driver_object: *mut DriverObject,
    use_mouse: u32,
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

static mut G_MOUSE_OBJECT: MouseObject = MouseObject {
    mouse_device: null_mut(),
    service_callback: null_mut(),
    class_driver_object: null_mut(),
    hid_driver_object: null_mut(),
    use_mouse: 0,
};

const MOUSE_MOVE_RELATIVE: u16 = 0x0000;
const MOUSE_MOVE_ABSOLUTE: u16 = 0x0001;
const MOUSE_VIRTUAL_DESKTOP: u16 = 0x0002;
const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;
const MOUSEEVENTF_MOVE: u32 = 0x0001;
const MOUSEEVENTF_VIRTUALDESK: u32 = 0x4000;
const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
const MOUSEEVENTF_XDOWN: u32 = 0x0080;
const MOUSEEVENTF_XUP: u32 = 0x0100;

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

fn mouse_open() -> bool {
    unsafe {
        if G_MOUSE_OBJECT.use_mouse == 0 {
            let class_wide = obfstr::obfwide!("\\Driver\\MouClass");
            let mut class_string = UnicodeString {
                length: (class_wide.len() * 2) as u16,
                maximum_length: (class_wide.len() * 2) as u16,
                buffer: class_wide.as_ptr() as *mut u16,
            };
            let mouhid_wide = obfstr::obfwide!("\\Driver\\MouHID");
            let i8042_wide = obfstr::obfwide!("\\Driver\\i8042prt");
            let mut mouse_driver_names = [
                UnicodeString {
                    length: (mouhid_wide.len() * 2) as u16,
                    maximum_length: (mouhid_wide.len() * 2) as u16,
                    buffer: mouhid_wide.as_ptr() as *mut u16,
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
                G_MOUSE_OBJECT.use_mouse = 0;
                return false;
            }

            let mut driver_idx = 0usize;
            while driver_idx < mouse_driver_names.len() {
                status = ob_reference_object_by_name(
                    &mut mouse_driver_names[driver_idx],
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
                G_MOUSE_OBJECT.use_mouse = 0;
                return false;
            }

            hid_device_object = (*hid_driver_object).device_object;
            G_MOUSE_OBJECT.service_callback = null_mut();
            G_MOUSE_OBJECT.mouse_device = null_mut();

            while !hid_device_object.is_null() && G_MOUSE_OBJECT.service_callback.is_null() {
                class_device_object = (*class_driver_object).device_object;
                while !class_device_object.is_null() && G_MOUSE_OBJECT.service_callback.is_null() {
                    if G_MOUSE_OBJECT.mouse_device.is_null()
                        && (*class_device_object).next_device.is_null()
                    {
                        G_MOUSE_OBJECT.mouse_device = class_device_object;
                    }

                    let device_extension = (*hid_device_object).device_extension;
                    let device_ext_size = ((*hid_device_object).device_object_extension as usize
                        - device_extension as usize)
                        / 4;

                    for i in 0..device_ext_size {
                        if *device_extension.add(i) as usize == class_device_object as usize
                            && *device_extension.add(i + 1) as usize > class_driver_object as usize
                        {
                            G_MOUSE_OBJECT.service_callback =
                                *device_extension.add(i + 1) as *mut c_void;
                            break;
                        }
                    }
                    class_device_object = (*class_device_object).next_device;
                }
                hid_device_object = (*hid_device_object).attached_device;
            }

            if G_MOUSE_OBJECT.mouse_device.is_null() {
                let mut target_device_object = (*class_driver_object).device_object;
                while !target_device_object.is_null() {
                    if (*target_device_object).next_device.is_null() {
                        G_MOUSE_OBJECT.mouse_device = target_device_object;
                        break;
                    }
                    target_device_object = (*target_device_object).next_device;
                }
            }

            G_MOUSE_OBJECT.class_driver_object = class_driver_object;
            G_MOUSE_OBJECT.hid_driver_object = hid_driver_object;
            G_MOUSE_OBJECT.use_mouse = if !G_MOUSE_OBJECT.mouse_device.is_null()
                && !G_MOUSE_OBJECT.service_callback.is_null()
            {
                1
            } else {
                0
            };
        }

        !G_MOUSE_OBJECT.mouse_device.is_null() && !G_MOUSE_OBJECT.service_callback.is_null()
    }
}

pub fn mouse_release() {
    unsafe {
        if !G_MOUSE_OBJECT.class_driver_object.is_null() {
            ob_deref(G_MOUSE_OBJECT.class_driver_object as *mut c_void);
            G_MOUSE_OBJECT.class_driver_object = null_mut();
        }
        if !G_MOUSE_OBJECT.hid_driver_object.is_null() {
            ob_deref(G_MOUSE_OBJECT.hid_driver_object as *mut c_void);
            G_MOUSE_OBJECT.hid_driver_object = null_mut();
        }
        G_MOUSE_OBJECT.use_mouse = 0;
        G_MOUSE_OBJECT.mouse_device = null_mut();
        G_MOUSE_OBJECT.service_callback = null_mut();
    }
}

fn mouse_call(x: i32, y: i32, button_flags: u16, flags: u16) {
    unsafe {
        if !mouse_open() {
            return;
        }
        let mut mid = MouseInputData {
            unit_id: 1,
            flags,
            buttons: button_flags as u32,
            raw_buttons: 0,
            last_x: x,
            last_y: y,
            extra_information: 0,
        };
        let irql = KzRaiseIrqlMeme(DISPATCH_LEVEL);
        let mut input_data = 0u32;
        let end = (core::ptr::addr_of!(mid) as *mut MouseInputData).add(1);
        MouseClassServiceCallbackMeme(
            G_MOUSE_OBJECT.mouse_device as *mut c_void,
            core::ptr::addr_of_mut!(mid) as *mut c_void,
            end as *mut c_void,
            &mut input_data,
        );
        KzLowerIrqlMeme(irql);
    }
}

pub fn handle_mouse_event(request: *mut Requests) {
    unsafe {
        if request.is_null() {
            return;
        }
        if !verify_secure_key((*request).secure_key) {
            (*request).return_value = 0;
            return;
        }

        let dw_flags = (*request).dw_flags;
        let dx = (*request).dx as i32;
        let dy = (*request).dy as i32;

        let mut x = 0i32;
        let mut y = 0i32;
        let mut button_flags = 0u16;
        let mut flags = MOUSE_MOVE_RELATIVE;

        if dw_flags & MOUSEEVENTF_MOVE != 0 {
            x = dx;
            y = dy;

            if dw_flags & MOUSEEVENTF_ABSOLUTE != 0 {
                flags = MOUSE_MOVE_ABSOLUTE;

                if dw_flags & MOUSEEVENTF_VIRTUALDESK != 0 {
                    flags |= MOUSE_VIRTUAL_DESKTOP;
                }

                x = dx.clamp(0, 65535);
                y = dy.clamp(0, 65535);
            }
        }

        if dw_flags & MOUSEEVENTF_LEFTDOWN != 0 {
            button_flags |= 0x0001;
        }
        if dw_flags & MOUSEEVENTF_LEFTUP != 0 {
            button_flags |= 0x0002;
        }
        if dw_flags & MOUSEEVENTF_RIGHTDOWN != 0 {
            button_flags |= 0x0004;
        }
        if dw_flags & MOUSEEVENTF_RIGHTUP != 0 {
            button_flags |= 0x0008;
        }
        if dw_flags & MOUSEEVENTF_MIDDLEDOWN != 0 {
            button_flags |= 0x0010;
        }
        if dw_flags & MOUSEEVENTF_MIDDLEUP != 0 {
            button_flags |= 0x0020;
        }
        if dw_flags & MOUSEEVENTF_XDOWN != 0 {
            button_flags |= 0x0040;
        }
        if dw_flags & MOUSEEVENTF_XUP != 0 {
            button_flags |= 0x0080;
        }

        mouse_call(x, y, button_flags, flags);

        (*request).return_value = 1;
    }
}
