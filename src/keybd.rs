// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::imports::{
    _IO_DRIVER_OBJECT_TYPE, _IofCompleteRequest, _KeAcquireSpinLockAtDpcLevel,
    _KeReleaseSpinLockFromDpcLevel, _MM_MAP_LOCKED_PAGES_SPECIFY_CACHE,
    _OB_REFERENCE_OBJECT_BY_NAME, _OBF_DEREFERENCE_OBJECT,
};
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
    class_driver_object: *mut DriverObject,
    data_queue_base: usize,
    data_queue_size: u32,
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
    class_driver_object: null_mut(),
    data_queue_base: 0,
    data_queue_size: 0,
    use_keyboard: 0,
};

const KEYB_DEVEXT_INPUT_COUNT: usize = 0x54;
const KEYB_DEVEXT_DATA_QUEUE_BASE: usize = 0x68;
const KEYB_DEVEXT_WRITE_POINTER: usize = 0x70;
const KEYB_DEVEXT_QUEUE_SIZE: usize = 0x8c;
const KEYB_DEVEXT_SPIN_LOCK: usize = 0xa0;
const KEYB_DEVEXT_PENDING_IRP: usize = 0xa8;

const IRP_MDL_ADDRESS: usize = 0x08;
const IRP_SYSTEM_BUFFER: usize = 0x18;
const IRP_IO_STATUS: usize = 0x30;
const IRP_IO_STATUS_INFORMATION: usize = 0x38;
const IRP_CANCEL_ROUTINE: usize = 0x68;
const IRP_CURRENT_STACK_LOCATION: usize = 0xb8;
const IRP_TAIL_LIST_ENTRY: usize = 0xa8;

const LIST_ENTRY_FLINK: usize = 0x00;
const LIST_ENTRY_BLINK: usize = 0x08;
const IO_STACK_READ_LENGTH: usize = 0x08;

const IO_KEYBOARD_INCREMENT: i8 = 6;
const MM_KERNEL_MODE: u32 = 0;
const MM_CACHED: u32 = 1;
const NORMAL_PAGE_PRIORITY: u32 = 16;

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
        if _OB_REFERENCE_OBJECT_BY_NAME.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        let f: FnObReferenceObjectByName = core::mem::transmute(_OB_REFERENCE_OBJECT_BY_NAME);
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
        if !_OBF_DEREFERENCE_OBJECT.is_null() {
            let f: FnObfDereferenceObject = core::mem::transmute(_OBF_DEREFERENCE_OBJECT);
            f(obj);
        }
    }
}

type FnKeSpinLock = unsafe extern "system" fn(*mut c_void);
type FnIofCompleteRequest = unsafe extern "system" fn(*mut c_void, i8);
type FnMmMapLockedPagesSpecifyCache =
    unsafe extern "system" fn(*mut c_void, u32, u32, *mut c_void, u32, u32) -> *mut c_void;

fn iof_set_cancel_routine(irp: usize) -> *mut c_void {
    let dst = (irp + IRP_CANCEL_ROUTINE) as *mut usize;
    let mut old: usize = 0;
    unsafe {
        core::arch::asm!(
            "xchg [{0}], {1}",
            in(reg) dst,
            inout(reg) old,
            options(nostack)
        );
    }
    old as *mut c_void
}

fn is_list_empty(head: usize) -> bool {
    crate::helpers::read_u64(head as *const u8, LIST_ENTRY_FLINK) as usize == head
}

fn list_remove_head(head: usize) -> usize {
    let first = crate::helpers::read_u64(head as *const u8, LIST_ENTRY_FLINK) as usize;
    if first == head {
        return 0;
    }
    let next = crate::helpers::read_u64(first as *const u8, LIST_ENTRY_FLINK) as usize;
    crate::helpers::write_u64(head as *mut u8, LIST_ENTRY_FLINK, next as u64);
    crate::helpers::write_u64(next as *mut u8, LIST_ENTRY_BLINK, head as u64);
    first
}

fn list_insert_head(head: usize, entry: usize) {
    let flink = crate::helpers::read_u64(head as *const u8, LIST_ENTRY_FLINK) as usize;
    crate::helpers::write_u64(entry as *mut u8, LIST_ENTRY_FLINK, flink as u64);
    crate::helpers::write_u64(entry as *mut u8, LIST_ENTRY_BLINK, head as u64);
    crate::helpers::write_u64(flink as *mut u8, LIST_ENTRY_BLINK, entry as u64);
    crate::helpers::write_u64(head as *mut u8, LIST_ENTRY_FLINK, entry as u64);
}

fn map_mdl(mdl: *mut c_void) -> *mut c_void {
    unsafe {
        if _MM_MAP_LOCKED_PAGES_SPECIFY_CACHE.is_null() {
            return null_mut();
        }
        let f: FnMmMapLockedPagesSpecifyCache =
            core::mem::transmute(_MM_MAP_LOCKED_PAGES_SPECIFY_CACHE);
        f(
            mdl,
            MM_KERNEL_MODE,
            MM_CACHED,
            null_mut(),
            0,
            NORMAL_PAGE_PRIORITY,
        )
    }
}

fn validate_device_extension(device_object: *mut DeviceObject) -> bool {
    unsafe {
        let devext = (*device_object).device_extension as *mut u8;
        if devext.is_null() {
            return false;
        }
        let base = crate::helpers::read_u64(devext, KEYB_DEVEXT_DATA_QUEUE_BASE) as usize;
        let size = crate::helpers::read_u32(devext, KEYB_DEVEXT_QUEUE_SIZE);
        let data_in = crate::helpers::read_u64(devext, KEYB_DEVEXT_WRITE_POINTER) as usize;
        if base == 0
            || size == 0
            || size as usize % core::mem::size_of::<KeyboardInputData>() != 0
            || data_in < base
            || data_in > base + size as usize
            || size as usize > 0x100000
        {
            return false;
        }
        G_KEYBOARD_OBJECT.data_queue_base = base;
        G_KEYBOARD_OBJECT.data_queue_size = size;
        true
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

            let mut class_driver_object: *mut DriverObject = null_mut();
            let status = ob_reference_object_by_name(
                &mut class_string,
                OBJ_CASE_INSENSITIVE,
                _IO_DRIVER_OBJECT_TYPE,
                KERNEL_MODE,
                (&mut class_driver_object as *mut *mut DriverObject) as *mut *mut c_void,
            );
            if status < 0 {
                G_KEYBOARD_OBJECT.use_keyboard = 0;
                return false;
            }
            G_KEYBOARD_OBJECT.class_driver_object = class_driver_object;
            G_KEYBOARD_OBJECT.keyboard_device = null_mut();

            let mut found = false;
            let mut device_object = (*class_driver_object).device_object;
            while !device_object.is_null() {
                if validate_device_extension(device_object) {
                    G_KEYBOARD_OBJECT.keyboard_device = device_object;
                    found = true;
                    break;
                }
                device_object = (*device_object).next_device;
            }

            G_KEYBOARD_OBJECT.use_keyboard = if found { 1 } else { 0 };
        }

        G_KEYBOARD_OBJECT.use_keyboard != 0 && !G_KEYBOARD_OBJECT.keyboard_device.is_null()
    }
}

pub fn keyboard_release() {
    unsafe {
        if !G_KEYBOARD_OBJECT.class_driver_object.is_null() {
            ob_deref(G_KEYBOARD_OBJECT.class_driver_object as *mut c_void);
            G_KEYBOARD_OBJECT.class_driver_object = null_mut();
        }
        G_KEYBOARD_OBJECT.use_keyboard = 0;
        G_KEYBOARD_OBJECT.keyboard_device = null_mut();
        G_KEYBOARD_OBJECT.data_queue_base = 0;
        G_KEYBOARD_OBJECT.data_queue_size = 0;
    }
}

fn keyboard_call(make_code: u16, flags: u16, extra_info: u32) {
    unsafe {
        if !keyboard_open() {
            return;
        }
        let devext = (*G_KEYBOARD_OBJECT.keyboard_device).device_extension as *mut u8;

        let packet = KeyboardInputData {
            unit_id: 0,
            make_code,
            flags,
            reserved: 0,
            extra_information: extra_info,
        };

        let acquire: FnKeSpinLock = core::mem::transmute(_KeAcquireSpinLockAtDpcLevel);
        let release: FnKeSpinLock = core::mem::transmute(_KeReleaseSpinLockFromDpcLevel);

        let irql = crate::reimpl_ke::kz_raise_irql(DISPATCH_LEVEL);

        let spin_lock = devext.add(KEYB_DEVEXT_SPIN_LOCK) as *mut c_void;
        acquire(spin_lock);

        let pending_queue = devext.add(KEYB_DEVEXT_PENDING_IRP) as usize;
        let mut pending_irp: usize = 0;
        let mut bytes_to_copy: usize = 0;

        if !is_list_empty(pending_queue) {
            let entry = list_remove_head(pending_queue);
            let irp = entry - IRP_TAIL_LIST_ENTRY;
            let old_cancel = iof_set_cancel_routine(irp);
            if old_cancel.is_null() {
                list_insert_head(pending_queue, entry);
                pending_irp = 0;
            } else {
                pending_irp = irp;
                let irp_stack =
                    crate::helpers::read_u64(irp as *const u8, IRP_CURRENT_STACK_LOCATION) as usize;
                let buffer_size =
                    crate::helpers::read_u32(irp_stack as *const u8, IO_STACK_READ_LENGTH) as usize;
                let copied = core::cmp::min(buffer_size, core::mem::size_of::<KeyboardInputData>());
                let mdl = crate::helpers::read_u64(irp as *const u8, IRP_MDL_ADDRESS) as usize;
                let mut irp_buffer: usize = 0;
                if mdl != 0 {
                    irp_buffer = map_mdl(mdl as *mut c_void) as usize;
                }
                if irp_buffer == 0 {
                    irp_buffer =
                        crate::helpers::read_u64(irp as *const u8, IRP_SYSTEM_BUFFER) as usize;
                }
                if irp_buffer != 0 && copied >= core::mem::size_of::<KeyboardInputData>() {
                    *(irp_buffer as *mut KeyboardInputData) = packet;
                    bytes_to_copy = copied;
                } else {
                    bytes_to_copy = 0;
                }
            }
        }

        if pending_irp == 0 {
            let base = G_KEYBOARD_OBJECT.data_queue_base;
            let size = G_KEYBOARD_OBJECT.data_queue_size as usize;
            let write_ptr = crate::helpers::read_u64(devext, KEYB_DEVEXT_WRITE_POINTER) as usize;
            let input_count_addr = devext.add(KEYB_DEVEXT_INPUT_COUNT) as usize;
            if base != 0 && write_ptr != 0 && size != 0 {
                let current = crate::helpers::read_u32(input_count_addr as *const u8, 0) as usize;
                let max_entries = size / core::mem::size_of::<KeyboardInputData>();
                if current < max_entries - 1 {
                    *(write_ptr as *mut KeyboardInputData) = packet;
                    let mut new_write_ptr = write_ptr + core::mem::size_of::<KeyboardInputData>();
                    let buffer_end = base + size;
                    if new_write_ptr >= buffer_end {
                        new_write_ptr = base;
                    }
                    crate::helpers::write_u64(
                        devext,
                        KEYB_DEVEXT_WRITE_POINTER,
                        new_write_ptr as u64,
                    );
                    (input_count_addr as *mut u32)
                        .write_unaligned((current as u32).wrapping_add(1));
                }
            }
        }

        release(spin_lock);
        crate::reimpl_ke::kz_lower_irql(irql);

        if pending_irp != 0 {
            ((pending_irp + IRP_IO_STATUS) as *mut u32).write_unaligned(STATUS_SUCCESS as u32);
            crate::helpers::write_u64(
                pending_irp as *mut u8,
                IRP_IO_STATUS_INFORMATION,
                bytes_to_copy as u64,
            );
            let complete: FnIofCompleteRequest = core::mem::transmute(_IofCompleteRequest);
            complete(pending_irp as *mut c_void, IO_KEYBOARD_INCREMENT);
        }
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
