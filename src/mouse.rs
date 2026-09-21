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
    class_driver_object: *mut DriverObject,
    data_queue_base: usize,
    data_queue_size: u32,
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
    class_driver_object: null_mut(),
    data_queue_base: 0,
    data_queue_size: 0,
    use_mouse: 0,
};

const DEVEXT_INPUT_COUNT: usize = 0x54;
const DEVEXT_DATA_QUEUE_BASE: usize = 0x68;
const DEVEXT_WRITE_POINTER: usize = 0x70;
const DEVEXT_QUEUE_SIZE: usize = 0x88;
const DEVEXT_SPIN_LOCK: usize = 0x90;
const DEVEXT_PENDING_IRP: usize = 0x98;

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

const IO_MOUSE_INCREMENT: i8 = 6;
const MM_KERNEL_MODE: u32 = 0;
const MM_CACHED: u32 = 1;
const NORMAL_PAGE_PRIORITY: u32 = 16;

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

fn validate_device_extension(device_object: *mut DeviceObject) -> bool {
    unsafe {
        let devext = (*device_object).device_extension as *mut u8;
        if devext.is_null() {
            return false;
        }
        let base = crate::helpers::read_u64(devext, DEVEXT_DATA_QUEUE_BASE) as usize;
        let size = crate::helpers::read_u32(devext, DEVEXT_QUEUE_SIZE);
        let data_in = crate::helpers::read_u64(devext, DEVEXT_WRITE_POINTER) as usize;
        if base == 0
            || size == 0
            || size as usize % core::mem::size_of::<MouseInputData>() != 0
            || data_in < base
            || data_in > base + size as usize
            || size as usize > 0x100000
        {
            return false;
        }
        G_MOUSE_OBJECT.data_queue_base = base;
        G_MOUSE_OBJECT.data_queue_size = size;
        true
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

            let mut class_driver_object: *mut DriverObject = null_mut();
            let status = ob_reference_object_by_name(
                &mut class_string,
                OBJ_CASE_INSENSITIVE,
                _IO_DRIVER_OBJECT_TYPE,
                KERNEL_MODE,
                (&mut class_driver_object as *mut *mut DriverObject) as *mut *mut c_void,
            );
            if status < 0 {
                G_MOUSE_OBJECT.use_mouse = 0;
                return false;
            }
            G_MOUSE_OBJECT.class_driver_object = class_driver_object;
            G_MOUSE_OBJECT.mouse_device = null_mut();

            let mut found = false;
            let mut device_object = (*class_driver_object).device_object;
            while !device_object.is_null() {
                if validate_device_extension(device_object) {
                    G_MOUSE_OBJECT.mouse_device = device_object;
                    found = true;
                    break;
                }
                device_object = (*device_object).next_device;
            }

            G_MOUSE_OBJECT.use_mouse = if found { 1 } else { 0 };
        }

        G_MOUSE_OBJECT.use_mouse != 0 && !G_MOUSE_OBJECT.mouse_device.is_null()
    }
}

pub fn mouse_release() {
    unsafe {
        if !G_MOUSE_OBJECT.class_driver_object.is_null() {
            ob_deref(G_MOUSE_OBJECT.class_driver_object as *mut c_void);
            G_MOUSE_OBJECT.class_driver_object = null_mut();
        }
        G_MOUSE_OBJECT.use_mouse = 0;
        G_MOUSE_OBJECT.mouse_device = null_mut();
        G_MOUSE_OBJECT.data_queue_base = 0;
        G_MOUSE_OBJECT.data_queue_size = 0;
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

fn mouse_call(x: i32, y: i32, button_flags: u16, flags: u16) {
    unsafe {
        if !mouse_open() {
            return;
        }
        let devext = (*G_MOUSE_OBJECT.mouse_device).device_extension as *mut u8;

        let packet = MouseInputData {
            unit_id: 0,
            flags,
            buttons: button_flags as u32,
            raw_buttons: 0,
            last_x: x,
            last_y: y,
            extra_information: 0,
        };

        let acquire: FnKeSpinLock = core::mem::transmute(_KeAcquireSpinLockAtDpcLevel);
        let release: FnKeSpinLock = core::mem::transmute(_KeReleaseSpinLockFromDpcLevel);

        let irql = crate::reimpl_ke::kz_raise_irql(DISPATCH_LEVEL);

        let spin_lock = devext.add(DEVEXT_SPIN_LOCK) as *mut c_void;
        acquire(spin_lock);

        let pending_queue = devext.add(DEVEXT_PENDING_IRP) as usize;
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
                let copied = core::cmp::min(buffer_size, core::mem::size_of::<MouseInputData>());
                let mdl = crate::helpers::read_u64(irp as *const u8, IRP_MDL_ADDRESS) as usize;
                let mut irp_buffer: usize = 0;
                if mdl != 0 {
                    irp_buffer = map_mdl(mdl as *mut c_void) as usize;
                }
                if irp_buffer == 0 {
                    irp_buffer =
                        crate::helpers::read_u64(irp as *const u8, IRP_SYSTEM_BUFFER) as usize;
                }
                if irp_buffer != 0 && copied >= core::mem::size_of::<MouseInputData>() {
                    *(irp_buffer as *mut MouseInputData) = packet;
                    bytes_to_copy = copied;
                } else {
                    bytes_to_copy = 0;
                }
            }
        }

        if pending_irp == 0 {
            let base = G_MOUSE_OBJECT.data_queue_base;
            let size = G_MOUSE_OBJECT.data_queue_size as usize;
            let write_ptr = crate::helpers::read_u64(devext, DEVEXT_WRITE_POINTER) as usize;
            let input_count_addr = devext.add(DEVEXT_INPUT_COUNT) as usize;
            if base != 0 && write_ptr != 0 && size != 0 {
                let current = crate::helpers::read_u32(input_count_addr as *const u8, 0) as usize;
                let max_entries = size / core::mem::size_of::<MouseInputData>();
                if current < max_entries - 1 {
                    *(write_ptr as *mut MouseInputData) = packet;
                    let mut new_write_ptr = write_ptr + core::mem::size_of::<MouseInputData>();
                    let buffer_end = base + size;
                    if new_write_ptr >= buffer_end {
                        new_write_ptr = base;
                    }
                    crate::helpers::write_u64(devext, DEVEXT_WRITE_POINTER, new_write_ptr as u64);
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
            complete(pending_irp as *mut c_void, IO_MOUSE_INCREMENT);
        }
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
