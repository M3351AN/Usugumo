// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;

use crate::consts::*;
use crate::imports::{_IofCompleteRequest, _MmMapLockedPagesSpecifyCache};
use crate::request_handler::request_handler;
use crate::types::{DeviceObject, IoStackLocation, IoStackParameters, Irp, NtStatus, Requests};

const _: () = assert!(core::mem::offset_of!(Irp, mdl_address) == 8);
const _: () = assert!(core::mem::offset_of!(Irp, io_status) == 48);
const _: () = assert!(core::mem::offset_of!(Irp, current_stack_location) == 192);
const _: () = assert!(core::mem::offset_of!(IoStackLocation, parameters) == 8);
const _: () = assert!(core::mem::offset_of!(IoStackParameters, length) == 0);
const _: () = assert!(core::mem::size_of::<Requests>() == 192);
const _: () = assert!(core::mem::offset_of!(Requests, time_stamp) == 168);
const _: () = assert!(core::mem::offset_of!(Requests, mem_size) == 48);
const _: () = assert!(core::mem::offset_of!(Requests, request_addr) == 24);
const _: () = assert!(core::mem::offset_of!(Requests, target_addr) == 40);

const IO_NO_INCREMENT: i8 = 0;
const KERNEL_MODE: u32 = 0;
const MM_CACHED: u32 = 1;
const NORMAL_PAGE_PRIORITY: u32 = 16;

type FnIofCompleteRequest = unsafe extern "system" fn(*mut Irp, i8);
type FnMmMapLockedPages =
    unsafe extern "system" fn(*mut c_void, u32, u32, *mut c_void, u32, u32) -> *mut c_void;

unsafe fn complete_request(irp: *mut Irp) {
    unsafe {
        if !_IofCompleteRequest.is_null() {
            let f: FnIofCompleteRequest = core::mem::transmute(_IofCompleteRequest);
            f(irp, IO_NO_INCREMENT);
        }
    }
}

unsafe fn map_locked(mdl: *mut c_void) -> *mut c_void {
    unsafe {
        if _MmMapLockedPagesSpecifyCache.is_null() {
            return null_mut();
        }
        let f: FnMmMapLockedPages = core::mem::transmute(_MmMapLockedPagesSpecifyCache);
        f(
            mdl,
            KERNEL_MODE,
            MM_CACHED,
            null_mut(),
            0,
            NORMAL_PAGE_PRIORITY,
        )
    }
}

pub unsafe extern "system" fn default_dispatch(
    _device_obj: *mut DeviceObject,
    irp: *mut c_void,
) -> NtStatus {
    let irp = irp as *mut Irp;
    unsafe {
        (*irp).io_status.status = STATUS_SUCCESS;
        (*irp).io_status.information = 0;
        complete_request(irp);
        STATUS_SUCCESS
    }
}

pub unsafe extern "system" fn write_dispatch(
    _device_obj: *mut DeviceObject,
    irp: *mut c_void,
) -> NtStatus {
    let irp = irp as *mut Irp;
    unsafe {
        let stack: *mut IoStackLocation = (*irp).current_stack_location;
        let write_len = (*stack).parameters.length;

        (*irp).io_status.status = STATUS_SUCCESS;
        (*irp).io_status.information = 0;

        let p_mdl = (*irp).mdl_address;
        if p_mdl.is_null() {
            (*irp).io_status.status = STATUS_INVALID_PARAMETER;
            complete_request(irp);
            return (*irp).io_status.status;
        }

        let p_request = map_locked(p_mdl);
        if p_request.is_null() {
            (*irp).io_status.status = STATUS_INSUFFICIENT_RESOURCES;
            complete_request(irp);
            return (*irp).io_status.status;
        }

        if write_len >= size_of::<Requests>() as u32 {
            if request_handler(p_request as *mut Requests) != 0 {
                (*irp).io_status.information = size_of::<Requests>();
                (*irp).io_status.status = STATUS_SUCCESS;
            } else {
                (*irp).io_status.status = STATUS_INVALID_DEVICE_REQUEST;
            }
        } else {
            (*irp).io_status.status = STATUS_BUFFER_TOO_SMALL;
        }

        complete_request(irp);
        (*irp).io_status.status
    }
}

pub unsafe extern "system" fn read_dispatch(
    _device_obj: *mut DeviceObject,
    irp: *mut c_void,
) -> NtStatus {
    let irp = irp as *mut Irp;
    unsafe {
        let stack: *mut IoStackLocation = (*irp).current_stack_location;
        let read_len = (*stack).parameters.length;

        (*irp).io_status.status = STATUS_SUCCESS;
        (*irp).io_status.information = 0;

        let p_mdl = (*irp).mdl_address;
        if p_mdl.is_null() {
            (*irp).io_status.status = STATUS_INVALID_PARAMETER;
            complete_request(irp);
            return (*irp).io_status.status;
        }

        let p_request = map_locked(p_mdl);
        if p_request.is_null() {
            (*irp).io_status.status = STATUS_INSUFFICIENT_RESOURCES;
            complete_request(irp);
            return (*irp).io_status.status;
        }

        if read_len >= size_of::<Requests>() as u32 {
            (*irp).io_status.information = size_of::<Requests>();
            (*irp).io_status.status = STATUS_SUCCESS;
        } else {
            (*irp).io_status.status = STATUS_BUFFER_TOO_SMALL;
        }

        complete_request(irp);
        (*irp).io_status.status
    }
}
