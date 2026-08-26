// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

pub type NtStatus = i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

unsafe impl Send for UnicodeString {}
unsafe impl Sync for UnicodeString {}

#[repr(C)]
pub struct DeviceObject {
    pub _type: u16,
    pub _size: u16,
    pub _reference_count: u32,
    pub _driver_object: *mut c_void,
    pub next_device: *mut DeviceObject,
    pub attached_device: *mut DeviceObject,
    pub _current_irp: *mut c_void,
    pub _timer: *mut c_void,
    pub flags: u32,
    pub _characteristics: u32,
    pub _vpb: *mut c_void,
    pub device_extension: *mut u64,
    pub _device_type: u32,
    pub _stack_size: u8,
    pub _pad1: [u8; 3],
    pub _queue: [u8; 0x48],
    pub _alignment_requirement: u32,
    pub _pad2: [u8; 4],
    pub _device_queue: [u8; 0x28],
    pub _dpc: [u8; 0x40],
    pub _active_thread_count: u32,
    pub _security_descriptor: *mut c_void,
    pub _device_lock: [u8; 0x18],
    pub _sector_size: u16,
    pub _spare1: u16,
    pub device_object_extension: *mut c_void,
    pub _reserved: *mut c_void,
}

#[repr(C)]
pub struct DriverObject {
    pub _type: u16,
    pub _size: u16,
    pub device_object: *mut DeviceObject,
    pub _flags: u32,
    pub _driver_start: *mut c_void,
    pub _driver_size: u32,
    pub _driver_section: *mut c_void,
    pub _driver_extension: *mut c_void,
    pub _driver_name: UnicodeString,
    pub _hardware_database: *mut c_void,
    pub _fast_io_dispatch: *mut c_void,
    pub _driver_init: *mut c_void,
    pub _driver_start_io: *mut c_void,
    pub driver_unload: Option<UnloadFn>,
    pub major_function: [Option<DispatchFn>; 28],
}

#[repr(C)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub information: usize,
}

#[repr(C)]
pub struct Irp {
    pub _type: u16,
    pub size: u16,
    pub mdl_address: *mut c_void,
    pub flags: u32,
    pub associated_irp: usize,
    pub thread_list_entry: [usize; 2],
    pub io_status: IoStatusBlock,
    _requestor_mode: u32,
    _pending_returned: u8,
    _stack_count: u8,
    _current_location: u8,
    _cancel: u8,
    _cancel_irql: u8,
    _apc_environment: u8,
    _allocation_flags: u8,
    _user_iosb: usize,
    _user_event: usize,
    _overlay: [usize; 2],
    _cancel_routine: usize,
    _user_buffer: usize,
    _tail_device_queue: [usize; 4],
    _tail_thread: usize,
    _tail_aux_buffer: usize,
    _tail_list_entry: [usize; 2],
    pub current_stack_location: *mut IoStackLocation,
}

#[repr(C)]
pub struct IoStackParameters {
    pub length: u32,
    pub key: u32,
    pub flags: u32,
    pub byte_offset: i64,
}

#[repr(C)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: IoStackParameters,
}

#[repr(C, packed)]
pub struct FixedStr64 {
    pub blocks: [u64; 8],
}

#[repr(C, packed)]
pub struct Requests {
    pub request_key: u64,
    pub return_value: u64,
    pub request_pid: u64,
    pub request_addr: u64,
    pub target_pid: u64,
    pub target_addr: u64,
    pub mem_size: u64,
    pub dw_flags: u32,
    pub dx: u32,
    pub dy: u32,
    pub dw_data: u32,
    pub dw_extra_info: u64,
    pub b_vk: u16,
    pub b_scan: u16,
    pub name_length: u64,
    pub name_str: FixedStr64,
    pub window_handle: usize,
    pub protect_flags: u32,
    pub time_stamp: u64,
    pub secure_key: u64,
    pub check_sum: u64,
}

pub type DispatchFn = unsafe extern "system" fn(*mut DeviceObject, *mut c_void) -> NtStatus;
pub type UnloadFn = unsafe extern "system" fn(*mut DriverObject);
pub type DriverInitFn =
    unsafe extern "system" fn(*mut DriverObject, *mut UnicodeString) -> NtStatus;
pub type IoCreateDriverFn = unsafe extern "system" fn(*mut UnicodeString, DriverInitFn) -> NtStatus;
