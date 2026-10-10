// Copyright (c) 2026 渟雲. All rights reserved.

use crate::types::NtStatus;
use crate::types::UnicodeString;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as i32;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as i32;
pub const STATUS_PENDING: NtStatus = 0x103;
pub const STATUS_PARTIAL_COPY: NtStatus = 0xC000_0204u32 as i32;

pub const PASSIVE_LEVEL: u8 = 0;
pub const DISPATCH_LEVEL: u8 = 2;

pub const KERNEL_MODE: u8 = 0;

pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;

pub const PMEM_PAGE_SIZE: usize = 0x1000;
pub const PMEM_PMASK: u64 = 0x000F_FFFF_FFFF_F000;
pub const PMEM_MAX_CPU_PAGES: usize = 64;
pub const POOL_FLAG_UNINITIALIZED: u64 = 0;
pub const POOL_TAG_COPY: u32 = 0x446C_6148;

pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x10;
pub const POOL_FLAG_NON_PAGED: u64 = 0x40;
pub const SYMLINK_TAG: u32 = 0x6B4C7355;

pub const IRP_MJ_CREATE: usize = 0;
pub const IRP_MJ_CLOSE: usize = 2;
pub const IRP_MJ_READ: usize = 3;
pub const IRP_MJ_WRITE: usize = 4;

pub const DO_DIRECT_IO: u32 = 0x10;
pub const DO_BUFFERED_IO: u32 = 0x04;
pub const DO_DEVICE_INITIALIZING: u32 = 0x80;

pub const USUGUMO_FUNC_BITS: u64 = 0x0000_0000_0000_FFFF;
pub const USUGUMO_SIGNATURE: u64 = 0xA5;
pub const USUGUMO_SIGNATURE_MASK: u64 = USUGUMO_SIGNATURE << 56;
pub const USUGUMO_PROBE: u64 = 1 << 0;
pub const USUGUMO_READ: u64 = 1 << 1;
pub const USUGUMO_WRITE: u64 = 1 << 2;
pub const USUGUMO_MOUSE: u64 = 1 << 3;
pub const USUGUMO_KEYBD: u64 = 1 << 4;
pub const USUGUMO_MODULE_BASE: u64 = 1 << 5;
pub const USUGUMO_MODULE_SIZE: u64 = 1 << 6;
pub const USUGUMO_PID: u64 = 1 << 7;
pub const USUGUMO_ANTI_CAPTURE: u64 = 1 << 8;
pub const USUGUMO_SUPPORTED_MASK: u64 = USUGUMO_PROBE
    | USUGUMO_READ
    | USUGUMO_WRITE
    | USUGUMO_MOUSE
    | USUGUMO_KEYBD
    | USUGUMO_MODULE_BASE
    | USUGUMO_MODULE_SIZE
    | USUGUMO_PID
    | USUGUMO_ANTI_CAPTURE;

pub static mut G_ACTIVE_PROCESS_LINKS_OFFSET: u32 = 0;
pub static mut G_USER_DIRECTORY_TABLE_BASE_OFFSET: u32 = 0;

pub static mut G_SYMBOLIC_LINK_NAME: UnicodeString = UnicodeString {
    length: 0,
    maximum_length: 0,
    buffer: core::ptr::null_mut(),
};
