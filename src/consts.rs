// Copyright (c) 2026 渟雲. All rights reserved.

use crate::types::NtStatus;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
pub const STATUS_INVALID_DEVICE_STATE: NtStatus = 0xC000_0184u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as i32;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as i32;
pub const STATUS_PENDING: NtStatus = 0x103;
pub const STATUS_PARTIAL_COPY: NtStatus = 0xC000_0204u32 as i32;
pub const STATUS_PENDING_VALUE: NtStatus = 0x0000_0103u32 as i32;

pub const PASSIVE_LEVEL: u8 = 0;
pub const DISPATCH_LEVEL: u8 = 2;

pub const KERNEL_MODE: u8 = 0;

pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;
pub const KERNEL_PTR_MIN: usize = 0xFFFF_8000_0000_0000;

pub const PMEM_PAGE_SIZE: usize = 0x1000;
pub const PMEM_PMASK: u64 = 0x000F_FFFF_FFFF_F000;
pub const PMEM_MAX_CPU_PAGES: usize = 64;
pub const POOL_FLAG_UNINITIALIZED: u64 = 0;
pub const POOL_TAG_COPY: u32 = 0x446C_6148;

pub const POOL_FLAG_NON_PAGED: u64 = 0x40;
pub const WSK_POOL_TAG: u32 = 0x4B53_5755;

pub const PORT_BASE: u16 = 20000;
pub const PORT_RANGE: u16 = 10000;

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

pub const USUGUMO_PROTOCOL_VERSION: u16 = 2;
pub const USUGUMO_PROTOCOL_VERSION_SHIFT: u32 = 16;

pub const fn probe_reply(version: u16, supported: u64) -> u64 {
    ((version as u64) << USUGUMO_PROTOCOL_VERSION_SHIFT) | (supported & 0xFFFF)
}

pub static mut G_ACTIVE_PROCESS_LINKS_OFFSET: u32 = 0;
pub static mut G_USER_DIRECTORY_TABLE_BASE_OFFSET: u32 = 0;
