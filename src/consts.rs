// Copyright (c) 2026 渟雲. All rights reserved.

use crate::types::NtStatus;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as i32;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as i32;

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
