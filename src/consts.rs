use crate::types::nt_status;

pub const status_success: nt_status = 0;
pub const status_unsuccessful: nt_status = 0xC000_0001u32 as i32;
pub const status_insufficient_resources: nt_status = 0xC000_009Au32 as i32;
pub const status_not_found: nt_status = 0xC000_0225u32 as i32;

pub const file_device_unknown: u32 = 0x22;
pub const file_device_secure_open: u32 = 0x10;
pub const pool_flag_non_paged: u64 = 0x40;
pub const symlink_tag: u32 = 0x6B4C7355;

pub const irp_mj_create: usize = 0;
pub const irp_mj_close: usize = 2;
pub const irp_mj_read: usize = 3;
pub const irp_mj_write: usize = 4;

pub const do_direct_io: u32 = 0x10;
pub const do_buffered_io: u32 = 0x04;
pub const do_device_initializing: u32 = 0x80;
