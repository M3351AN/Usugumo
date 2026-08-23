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

pub const device_prefix: [u16; 8] = [
    '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16,
    'i' as u16, 'c' as u16, 'e' as u16, '\\' as u16,
];
pub const sym_prefix: [u16; 19] = [
    '\\' as u16, 'D' as u16, 'o' as u16, 's' as u16, 'D' as u16,
    'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
    's' as u16, '\\' as u16, 'G' as u16, 'l' as u16, 'o' as u16,
    'b' as u16, 'a' as u16, 'l' as u16, '\\' as u16,
];
