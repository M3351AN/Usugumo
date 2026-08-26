// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::ffi::{kmemmove, kmemset};
use crate::imports::resolve_kernel_export;
use crate::sha256::sha256_const;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const i8) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void {
    unsafe { kmemset(dst, val, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void {
    unsafe { kmemmove(dst, src, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void {
    unsafe { kmemmove(dst, src, len) }
}

pub fn kstricmp(mut a: *const i8, mut b: *const i8) -> i32 {
    unsafe {
        loop {
            let c1 = *a as i32;
            a = a.add(1);
            let c2 = *b as i32;
            b = b.add(1);
            let mut x = c1 + 32;
            if (c1 as u32).wrapping_sub(65) > 0x19 {
                x = c1;
            }
            let mut y = c2 + 32;
            if (c2 as u32).wrapping_sub(65) > 0x19 {
                y = c2;
            }
            if x == 0 || x != y {
                return x - y;
            }
        }
    }
}

pub fn kwcsicmp(mut a: *const u16, mut b: *const u16) -> i32 {
    unsafe {
        loop {
            let c1 = *a as u32;
            a = a.add(1);
            let c2 = *b as u32;
            b = b.add(1);
            let mut x = c1 + 32;
            if c1.wrapping_sub(65) & 0xFFFF > 0x19 {
                x = c1;
            }
            let mut y = c2 + 32;
            if c2.wrapping_sub(65) & 0xFFFF > 0x19 {
                y = c2;
            }
            if x == 0 || x != y {
                return x as i32 - y as i32;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub fn kwcslen(s: *const u16) -> usize {
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

static mut G_PEB_OFFSET: u32 = 0;

fn get_peb_offset() -> u32 {
    unsafe {
        if G_PEB_OFFSET != 0 {
            return G_PEB_OFFSET;
        }
        let func = resolve_kernel_export(sha256_const(b"PsGetProcessPeb"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if *p.add(i) == 0x48 && *p.add(i + 1) == 0x8B && *p.add(i + 2) == 0x81 {
                let off = u32::from_le_bytes([
                    *p.add(i + 3),
                    *p.add(i + 4),
                    *p.add(i + 5),
                    *p.add(i + 6),
                ]);
                if off > 0x10 && off <= 0x1000 {
                    G_PEB_OFFSET = off;
                    return off;
                }
            }
            i += 1;
        }
        0
    }
}

pub fn ps_get_process_peb_trick(process: *mut c_void) -> *mut c_void {
    unsafe {
        let off = get_peb_offset();
        if off == 0 {
            return null_mut();
        }
        *((process as *const u8).add(off as usize) as *const *mut c_void)
    }
}

static mut G_IMAGE_FILE_NAME_OFFSET: u32 = 0;

fn get_image_file_name_offset() -> u32 {
    unsafe {
        if G_IMAGE_FILE_NAME_OFFSET != 0 {
            return G_IMAGE_FILE_NAME_OFFSET;
        }
        let func = resolve_kernel_export(sha256_const(b"PsGetProcessImageFileName"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if *p.add(i) == 0x48 && *p.add(i + 1) == 0x8D && *p.add(i + 2) == 0x81 {
                let off = u32::from_le_bytes([
                    *p.add(i + 3),
                    *p.add(i + 4),
                    *p.add(i + 5),
                    *p.add(i + 6),
                ]);
                if off > 0x10 && off <= 0x1000 {
                    G_IMAGE_FILE_NAME_OFFSET = off;
                    return off;
                }
            }
            i += 1;
        }
        0
    }
}

pub fn ps_get_process_image_file_name_trick(process: *mut c_void) -> *mut i8 {
    unsafe {
        let off = get_image_file_name_offset();
        if off == 0 {
            return null_mut();
        }
        (process as *const u8).add(off as usize) as *mut i8
    }
}

static mut G_PROCESS_ID_OFFSET: u32 = 0;

fn get_process_id_offset() -> u32 {
    unsafe {
        if G_PROCESS_ID_OFFSET != 0 {
            return G_PROCESS_ID_OFFSET;
        }
        let func = resolve_kernel_export(sha256_const(b"PsGetProcessId"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if *p.add(i) == 0x48 && *p.add(i + 1) == 0x8B && *p.add(i + 2) == 0x81 {
                let off = u32::from_le_bytes([
                    *p.add(i + 3),
                    *p.add(i + 4),
                    *p.add(i + 5),
                    *p.add(i + 6),
                ]);
                if off > 0x10 && off <= 0x1000 {
                    G_PROCESS_ID_OFFSET = off;
                    return off;
                }
            }
            i += 1;
        }
        0
    }
}

pub fn ps_get_process_id_trick(process: *mut c_void) -> usize {
    unsafe {
        let off = get_process_id_offset();
        if off == 0 {
            return 0;
        }
        *((process as *const u8).add(off as usize) as *const usize)
    }
}

static mut G_PROCESS_EXIT_STATUS_OFFSET: u32 = 0;

fn get_process_exit_status_offset() -> u32 {
    unsafe {
        if G_PROCESS_EXIT_STATUS_OFFSET != 0 {
            return G_PROCESS_EXIT_STATUS_OFFSET;
        }
        let func = resolve_kernel_export(sha256_const(b"PsGetProcessExitStatus"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if *p.add(i) == 0x8B && *p.add(i + 1) == 0x81 {
                let off = u32::from_le_bytes([
                    *p.add(i + 2),
                    *p.add(i + 3),
                    *p.add(i + 4),
                    *p.add(i + 5),
                ]);
                if off > 0x10 && off <= 0x1000 {
                    G_PROCESS_EXIT_STATUS_OFFSET = off;
                    return off;
                }
            }
            i += 1;
        }
        0
    }
}

pub fn ps_get_process_exit_status_trick(process: *mut c_void) -> i32 {
    unsafe {
        let off = get_process_exit_status_offset();
        if off == 0 {
            return 0;
        }
        *((process as *const u8).add(off as usize) as *const i32)
    }
}

static mut G_PFN_BASE: u64 = 0;
static mut G_PTE_BASE: u64 = 0;

fn parse_bases() {
    unsafe {
        if G_PFN_BASE != 0 && G_PTE_BASE != 0 {
            return;
        }
        let func = resolve_kernel_export(sha256_const(b"MmGetVirtualForPhysical"));
        if func.is_null() {
            return;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x20 {
            if *p.add(i) == 0x48 && *p.add(i + 1) == 0xB8 {
                G_PFN_BASE = u64::from_le_bytes(core::ptr::read(p.add(i + 2) as *const [u8; 8]));
                return;
            }
            i += 1;
        }
        let mut j = 0;
        while j < 0x40 {
            if *p.add(j) == 0x48 && *p.add(j + 1) == 0xBA {
                G_PTE_BASE = u64::from_le_bytes(core::ptr::read(p.add(j + 2) as *const [u8; 8]));
                return;
            }
            j += 1;
        }
    }
}

pub fn mm_get_virtual_for_physical_trick(physical_address: u64) -> *mut c_void {
    unsafe {
        parse_bases();
        let pfn = physical_address >> 12;
        let offset = physical_address & 0xFFF;
        let val = *((G_PFN_BASE + pfn * 48) as *const u64);
        let shifted = val << 25;
        let base2_shifted = G_PTE_BASE << 25;
        let diff = (shifted.wrapping_sub(base2_shifted) as i64) >> 16;
        (diff as u64 + offset) as *mut c_void
    }
}
