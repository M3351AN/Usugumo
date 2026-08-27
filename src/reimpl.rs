// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::imports::resolve_kernel_export;

static mut G_PEB_OFFSET: u32 = 0;

fn get_peb_offset() -> u32 {
    unsafe {
        if G_PEB_OFFSET != 0 {
            return G_PEB_OFFSET;
        }
        let func = resolve_kernel_export(crate::hash!(b"PsGetProcessPeb"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if crate::helpers::read_u8(p, i) == 0x48
                && crate::helpers::read_u8(p, i + 1) == 0x8B
                && crate::helpers::read_u8(p, i + 2) == 0x81
            {
                let off = crate::helpers::read_u32(p, i + 3);
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
    let off = get_peb_offset();
    if off == 0 {
        return null_mut();
    }
    crate::helpers::read_u64(process as *const u8, off as usize) as *mut c_void
}

static mut G_IMAGE_FILE_NAME_OFFSET: u32 = 0;

fn get_image_file_name_offset() -> u32 {
    unsafe {
        if G_IMAGE_FILE_NAME_OFFSET != 0 {
            return G_IMAGE_FILE_NAME_OFFSET;
        }
        let func = resolve_kernel_export(crate::hash!(b"PsGetProcessImageFileName"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if crate::helpers::read_u8(p, i) == 0x48
                && crate::helpers::read_u8(p, i + 1) == 0x8D
                && crate::helpers::read_u8(p, i + 2) == 0x81
            {
                let off = crate::helpers::read_u32(p, i + 3);
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
        let func = resolve_kernel_export(crate::hash!(b"PsGetProcessId"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if crate::helpers::read_u8(p, i) == 0x48
                && crate::helpers::read_u8(p, i + 1) == 0x8B
                && crate::helpers::read_u8(p, i + 2) == 0x81
            {
                let off = crate::helpers::read_u32(p, i + 3);
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
    let off = get_process_id_offset();
    if off == 0 {
        return 0;
    }
    crate::helpers::read_u64(process as *const u8, off as usize) as usize
}

static mut G_PROCESS_EXIT_STATUS_OFFSET: u32 = 0;

fn get_process_exit_status_offset() -> u32 {
    unsafe {
        if G_PROCESS_EXIT_STATUS_OFFSET != 0 {
            return G_PROCESS_EXIT_STATUS_OFFSET;
        }
        let func = resolve_kernel_export(crate::hash!(b"PsGetProcessExitStatus"));
        if func.is_null() {
            return 0;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x10 {
            if crate::helpers::read_u8(p, i) == 0x8B && crate::helpers::read_u8(p, i + 1) == 0x81 {
                let off = crate::helpers::read_u32(p, i + 2);
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
    let off = get_process_exit_status_offset();
    if off == 0 {
        return 0;
    }
    crate::helpers::read_u32(process as *const u8, off as usize) as i32
}

static mut G_PFN_BASE: u64 = 0;
static mut G_PTE_BASE: u64 = 0;

fn parse_bases() {
    unsafe {
        if G_PFN_BASE != 0 && G_PTE_BASE != 0 {
            return;
        }
        let func = resolve_kernel_export(crate::hash!(b"MmGetVirtualForPhysical"));
        if func.is_null() {
            return;
        }
        let p = func as *const u8;
        let mut i = 0;
        while i < 0x20 {
            if crate::helpers::read_u8(p, i) == 0x48 && crate::helpers::read_u8(p, i + 1) == 0xB8 {
                G_PFN_BASE = crate::helpers::read_u64(p, i + 2);
                return;
            }
            i += 1;
        }
        let mut j = 0;
        while j < 0x40 {
            if crate::helpers::read_u8(p, j) == 0x48 && crate::helpers::read_u8(p, j + 1) == 0xBA {
                G_PTE_BASE = crate::helpers::read_u64(p, j + 2);
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
        let val = crate::helpers::read_u64((G_PFN_BASE + pfn * 48) as *const u8, 0);
        let shifted = val << 25;
        let base2_shifted = G_PTE_BASE << 25;
        let diff = (shifted.wrapping_sub(base2_shifted) as i64) >> 16;
        (diff as u64 + offset) as *mut c_void
    }
}
