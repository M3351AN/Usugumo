// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::types::UnicodeString;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const NT_HEADER_LIMIT: usize = 0x7FFF_FFFE_FFFF;

pub fn rtl_image_nt_header(image_base: *mut c_void) -> *mut c_void {
    let base = image_base as usize;
    if base.wrapping_sub(1) > usize::MAX - 2 {
        return null_mut();
    }
    if crate::helpers::read_u16(image_base as *const u8, 0) != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }
    let nt = base.wrapping_add(crate::helpers::read_u32(image_base as *const u8, 0x3C) as usize);
    if nt < base {
        return null_mut();
    }
    if base <= NT_HEADER_LIMIT {
        let t = nt.wrapping_add(0x107);
        if t < nt || t > NT_HEADER_LIMIT {
            return null_mut();
        }
    }
    if crate::helpers::read_u32(nt as *const u8, 0) == IMAGE_NT_SIGNATURE {
        return nt as *mut c_void;
    }
    null_mut()
}

pub fn rtl_compare_memory(src1: *const u8, src2: *const u8, len: usize) -> usize {
    let mut i = 0;
    while i < len {
        if crate::helpers::read_u8(src1, i) != crate::helpers::read_u8(src2, i) {
            break;
        }
        i += 1;
    }
    i
}

pub fn rtl_init_unicode_string(dest: *mut UnicodeString, source: *const u16) {
    unsafe {
        (*dest).length = 0;
        (*dest).maximum_length = 0;
        (*dest).buffer = source as *mut u16;
        if source.is_null() {
            return;
        }
        let mut len = crate::util::kwcslen(source) * 2;
        if len >= 0xFFFE {
            len = 0xFFFC;
        }
        (*dest).length = len as u16;
        (*dest).maximum_length = (len + 2) as u16;
    }
}
