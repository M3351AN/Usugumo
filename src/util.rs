// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmemmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void {
    let d = dst as *mut u8;
    let s = src as *const u8;
    unsafe {
        if (d as usize) <= (s as usize) || (s as usize).wrapping_add(len) <= (d as usize) {
            for i in 0..len {
                *d.add(i) = *s.add(i);
            }
        } else {
            let mut i = len;
            while i > 0 {
                i -= 1;
                *d.add(i) = *s.add(i);
            }
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmemset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void {
    let d = dst as *mut u8;
    let v = val as u8;
    unsafe {
        for i in 0..len {
            *d.add(i) = v;
        }
    }
    dst
}

pub fn kstrlen(s: *const i8) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const i8) -> usize {
    kstrlen(s)
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
pub extern "C" fn kwcslen(s: *const u16) -> usize {
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub fn zero_memory(ptr: *mut u8, len: usize) {
    unsafe {
        let mut p = ptr;
        for _ in 0..len {
            core::ptr::write_volatile(p, 0u8);
            p = p.add(1);
        }
    }
}
