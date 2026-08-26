// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

use crate::types::{Requests, UnicodeString};

unsafe extern "system" {
    pub fn RtlInitUnicodeStringMeme(dest: *mut UnicodeString, source: *const u16);
    pub fn RtlImageNtHeaderMeme(base: *mut c_void) -> *mut c_void;
    pub fn ResolveRelativeAddress(base: *mut c_void, offset: u32) -> *mut u8;
    pub fn KeGetCurrentIrqlMeme() -> u8;
    pub fn PsGetProcessExitStatusTrick(proc: *mut c_void) -> i32;
    pub fn PsGetProcessPebTrick(proc: *mut c_void) -> *mut c_void;
    pub fn PsGetProcessImageFileNameTrick(proc: *mut c_void) -> *mut i8;
    pub fn PsGetProcessIdTrick(proc: *mut c_void) -> usize;
    pub fn MmGetVirtualForPhysicalTrick(phys: u64) -> *mut c_void;
    pub fn kwcsicmp(a: *const u16, b: *const u16) -> i32;
    pub fn kstricmp(a: *const i8, b: *const i8) -> i32;
    pub fn kwcslen(s: *const u16) -> usize;
    pub fn kmemset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void;
    pub fn kmemmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    pub fn RtlCompareMemoryMeme(src1: *const u8, src2: *const u8, len: usize) -> usize;
    pub fn CalculateRequestsChecksum(req: *mut Requests) -> u64;
    pub fn KzRaiseIrqlMeme(new_irql: u8) -> u8;
    pub fn KzLowerIrqlMeme(new_irql: u8);
    pub fn MouseClassServiceCallbackMeme(
        device: *mut c_void,
        input_start: *mut c_void,
        input_end: *mut c_void,
        consumed: *mut u32,
    );
    pub fn KeyboardClassServiceCallbackMeme(
        device: *mut c_void,
        input_start: *mut c_void,
        input_end: *mut c_void,
        consumed: *mut u32,
    );
}
