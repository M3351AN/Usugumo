// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

use crate::types::UnicodeString;

unsafe extern "system" {
    pub fn RtlInitUnicodeStringMeme(dest: *mut UnicodeString, source: *const u16);
    pub fn RtlImageNtHeaderMeme(base: *mut c_void) -> *mut c_void;
    pub fn KeGetCurrentIrqlMeme() -> u8;
    pub fn RtlCompareMemoryMeme(src1: *const u8, src2: *const u8, len: usize) -> usize;
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
