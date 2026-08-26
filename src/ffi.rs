// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

use crate::types::{FixedStr64, NtStatus, Requests, UnicodeString};

unsafe extern "system" {
    pub fn GetBootVolumeSerial(out: *mut i8, out_len: u32) -> NtStatus;
    pub fn GenerateObfuscatedName(
        serial: *const u8,
        serial_len: u32,
        out: *mut u16,
        out_len: u32,
    ) -> NtStatus;
    pub fn RtlInitUnicodeStringMeme(dest: *mut UnicodeString, source: *const u16);
    pub fn MouseRelease();
    pub fn KeyboardRelease();
    pub fn SearchSignForImage(
        image_base: *mut c_void,
        pattern: *const u8,
        mask: *const i8,
        len: u32,
    ) -> *mut c_void;
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
    pub fn DecodeFixedStr64(fs: *const FixedStr64, output: *mut i8, orig_len: u64);
    pub fn ConvertToPWSTR(ascii: *const i8) -> *mut u16;
    pub fn kmemset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void;
    pub fn kmemmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    pub fn Sha256(data: *const u8, length: usize, digest: *mut u8);
    pub fn RtlCompareMemoryMeme(src1: *const u8, src2: *const u8, len: usize) -> usize;
    pub fn CalculateRequestsChecksum(req: *mut Requests) -> u64;
    pub fn HandleMouseEvent(req: *mut Requests);
    pub fn HandleKeybdEvent(req: *mut Requests);
}
