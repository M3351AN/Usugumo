// Copyright (c) 2026 渟雲. All rights reserved.

use crate::types::{NtStatus, Requests, UnicodeString};

unsafe extern "system" {
    pub fn InitPmemPages() -> NtStatus;
    pub fn CleanupPmemPages();
    pub fn GetBootVolumeSerial(out: *mut i8, out_len: u32) -> NtStatus;
    pub fn GenerateObfuscatedName(
        serial: *const u8,
        serial_len: u32,
        out: *mut u16,
        out_len: u32,
    ) -> NtStatus;
    pub fn RtlInitUnicodeStringMeme(dest: *mut UnicodeString, source: *const u16);
    pub fn InitGreProtectSpriteContent() -> u8;
    pub fn MouseRelease();
    pub fn KeyboardRelease();
    pub fn Sha256(data: *const u8, length: usize, digest: *mut u8);
    pub fn RtlCompareMemoryMeme(src1: *const u8, src2: *const u8, len: usize) -> usize;
    pub fn CalculateRequestsChecksum(req: *mut Requests) -> u64;
    pub fn ReadVM(req: *mut Requests) -> u8;
    pub fn WriteVM(req: *mut Requests) -> u8;
    pub fn GetDllAddress(req: *mut Requests) -> u64;
    pub fn GetDllSize(req: *mut Requests) -> u64;
    pub fn GetProcessIdByName(req: *mut Requests) -> u64;
    pub fn HandleMouseEvent(req: *mut Requests);
    pub fn HandleKeybdEvent(req: *mut Requests);
    pub fn HandleAntiCapture(req: *mut Requests) -> u8;
}
