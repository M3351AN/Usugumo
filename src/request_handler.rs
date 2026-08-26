// Copyright (c) 2026 渟雲. All rights reserved.

use crate::consts::*;
use crate::ffi::*;
use crate::reimpl_ke::query_system_time;
use crate::types::Requests;

const TICKS_PER_SECOND: i64 = 10_000_000;

#[unsafe(no_mangle)]
pub static PUBLIC_KEY: [u8; 32] = [
    0x29, 0x51, 0x35, 0x8E, 0x6F, 0x85, 0xA5, 0xDA, 0xE0, 0x8E, 0x60, 0x3E, 0x94, 0x6E, 0xE9, 0xBD,
    0x49, 0xA1, 0x67, 0xE1, 0x02, 0xA3, 0xA0, 0x61, 0x4E, 0x55, 0x24, 0x5C, 0x0A, 0x16, 0xD6, 0xD0,
];

fn get_timestamp() -> i64 {
    query_system_time()
}

fn is_timestamp_valid(ts: u64, tolerance_seconds: i64) -> bool {
    let current = get_timestamp();
    let tolerance_ticks = tolerance_seconds * TICKS_PER_SECOND;
    let diff = if ts > current as u64 {
        ts - current as u64
    } else {
        current as u64 - ts
    };
    diff <= tolerance_ticks as u64
}

fn verify_secure_key(secure_key: u64) -> bool {
    let key_bytes = secure_key.to_ne_bytes();
    let mut local_checksum = [0u8; 32];
    unsafe {
        Sha256(key_bytes.as_ptr(), 8, local_checksum.as_mut_ptr());
        RtlCompareMemoryMeme(local_checksum.as_ptr(), PUBLIC_KEY.as_ptr(), 32) == 32
    }
}

pub unsafe extern "system" fn request_handler(pstruct: *mut Requests) -> u8 {
    unsafe {
        if pstruct.is_null() {
            return 0;
        }
        if !is_timestamp_valid((*pstruct).time_stamp, 1) {
            return 0;
        }
        if (*pstruct).check_sum != CalculateRequestsChecksum(pstruct) {
            return 0;
        }
        if !verify_secure_key((*pstruct).secure_key) {
            return 0;
        }
        if ((*pstruct).request_key & USUGUMO_SIGNATURE_MASK) != USUGUMO_SIGNATURE_MASK {
            return 0;
        }
        let func = (*pstruct).request_key & USUGUMO_FUNC_BITS;

        if func & USUGUMO_PROBE != 0 {
            (*pstruct).return_value = USUGUMO_SUPPORTED_MASK;
            return 1;
        }

        let mut handled = false;

        if func & USUGUMO_READ != 0 {
            (*pstruct).return_value = ReadVM(pstruct) as u64;
            handled = true;
        }
        if func & USUGUMO_WRITE != 0 {
            (*pstruct).return_value = WriteVM(pstruct) as u64;
            handled = true;
        }
        if func & USUGUMO_MOUSE != 0 {
            HandleMouseEvent(pstruct);
            (*pstruct).return_value = 1;
            handled = true;
        }
        if func & USUGUMO_KEYBD != 0 {
            HandleKeybdEvent(pstruct);
            (*pstruct).return_value = 1;
            handled = true;
        }
        if func & USUGUMO_MODULE_BASE != 0 {
            (*pstruct).return_value = GetDllAddress(pstruct);
            handled = true;
        }
        if func & USUGUMO_MODULE_SIZE != 0 {
            (*pstruct).return_value = GetDllSize(pstruct);
            handled = true;
        }
        if func & USUGUMO_PID != 0 {
            (*pstruct).return_value = GetProcessIdByName(pstruct);
            handled = true;
        }
        if func & USUGUMO_ANTI_CAPTURE != 0 {
            (*pstruct).return_value = HandleAntiCapture(pstruct) as u64;
            handled = true;
        }

        handled as u8
    }
}
