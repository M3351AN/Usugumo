// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;

unsafe extern "system" {
    pub fn KeyboardClassServiceCallbackMeme(
        device: *mut c_void,
        input_start: *mut c_void,
        input_end: *mut c_void,
        consumed: *mut u32,
    );
}
