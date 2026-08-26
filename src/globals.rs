// Copyright (c) 2026 渟雲. All rights reserved.

use crate::types::UnicodeString;

pub static mut G_SYMBOLIC_LINK_NAME: UnicodeString = UnicodeString {
    length: 0,
    maximum_length: 0,
    buffer: core::ptr::null_mut(),
};
