// Copyright (c) 2026 渟雲. All rights reserved.

const KUSER_SHARED_SYSTEM_TIME: u64 = 0xFFFF_F780_0000_0014;

pub fn query_system_time() -> i64 {
    unsafe {
        let ptr = KUSER_SHARED_SYSTEM_TIME as *const i64;
        *ptr
    }
}
