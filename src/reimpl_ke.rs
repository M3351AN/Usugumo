// Copyright (c) 2026 渟雲. All rights reserved.

const KUSER_SHARED_SYSTEM_TIME: u64 = 0xFFFF_F780_0000_0014;

pub fn query_system_time() -> i64 {
    crate::helpers::read_u64(KUSER_SHARED_SYSTEM_TIME as *const u8, 0) as i64
}

pub fn ke_get_current_irql() -> u8 {
    let irql: u64;
    unsafe {
        core::arch::asm!("mov {}, cr8", out(reg) irql, options(nostack));
    }
    irql as u8
}

pub fn kz_raise_irql(new_irql: u8) -> u8 {
    let old: u64;
    let new = new_irql as u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr8",
            "mov cr8, {1}",
            out(reg) old,
            in(reg) new,
            options(nostack)
        );
    }
    old as u8
}

pub fn kz_lower_irql(new_irql: u8) {
    let new = new_irql as u64;
    unsafe {
        core::arch::asm!("mov cr8, {}", in(reg) new, options(nostack));
    }
}
