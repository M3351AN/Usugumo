// Copyright (c) 2026 渟雲. All rights reserved.

const KUSER_SHARED_INTERRUPT_TIME: u64 = 0xFFFF_F780_0000_0008;

static mut S_STATE: [u64; 4] = [0; 4];

#[inline]
fn rotl64(x: u64, k: u32) -> u64 {
    (x << k) | (x >> (64 - k))
}

#[inline]
fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[inline]
fn xoshiro256_starstar() -> u64 {
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(S_STATE);
        let result = rotl64(s[1].wrapping_mul(5), 7).wrapping_mul(9);
        let t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = rotl64(s[3], 45);

        result
    }
}

pub fn random_engine_next() -> u64 {
    xoshiro256_starstar()
}

#[inline]
fn read_interrupt_time_raw() -> u64 {
    let ptr = KUSER_SHARED_INTERRUPT_TIME as *const u32;
    let lo = unsafe { *ptr };
    let mut hi1 = unsafe { *ptr.add(1) } as i32;
    let hi2 = unsafe { *ptr.add(2) } as i32;
    if hi1 != hi2 {
        hi1 = unsafe { *ptr.add(1) } as i32;
    }
    ((hi1 as u32 as u64) << 32) | lo as u64
}

fn rdtsc() -> u64 {
    let mut lo: u32;
    let mut hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack));
    }
    ((hi as u64) << 32) | lo as u64
}

pub fn random_engine_init() {
    unsafe {
        let mut entropy = [0u64; 4];
        entropy[0] = rdtsc();
        entropy[1] = read_interrupt_time_raw();
        entropy[2] = core::ptr::addr_of!(entropy) as u64;
        entropy[3] = rdtsc();

        let mut mix = 0x243F_6A88_85A3_08D3u64;
        for i in 0..4 {
            mix ^= entropy[i];
            S_STATE[i] = splitmix64(&mut mix);
        }

        if (S_STATE[0] | S_STATE[1] | S_STATE[2] | S_STATE[3]) == 0 {
            S_STATE[0] = 0x9E37_79B9_7F4A_7C15;
            S_STATE[1] = 0xD1B5_4A32_D192_ED03;
            S_STATE[2] = 0x85E1_C3D7_53D4_6D27;
            S_STATE[3] = 0x94D0_49BB_1331_11EB;
        }
    }
}
