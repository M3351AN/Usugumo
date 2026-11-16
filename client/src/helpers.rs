// Copyright (c) 2026 渟雲. All rights reserved.

use std::sync::OnceLock;

use crate::types::FixedStr64;

pub(crate) const CRC64_POLYNOMIAL: u64 = 0x85E1C3D753D46D27;

fn crc64_table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u64; 256];
        for (rcx, slot) in table.iter_mut().enumerate() {
            let mut rax = rcx as u64;
            let mut i = 0;
            while i < 8 {
                if rax & 1 != 0 {
                    rax ^= CRC64_POLYNOMIAL;
                }
                rax >>= 1;
                i += 1;
            }
            *slot = rax;
        }
        table
    })
}

pub(crate) fn crc64(bytes: &[u8]) -> u64 {
    let table = crc64_table();
    let mut rax = 0xFFFF_FFFF_FFFF_FFFFu64;
    for &b in bytes {
        rax ^= b as u64;
        let idx = (rax & 0xFF) as usize;
        rax >>= 8;
        rax ^= table[idx];
    }
    !rax
}

pub(crate) fn encode_fixed_str64(input: &[u8], out: &mut FixedStr64) {
    let mut blocks = [0u64; 8];
    for (i, &c) in input.iter().take(64).enumerate() {
        let block = i / 8;
        let pos = i % 8;
        blocks[block] |= (c as u64) << (8 * (7 - pos));
    }
    *out = FixedStr64 { blocks };
}

pub(crate) fn decode_fixed_str64(fs: *const FixedStr64, output: *mut i8, orig_len: u64) {
    unsafe {
        let mut idx = 0usize;
        for block in 0..8 {
            for i in 0..8 {
                if idx as u64 >= orig_len {
                    break;
                }
                let shift = 8 * (7 - i);
                *output.add(idx) = (((*fs).blocks[block] >> shift) & 0xFF) as i8;
                idx += 1;
            }
        }
        *output.add(orig_len as usize) = 0;
    }
}
