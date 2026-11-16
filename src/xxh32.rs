// Copyright (c) 2026 渟雲. All rights reserved.

const PRIME1: u32 = 0x9E37_79B1;
const PRIME2: u32 = 0x85EB_CA77;
const PRIME3: u32 = 0xC2B2_AE3D;
const PRIME4: u32 = 0x27D4_EB2F;
const PRIME5: u32 = 0x1656_67B1;

const fn round(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(PRIME2))
        .rotate_left(13)
        .wrapping_mul(PRIME1)
}

const fn read_u32(b: &[u8], off: usize) -> u32 {
    (b[off] as u32)
        | ((b[off + 1] as u32) << 8)
        | ((b[off + 2] as u32) << 16)
        | ((b[off + 3] as u32) << 24)
}

pub const fn xxh32(input: &[u8]) -> u32 {
    let len = input.len();
    let mut h: u32 = PRIME5;
    let mut i = 0usize;

    if len >= 16 {
        let mut v1 = PRIME1.wrapping_add(PRIME2);
        let mut v2 = PRIME2;
        let mut v3: u32 = 0;
        let mut v4 = 0u32.wrapping_sub(PRIME1);
        while i + 16 <= len {
            v1 = round(v1, read_u32(input, i));
            v2 = round(v2, read_u32(input, i + 4));
            v3 = round(v3, read_u32(input, i + 8));
            v4 = round(v4, read_u32(input, i + 12));
            i += 16;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    }

    h = h.wrapping_add(len as u32);
    while i + 4 <= len {
        h = h
            .wrapping_add(read_u32(input, i).wrapping_mul(PRIME3))
            .rotate_left(17)
            .wrapping_mul(PRIME4);
        i += 4;
    }
    while i < len {
        h = h
            .wrapping_add((input[i] as u32).wrapping_mul(PRIME5))
            .rotate_left(11)
            .wrapping_mul(PRIME1);
        i += 1;
    }

    h ^= h >> 15;
    h = h.wrapping_mul(PRIME2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME3);
    h ^= h >> 16;
    h
}

pub const fn tag_hex(tag: u32) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    let mut i = 0usize;
    while i < 8 {
        let nib = (tag >> (28 - 4 * i)) & 0xF;
        out[i] = HEX[nib as usize];
        i += 1;
    }
    out
}

pub const fn key_of(name: &str) -> [u8; 8] {
    tag_hex(xxh32(name.as_bytes()))
}
