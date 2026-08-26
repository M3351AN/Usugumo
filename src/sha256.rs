// Copyright (c) 2026 渟雲. All rights reserved.

const K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

const H0: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

#[inline]
const fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

#[inline]
fn load_be(p: *const u8) -> u32 {
    unsafe {
        ((*p as u32) << 24)
            | ((*p.add(1) as u32) << 16)
            | ((*p.add(2) as u32) << 8)
            | (*p.add(3) as u32)
    }
}

fn compress(block: *const u8, state: &mut [u32; 8]) {
    unsafe {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = load_be(block.add(i * 4));
        }
        for i in 16..64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

pub fn sha256(data: *const u8, length: usize, digest: *mut u8) {
    unsafe {
        let mut state = H0;
        let mut p = data;
        let full = length / 64;
        let rem = length % 64;

        for _ in 0..full {
            compress(p, &mut state);
            p = p.add(64);
        }

        let mut last = [0u8; 64];
        let mut rem_idx = 0usize;
        for i in 0..rem {
            last[rem_idx] = *p.add(i);
            rem_idx += 1;
        }
        last[rem_idx] = 0x80;
        rem_idx += 1;

        let bit_len = (length as u64) * 8;
        if rem_idx > 56 {
            while rem_idx < 64 {
                last[rem_idx] = 0;
                rem_idx += 1;
            }
            compress(last.as_ptr(), &mut state);
            rem_idx = 0;
            while rem_idx < 56 {
                last[rem_idx] = 0;
                rem_idx += 1;
            }
        } else {
            while rem_idx < 56 {
                last[rem_idx] = 0;
                rem_idx += 1;
            }
        }
        for i in 0..8 {
            last[56 + i] = (bit_len >> (56 - i * 8)) as u8;
        }
        compress(last.as_ptr(), &mut state);

        for i in 0..8 {
            *digest.add(i * 4 + 0) = (state[i] >> 24) as u8;
            *digest.add(i * 4 + 1) = (state[i] >> 16) as u8;
            *digest.add(i * 4 + 2) = (state[i] >> 8) as u8;
            *digest.add(i * 4 + 3) = state[i] as u8;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Sha256(data: *const u8, length: usize, digest: *mut u8) {
    sha256(data, length, digest)
}

const fn load_be_const(input: &[u8], offset: usize) -> u32 {
    ((input[offset] as u32) << 24)
        | ((input[offset + 1] as u32) << 16)
        | ((input[offset + 2] as u32) << 8)
        | (input[offset + 3] as u32)
}

const fn compress_const(state: &mut [u32; 8], input: &[u8], offset: usize) {
    let mut w = [0u32; 64];
    let mut i = 0;
    while i < 16 {
        w[i] = load_be_const(input, offset + i * 4);
        i += 1;
    }
    while i < 64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    i = 0;
    while i < 64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub const fn sha256_const(input: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let full = input.len() / 64;
    let rem = input.len() % 64;

    let mut block = 0;
    while block < full {
        compress_const(&mut state, input, block * 64);
        block += 1;
    }

    let mut last = [0u8; 64];
    let mut idx = 0;
    while idx < rem {
        last[idx] = input[full * 64 + idx];
        idx += 1;
    }
    last[idx] = 0x80;
    idx += 1;

    let bit_len = (input.len() as u64) * 8;
    if idx > 56 {
        while idx < 64 {
            last[idx] = 0;
            idx += 1;
        }
        compress_const(&mut state, &last, 0);
        idx = 0;
        while idx < 56 {
            last[idx] = 0;
            idx += 1;
        }
    } else {
        while idx < 56 {
            last[idx] = 0;
            idx += 1;
        }
    }
    let mut bi = 0;
    while bi < 8 {
        last[56 + bi] = (bit_len >> (56 - bi * 8)) as u8;
        bi += 1;
    }
    compress_const(&mut state, &last, 0);

    let mut out = [0u8; 32];
    let mut oi = 0;
    while oi < 8 {
        out[oi * 4 + 0] = (state[oi] >> 24) as u8;
        out[oi * 4 + 1] = (state[oi] >> 16) as u8;
        out[oi * 4 + 2] = (state[oi] >> 8) as u8;
        out[oi * 4 + 3] = state[oi] as u8;
        oi += 1;
    }
    out
}
