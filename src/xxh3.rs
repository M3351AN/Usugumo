const STRIPE_LEN: usize = 64;
const SECRET_CONSUME_RATE: usize = 8;
const SECRET_MERGEACCS_START: usize = 11;
const SECRET_LASTACC_START: usize = 7;
const MID_SIZE_MAX: usize = 240;
const SECRET_SIZE_MIN: usize = 136;

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

const DEFAULT_SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

const INITIAL_ACC: [u64; 8] = [
    PRIME32_3 as u64,
    PRIME64_1,
    0xC2B2_AE3D_27D4_EB4F,
    0x1656_67B1_9E37_79F9,
    0x85EB_CA77_C2B2_AE63,
    PRIME32_2 as u64,
    PRIME64_5,
    PRIME32_1 as u64,
];

const fn read_u32(input: &[u8], cursor: usize) -> u32 {
    input[cursor] as u32
        | (input[cursor + 1] as u32) << 8
        | (input[cursor + 2] as u32) << 16
        | (input[cursor + 3] as u32) << 24
}

const fn read_u64(input: &[u8], cursor: usize) -> u64 {
    input[cursor] as u64
        | (input[cursor + 1] as u64) << 8
        | (input[cursor + 2] as u64) << 16
        | (input[cursor + 3] as u64) << 24
        | (input[cursor + 4] as u64) << 32
        | (input[cursor + 5] as u64) << 40
        | (input[cursor + 6] as u64) << 48
        | (input[cursor + 7] as u64) << 56
}

const fn mult32_to64(left: u32, right: u32) -> u64 {
    (left as u64).wrapping_mul(right as u64)
}

const fn xorshift64(value: u64, shift: u64) -> u64 {
    value ^ (value >> shift)
}

const fn avalanche(mut value: u64) -> u64 {
    value = xorshift64(value, 37);
    value = value.wrapping_mul(0x1656_6791_9E37_79F9);
    xorshift64(value, 32)
}

const fn xxh64_avalanche(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    value ^= value >> 29;
    value = value.wrapping_mul(0x1656_67B1_9E37_79F9);
    value ^= value >> 32;
    value
}

const fn strong_avalanche(mut value: u64, len: u64) -> u64 {
    value ^= value.rotate_left(49) ^ value.rotate_left(24);
    value = value.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    value ^= (value >> 35).wrapping_add(len);
    value = value.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    xorshift64(value, 28)
}

const fn mul64_to128(left: u64, right: u64) -> (u64, u64) {
    let product = left as u128 * right as u128;
    (product as u64, (product >> 64) as u64)
}

const fn mul128_fold64(left: u64, right: u64) -> u64 {
    let (low, high) = mul64_to128(left, right);
    low ^ high
}

const fn mix16_b(
    input: &[u8],
    input_offset: usize,
    secret: &[u8],
    secret_offset: usize,
    seed: u64,
) -> u64 {
    let mut input_lo = read_u64(input, input_offset);
    let mut input_hi = read_u64(input, input_offset + 8);
    input_lo ^= read_u64(secret, secret_offset).wrapping_add(seed);
    input_hi ^= read_u64(secret, secret_offset + 8).wrapping_sub(seed);
    mul128_fold64(input_lo, input_hi)
}

const fn xxh3_64_9to16(input: &[u8], seed: u64, secret: &[u8]) -> u64 {
    let flip1 = (read_u64(secret, 24) ^ read_u64(secret, 32)).wrapping_add(seed);
    let flip2 = (read_u64(secret, 40) ^ read_u64(secret, 48)).wrapping_sub(seed);

    let input_lo = read_u64(input, 0) ^ flip1;
    let input_hi = read_u64(input, input.len() - 8) ^ flip2;

    let acc = (input.len() as u64)
        .wrapping_add(input_lo.swap_bytes())
        .wrapping_add(input_hi)
        .wrapping_add(mul128_fold64(input_lo, input_hi));
    avalanche(acc)
}

const fn xxh3_64_4to8(input: &[u8], mut seed: u64, secret: &[u8]) -> u64 {
    seed ^= ((seed as u32).swap_bytes() as u64) << 32;

    let input1 = read_u32(input, 0);
    let input2 = read_u32(input, input.len() - 4);

    let flip = (read_u64(secret, 8) ^ read_u64(secret, 16)).wrapping_sub(seed);
    let input64 = (input2 as u64).wrapping_add((input1 as u64) << 32);
    let keyed = input64 ^ flip;

    strong_avalanche(keyed, input.len() as u64)
}

const fn xxh3_64_1to3(input: &[u8], seed: u64, secret: &[u8]) -> u64 {
    let combo = ((input[0] as u32) << 16)
        | ((input[input.len() >> 1] as u32) << 24)
        | (input[input.len() - 1] as u32)
        | ((input.len() as u32) << 8);

    let flip = ((read_u32(secret, 0) ^ read_u32(secret, 4)) as u64).wrapping_add(seed);
    xxh64_avalanche((combo as u64) ^ flip)
}

const fn xxh3_64_0to16(input: &[u8], seed: u64, secret: &[u8]) -> u64 {
    if input.len() > 8 {
        xxh3_64_9to16(input, seed, secret)
    } else if input.len() >= 4 {
        xxh3_64_4to8(input, seed, secret)
    } else if input.len() > 0 {
        xxh3_64_1to3(input, seed, secret)
    } else {
        xxh64_avalanche(seed ^ read_u64(secret, 56) ^ read_u64(secret, 64))
    }
}

const fn xxh3_64_17to128(input: &[u8], seed: u64, secret: &[u8]) -> u64 {
    let mut acc = (input.len() as u64).wrapping_mul(PRIME64_1);
    if input.len() > 32 {
        if input.len() > 64 {
            if input.len() > 96 {
                acc = acc.wrapping_add(mix16_b(input, 48, secret, 96, seed));
                acc = acc.wrapping_add(mix16_b(input, input.len() - 64, secret, 112, seed));
            }
            acc = acc.wrapping_add(mix16_b(input, 32, secret, 64, seed));
            acc = acc.wrapping_add(mix16_b(input, input.len() - 48, secret, 80, seed));
        }
        acc = acc.wrapping_add(mix16_b(input, 16, secret, 32, seed));
        acc = acc.wrapping_add(mix16_b(input, input.len() - 32, secret, 48, seed));
    }
    acc = acc.wrapping_add(mix16_b(input, 0, secret, 0, seed));
    acc = acc.wrapping_add(mix16_b(input, input.len() - 16, secret, 16, seed));
    avalanche(acc)
}

const fn xxh3_64_129to240(input: &[u8], seed: u64, secret: &[u8]) -> u64 {
    const START_OFFSET: usize = 3;
    const LAST_OFFSET: usize = 17;

    let mut acc = (input.len() as u64).wrapping_mul(PRIME64_1);
    let nb_rounds = input.len() / 16;

    let mut idx = 0;
    while idx < 8 {
        acc = acc.wrapping_add(mix16_b(input, 16 * idx, secret, 16 * idx, seed));
        idx += 1;
    }
    acc = avalanche(acc);

    while idx < nb_rounds {
        acc = acc.wrapping_add(mix16_b(
            input,
            16 * idx,
            secret,
            16 * (idx - 8) + START_OFFSET,
            seed,
        ));
        idx += 1;
    }

    acc = acc.wrapping_add(mix16_b(
        input,
        input.len() - 16,
        secret,
        SECRET_SIZE_MIN - LAST_OFFSET,
        seed,
    ));
    avalanche(acc)
}

const fn mix_two_accs(acc: &[u64], acc_offset: usize, secret: &[u8], secret_offset: usize) -> u64 {
    mul128_fold64(
        acc[acc_offset] ^ read_u64(secret, secret_offset),
        acc[acc_offset + 1] ^ read_u64(secret, secret_offset + 8),
    )
}

const fn merge_accs(acc: &[u64], secret: &[u8], secret_offset: usize, mut result: u64) -> u64 {
    let mut idx = 0;
    while idx < 4 {
        result = result.wrapping_add(mix_two_accs(acc, idx * 2, secret, secret_offset + idx * 16));
        idx += 1;
    }
    avalanche(result)
}

const fn scramble_acc(mut acc: [u64; 8], secret: &[u8], secret_offset: usize) -> [u64; 8] {
    let mut idx = 0;
    while idx < 8 {
        let key = read_u64(secret, secret_offset + 8 * idx);
        let mut acc_val = xorshift64(acc[idx], 47);
        acc_val ^= key;
        acc[idx] = acc_val.wrapping_mul(PRIME32_1 as u64);
        idx += 1;
    }
    acc
}

const fn accumulate_512(
    mut acc: [u64; 8],
    input: &[u8],
    input_offset: usize,
    secret: &[u8],
    secret_offset: usize,
) -> [u64; 8] {
    let mut idx = 0;
    while idx < 8 {
        let data_val = read_u64(input, input_offset + 8 * idx);
        let data_key = data_val ^ read_u64(secret, secret_offset + 8 * idx);

        acc[idx ^ 1] = acc[idx ^ 1].wrapping_add(data_val);
        acc[idx] = acc[idx]
            .wrapping_add(mult32_to64((data_key & 0xFFFF_FFFF) as u32, (data_key >> 32) as u32));
        idx += 1;
    }
    acc
}

const fn accumulate_loop(
    mut acc: [u64; 8],
    input: &[u8],
    input_offset: usize,
    secret: &[u8],
    secret_offset: usize,
    nb_stripes: usize,
) -> [u64; 8] {
    let mut idx = 0;
    while idx < nb_stripes {
        acc = accumulate_512(
            acc,
            input,
            input_offset + idx * STRIPE_LEN,
            secret,
            secret_offset + idx * SECRET_CONSUME_RATE,
        );
        idx += 1;
    }
    acc
}

const fn hash_long_internal_loop(input: &[u8], secret: &[u8]) -> [u64; 8] {
    let mut acc = INITIAL_ACC;
    let nb_stripes = (secret.len() - STRIPE_LEN) / SECRET_CONSUME_RATE;
    let block_len = STRIPE_LEN * nb_stripes;
    let nb_blocks = (input.len() - 1) / block_len;

    let mut idx = 0;
    while idx < nb_blocks {
        acc = accumulate_loop(acc, input, idx * block_len, secret, 0, nb_stripes);
        acc = scramble_acc(acc, secret, secret.len() - STRIPE_LEN);
        idx += 1;
    }

    let nb_stripes = ((input.len() - 1) - (block_len * nb_blocks)) / STRIPE_LEN;
    acc = accumulate_loop(acc, input, nb_blocks * block_len, secret, 0, nb_stripes);
    accumulate_512(
        acc,
        input,
        input.len() - STRIPE_LEN,
        secret,
        secret.len() - STRIPE_LEN - SECRET_LASTACC_START,
    )
}

const fn xxh3_64_long(input: &[u8], secret: &[u8]) -> u64 {
    let acc = hash_long_internal_loop(input, secret);
    merge_accs(
        &acc,
        secret,
        SECRET_MERGEACCS_START,
        (input.len() as u64).wrapping_mul(PRIME64_1),
    )
}

pub const fn xxh3_64(input: &[u8]) -> u64 {
    if input.len() <= 16 {
        xxh3_64_0to16(input, 0, &DEFAULT_SECRET)
    } else if input.len() <= 128 {
        xxh3_64_17to128(input, 0, &DEFAULT_SECRET)
    } else if input.len() <= MID_SIZE_MAX {
        xxh3_64_129to240(input, 0, &DEFAULT_SECRET)
    } else {
        xxh3_64_long(input, &DEFAULT_SECRET)
    }
}
