// Copyright (c) 2026 渟雲. All rights reserved.
#include "sha256.h"

static const ULONG kSha256K[64] = {
    0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL,
    0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
    0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL,
    0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
    0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
    0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
    0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL,
    0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
    0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL,
    0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
    0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL,
    0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
    0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL,
    0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
    0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
    0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static __forceinline ULONG Sha256LoadBe(const UCHAR* p) {
  return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) |
         (ULONG)p[3];
}

static VOID Sha256Compress(const UCHAR block[64], ULONG state[8]) {
  ULONG w[64];
  ULONG a, b, c, d, e, f, g, h;
  ULONG t1, t2;

  for (int i = 0; i < 16; i++) {
    w[i] = Sha256LoadBe(block + i * 4);
  }
  for (int i = 16; i < 64; i++) {
    ULONG s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    ULONG s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  for (int i = 0; i < 64; i++) {
    ULONG S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
    ULONG ch = (e & f) ^ (~e & g);
    t1 = h + S1 + ch + kSha256K[i] + w[i];
    ULONG S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
    ULONG maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

VOID Sha256(const void* data, SIZE_T length, UCHAR digest[SHA256_DIGEST_SIZE]) {
  ULONG state[8] = {
      0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
      0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
  };

  const UCHAR* p = (const UCHAR*)data;
  SIZE_T full = length / 64;
  SIZE_T rem = length % 64;

  for (SIZE_T i = 0; i < full; i++) {
    Sha256Compress(p, state);
    p += 64;
  }

  UCHAR last[64];
  ULONG rem_idx = 0;
  for (; rem_idx < rem; rem_idx++) {
    last[rem_idx] = p[rem_idx];
  }
  last[rem_idx++] = 0x80;

  ULONGLONG bit_len = (ULONGLONG)length * 8;
  if (rem_idx > 56) {
    for (; rem_idx < 64; rem_idx++) {
      last[rem_idx] = 0;
    }
    Sha256Compress(last, state);
    for (rem_idx = 0; rem_idx < 56; rem_idx++) {
      last[rem_idx] = 0;
    }
  } else {
    for (; rem_idx < 56; rem_idx++) {
      last[rem_idx] = 0;
    }
  }
  for (int i = 0; i < 8; i++) {
    last[56 + i] = (UCHAR)(bit_len >> (56 - i * 8));
  }
  Sha256Compress(last, state);

  for (int i = 0; i < 8; i++) {
    digest[i * 4 + 0] = (UCHAR)(state[i] >> 24);
    digest[i * 4 + 1] = (UCHAR)(state[i] >> 16);
    digest[i * 4 + 2] = (UCHAR)(state[i] >> 8);
    digest[i * 4 + 3] = (UCHAR)(state[i]);
  }
}
