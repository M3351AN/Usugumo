// Copyright (c) 2026 渟雲. All rights reserved.
#include "random.h"
#include <intrin.h>

static ULONGLONG s_state[4];

static __forceinline ULONGLONG Rotl64(ULONGLONG x, int k) {
  return (x << k) | (x >> (64 - k));
}

static __forceinline ULONGLONG SplitMix64(ULONGLONG* x) {
  ULONGLONG z = (*x += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

static __forceinline ULONGLONG Xoshiro256StarStar(void) {
  ULONGLONG* s = s_state;
  ULONGLONG result = Rotl64(s[1] * 5, 7) * 9;
  ULONGLONG t = s[1] << 17;

  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = Rotl64(s[3], 45);

  return result;
}

static __forceinline ULONGLONG ReadInterruptTimeRaw(void) {
  volatile KSYSTEM_TIME* t = &SharedUserData->InterruptTime;
  ULONG lo = t->LowPart;
  LONG hi1 = t->High1Time;
  LONG hi2 = t->High2Time;
  if (hi1 != hi2) {
    hi1 = t->High1Time;
  }
  return (((ULONGLONG)(ULONG)hi1) << 32) | lo;
}

// Entropy from：
// __rdtsc()
// SharedUserData
// STACK
VOID RandomEngineInit(VOID) {
  ULONGLONG entropy[4];

  entropy[0] = __rdtsc();
  entropy[1] = ReadInterruptTimeRaw();
  entropy[2] = (ULONGLONG)(ULONG_PTR)&entropy;
  entropy[3] = __rdtsc();
  ULONGLONG mix = 0x243F6A8885A308D3ULL;
  for (int i = 0; i < 4; i++) {
    mix ^= entropy[i];
    s_state[i] = SplitMix64(&mix);
  }

  if ((s_state[0] | s_state[1] | s_state[2] | s_state[3]) == 0) {
    s_state[0] = 0x9E3779B97F4A7C15ULL;
    s_state[1] = 0xD1B54A32D192ED03ULL;
    s_state[2] = 0x85E1C3D753D46D27ULL;
    s_state[3] = 0x94D049BB133111EBULL;
  }
}

ULONGLONG RandomEngineNext(VOID) { return Xoshiro256StarStar(); }
