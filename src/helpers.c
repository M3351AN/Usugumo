// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

static const ULONG kSha256K[64] = {
    0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL, 0x3956C25BUL,
    0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL, 0xD807AA98UL, 0x12835B01UL,
    0x243185BEUL, 0x550C7DC3UL, 0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL,
    0xC19BF174UL, 0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
    0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL, 0x983E5152UL,
    0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL, 0xC6E00BF3UL, 0xD5A79147UL,
    0x06CA6351UL, 0x14292967UL, 0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL,
    0x53380D13UL, 0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
    0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL, 0xD192E819UL,
    0xD6990624UL, 0xF40E3585UL, 0x106AA070UL, 0x19A4C116UL, 0x1E376C08UL,
    0x2748774CUL, 0x34B0BCB5UL, 0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL,
    0x682E6FF3UL, 0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
    0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL};

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
  ULONG state[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
                    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL};

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

VOID DecodeFixedStr64(const FixedStr64* fs, char* output, SIZE_T origLen) {
  size_t idx = 0;
  for (size_t block = 0; block < 8; block++) {
    for (int i = 0; i < 8; i++) {
      if (idx >= origLen) {
        break;
      }
      int shift = 8 * (7 - i);
      output[idx++] = (char)((fs->blocks[block] >> shift) & 0xFF);
    }
  }
  output[origLen] = '\0';
}

PWSTR ConvertToPWSTR(const char* ascii_str) {
  SIZE_T len = 0;

  while (ascii_str[len] != '\0') {
    len++;
  }

  wchar_t* w_str = (wchar_t*)_ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                             (len + 1) * sizeof(WCHAR), 'NtFs');
  if (!w_str) {
    return NULL;
  }

  for (SIZE_T i = 0; i < len; i++) {
    w_str[i] = (WCHAR)ascii_str[i];
  }
  w_str[len] = L'\0';

  return w_str;
}

PVOID SearchSignForImage(PVOID ImageBase, PUCHAR Pattern, PCHAR Mask,
                                ULONG PatternSize) {
  PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeaderMeme(ImageBase);
  if (!NtHeaders) return NULL;

  PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
  for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections;
       i++, Section++) {
    if (kstricmp((PCHAR)Section->Name, ".text") == 0 ||
        (Section->Characteristics & IMAGE_SCN_CNT_CODE)) {
      PUCHAR Start = (PUCHAR)ImageBase + Section->VirtualAddress;
      ULONG Size = Section->Misc.VirtualSize;

      for (ULONG j = 0; j <= Size - PatternSize; j++) {
        BOOLEAN Found = TRUE;

        for (ULONG k = 0; k < PatternSize; k++) {
          if (Mask[k] == 'x' && Start[j + k] != Pattern[k]) {
            Found = FALSE;
            break;
          }
        }

        if (Found) return Start + j;
      }
    }
  }

  return NULL;
}

NTSTATUS ZwReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes,
                                 PACCESS_STATE PassedAccessState,
                                 ACCESS_MASK DesiredAccess,
                                 POBJECT_TYPE ObjectType,
                                 KPROCESSOR_MODE AccessMode,
                                 LPVOID ParseContext, PDRIVER_OBJECT* Object) {
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  if (_ObReferenceObjectByName != NULL) {
    Status = _ObReferenceObjectByName(ObjectName, Attributes, PassedAccessState,
                                      DesiredAccess, ObjectType, AccessMode,
                                      ParseContext, Object);
  }

  return Status;
}

NTSTATUS GetMachineGuid(WCHAR* guid_buf, size_t buf_len) {
  if (!guid_buf || buf_len < 64) {
    return STATUS_INVALID_PARAMETER;
  }

  UNICODE_STRING key_path = RTL_CONSTANT_STRING(
      L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
  UNICODE_STRING value_name = RTL_CONSTANT_STRING(L"MachineGuid");
  HANDLE hKey = NULL;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG data_len = 0;
  PKEY_VALUE_PARTIAL_INFORMATION pInfo = NULL;

  OBJECT_ATTRIBUTES obj_attr;
  InitializeObjectAttributes(
      &obj_attr,
      &key_path,
      OBJ_CASE_INSENSITIVE,
      NULL,
      NULL
  );

  status = ZwOpenKey(&hKey, KEY_READ, &obj_attr);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = ZwQueryValueKey(hKey, &value_name, KeyValuePartialInformation, NULL,
                           0, &data_len);
  if (status != STATUS_BUFFER_TOO_SMALL) {
    ZwClose(hKey);
    return status;
  }

  pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)_ExAllocatePool2(POOL_FLAG_PAGED,
                                                          data_len, 'File');
  if (!pInfo) {
    ZwClose(hKey);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = ZwQueryValueKey(hKey, &value_name, KeyValuePartialInformation, pInfo,
                           data_len, &data_len);
  if (NT_SUCCESS(status)) {
    size_t copy_len = min((size_t)data_len, buf_len - 1);
    kmemmove(guid_buf, pInfo->Data, copy_len * sizeof(WCHAR));
    guid_buf[copy_len] = L'\0';
  }

  if (pInfo) _ExFreePoolWithTag(pInfo, 0);
  ZwClose(hKey);
  return status;
}
