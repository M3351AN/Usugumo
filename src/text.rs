// Copyright (c) 2026 渟雲. All rights reserved.

pub use crate::xxh32::key_of;

pub fn find_by_tag<'a>(text: &'a [u8], tag: &[u8; 8]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i < text.len() {
        let end = text[i..]
            .iter()
            .position(|&c| c == b'\n')
            .map(|p| i + p)
            .unwrap_or(text.len());
        let len = if end > i && text[end - 1] == b'\r' {
            end - 1 - i
        } else {
            end - i
        };
        if len > 8 {
            let line = &text[i..i + len];
            if &line[..8] == tag && line[8] == b'=' {
                return Some(&line[9..]);
            }
        }
        i = if end < text.len() {
            end + 1
        } else {
            text.len()
        };
    }
    None
}

pub fn find_u64_by_tag(text: &[u8], tag: &[u8; 8]) -> Option<u64> {
    let value = find_by_tag(text, tag)?;
    if value.is_empty() {
        return None;
    }
    let mut n = 0u64;
    for &c in value {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
    failed: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        let failed = buf.is_empty();
        Self {
            buf,
            len: 0,
            failed,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        if self.len + bytes.len() > self.buf.len() {
            self.failed = true;
            return;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn raw_u64(&mut self, v: u64) {
        let mut tmp = [0u8; 20];
        let mut n = 0usize;
        let mut x = v;
        if x == 0 {
            self.put(b"0");
            return;
        }
        while x > 0 {
            tmp[n] = b'0' + (x % 10) as u8;
            x /= 10;
            n += 1;
        }
        let mut out = [0u8; 20];
        for k in 0..n {
            out[k] = tmp[n - 1 - k];
        }
        self.put(&out[..n]);
    }

    pub fn u64(&mut self, tag: &[u8; 8], v: u64) {
        self.put(tag);
        self.put(b"=");
        self.raw_u64(v);
        self.put(b"\n");
    }

    pub fn bytes(&mut self, tag: &[u8; 8], v: &[u8]) {
        self.put(tag);
        self.put(b"=");
        for &c in v {
            if c >= 0x20 && c != 0x7F && c != b'\n' && c != b'\r' {
                self.put(&[c]);
            }
        }
        self.put(b"\n");
    }

    pub fn finish(self) -> Option<usize> {
        if self.failed { None } else { Some(self.len) }
    }
}
