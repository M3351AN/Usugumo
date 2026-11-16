// Copyright (c) 2026 渟雲. All rights reserved.

pub(crate) struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
}

impl Pattern {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for token in text.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(0u8);
                mask.push(0u8);
            } else {
                let value = u8::from_str_radix(token, 16).ok()?;
                bytes.push(value);
                mask.push(0xFF);
            }
        }
        if bytes.is_empty() || bytes.len() > 256 {
            return None;
        }
        Some(Self { bytes, mask })
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn matches_at(&self, data: &[u8]) -> bool {
        data.len() >= self.bytes.len()
            && self
                .bytes
                .iter()
                .zip(self.mask.iter())
                .zip(data.iter())
                .all(|((&p, &m), &d)| m == 0 || p == d)
    }
}

pub(crate) const CHUNK_SIZE: usize = 4096;

pub(crate) fn find_in_chunk(haystack: &[u8], pattern: &Pattern) -> Option<usize> {
    let plen = pattern.len();
    if haystack.len() < plen {
        return None;
    }
    let limit = haystack.len() - plen;
    for i in 0..=limit {
        if pattern.matches_at(&haystack[i..]) {
            return Some(i);
        }
    }
    None
}
