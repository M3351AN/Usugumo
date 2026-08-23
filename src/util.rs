pub fn wcslen(s: &[u16]) -> usize {
    let mut n = 0;
    while n < s.len() && s[n] != 0 {
        n += 1;
    }
    n
}

pub fn zero_memory(ptr: *mut u8, len: usize) {
    unsafe { core::ptr::write_bytes(ptr, 0, len) };
}
