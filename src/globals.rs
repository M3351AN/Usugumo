use crate::types::unicode_string;

pub static sddl_bytes: [u16; 16] = [
    0x44, 0x3A, 0x50, 0x28, 0x41, 0x3B, 0x3B, 0x47,
    0x41, 0x3B, 0x3B, 0x3B, 0x57, 0x44, 0x29, 0x00,
];
pub static sddl_string: unicode_string = unicode_string {
    length: 30,
    maximum_length: 32,
    buffer: sddl_bytes.as_ptr() as *mut u16,
};

pub static mut g_symbolic_link_name: unicode_string = unicode_string {
    length: 0,
    maximum_length: 0,
    buffer: core::ptr::null_mut(),
};
