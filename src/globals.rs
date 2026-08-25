use crate::types::unicode_string;

pub static mut g_symbolic_link_name: unicode_string = unicode_string {
    length: 0,
    maximum_length: 0,
    buffer: core::ptr::null_mut(),
};
