// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::request_handler::verify_secure_key;
use crate::types::Requests;

type GreProtectSpriteContentFn = unsafe extern "system" fn(*mut c_void, usize, i32, u32) -> i32;

static mut GRE_PROTECT_SPRITE_CONTENT: Option<GreProtectSpriteContentFn> = None;

pub fn init_gre_protect_sprite_content() -> u8 {
    unsafe {
        if core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT)
            .read()
            .is_none()
        {
            let module_base =
                crate::helpers::get_module_base(obfstr::obfwide!("win32kfull.sys").as_ptr());
            if module_base.is_null() {
                return 0;
            }

            let image_end = crate::helpers::get_image_end(module_base);

            let found = crate::helpers::pattern_scan(
                module_base as *const u8,
                image_end as *const u8,
                obfstr::obfbytes!(b"E8 ? ? ? ? 8B ? 85 C0 75 0E"),
            );
            if found.is_null() {
                return 0;
            }

            let address = crate::helpers::resolve_relative_address(found, 1);
            if address.is_null() {
                return 0;
            }
            GRE_PROTECT_SPRITE_CONTENT = Some(core::mem::transmute(address));
        }
        1
    }
}

fn zw_protect_window(hwnd: usize, flags: u32) -> bool {
    unsafe {
        if core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT)
            .read()
            .is_none()
        {
            if init_gre_protect_sprite_content() == 0 {
                return false;
            }
        }
        match core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT).read() {
            Some(f) => f(null_mut(), hwnd, 1, flags) != 0,
            None => false,
        }
    }
}

pub fn handle_anti_capture(req: *mut Requests) -> u8 {
    unsafe {
        if req.is_null() {
            return 0;
        }
        if !verify_secure_key((*req).secure_key) {
            return 0;
        }

        let hwnd = (*req).window_handle;
        let flags = (*req).protect_flags;
        zw_protect_window(hwnd, flags) as u8
    }
}
