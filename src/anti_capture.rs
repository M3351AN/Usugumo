// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::ffi::*;
use crate::imports::_PsLoadedModuleList;
use crate::request_handler::verify_secure_key;
use crate::types::Requests;

type GreProtectSpriteContentFn = unsafe extern "system" fn(*mut c_void, usize, i32, u32) -> i32;

static mut GRE_PROTECT_SPRITE_CONTENT: Option<GreProtectSpriteContentFn> = None;

fn get_win32k_base() -> *mut c_void {
    unsafe {
        if _PsLoadedModuleList.is_null() {
            return null_mut();
        }
        let target = obfstr::obfwide!("win32kfull.sys");
        let head = _PsLoadedModuleList as usize;
        let mut entry = *(_PsLoadedModuleList as *const usize);
        while entry != head {
            let module = entry as *mut u8;
            let base_dll_name_buffer = *(module.add(0x60) as *const usize);
            let dll_base = *(module.add(0x30) as *const usize);
            if base_dll_name_buffer != 0
                && kwcsicmp(base_dll_name_buffer as *const u16, target.as_ptr()) == 0
            {
                return dll_base as *mut c_void;
            }
            entry = *(module as *const usize);
        }
        null_mut()
    }
}

pub fn init_gre_protect_sprite_content() -> u8 {
    unsafe {
        if core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT)
            .read()
            .is_none()
        {
            let module_base = get_win32k_base();
            if module_base.is_null() {
                return 0;
            }

            let pattern: [u8; 11] = [
                0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xCC, 0x85, 0xC0, 0x75, 0x0E,
            ];
            let mask: [i8; 11] = [
                b'x' as i8, b'?' as i8, b'?' as i8, b'?' as i8, b'?' as i8, b'x' as i8, b'?' as i8,
                b'x' as i8, b'x' as i8, b'x' as i8, b'x' as i8,
            ];

            let found = crate::helpers::search_sign_for_image(
                module_base,
                pattern.as_ptr(),
                mask.as_ptr(),
                pattern.len() as u32,
            );
            if found.is_null() {
                return 0;
            }

            let address = ResolveRelativeAddress(found, 1);
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
