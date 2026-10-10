// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::imports::{
    _KE_STACK_ATTACH_PROCESS, _KE_UNSTACK_DETACH_PROCESS, _OBF_DEREFERENCE_OBJECT,
    _PS_LOOKUP_PROCESS_BY_PROCESS_ID,
};
use crate::request_handler::verify_secure_key;
use crate::types::Requests;

type GreProtectSpriteContentFn = unsafe extern "system" fn(usize, usize, i32, u32) -> i64;
type FnPsLookupProcessByProcessId = unsafe extern "system" fn(usize, *mut *mut c_void) -> i32;
type FnObfDereferenceObject = unsafe extern "system" fn(*mut c_void) -> i64;
type FnKeStackAttachProcess = unsafe extern "system" fn(*mut c_void, *mut c_void);
type FnKeUnstackDetachProcess = unsafe extern "system" fn(usize);

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

            let found = crate::helpers::pattern_scan_image(
                module_base,
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

fn call_gre(hwnd: usize, flags: u32) -> i64 {
    unsafe {
        match core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT).read() {
            Some(f) => f(0, hwnd, 1, flags),
            None => 0,
        }
    }
}

fn zw_protect_window(hwnd: usize, flags: u32, request_pid: u64) -> bool {
    unsafe {
        if request_pid != 0
            && !_PS_LOOKUP_PROCESS_BY_PROCESS_ID.is_null()
            && !_OBF_DEREFERENCE_OBJECT.is_null()
        {
            let stack_fn = _KE_STACK_ATTACH_PROCESS;
            let unstack_fn = _KE_UNSTACK_DETACH_PROCESS;
            if !stack_fn.is_null() && !unstack_fn.is_null() {
                let mut proc: *mut c_void = null_mut();
                let f_lookup: FnPsLookupProcessByProcessId =
                    core::mem::transmute(_PS_LOOKUP_PROCESS_BY_PROCESS_ID);
                if f_lookup(request_pid as usize, &mut proc) >= 0 && !proc.is_null() {
                    let f_stack: FnKeStackAttachProcess = core::mem::transmute(stack_fn);
                    let mut apc_state = [0u8; 0x40];
                    f_stack(proc, apc_state.as_mut_ptr() as *mut c_void);
                    if core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT)
                        .read()
                        .is_none()
                    {
                        let _ = init_gre_protect_sprite_content();
                    }
                    let r = call_gre(hwnd, flags);
                    let f_unstack: FnKeUnstackDetachProcess = core::mem::transmute(unstack_fn);
                    f_unstack(apc_state.as_mut_ptr() as usize);
                    let f_deref: FnObfDereferenceObject =
                        core::mem::transmute(_OBF_DEREFERENCE_OBJECT);
                    f_deref(proc);
                    return r != 0;
                }
            }
        }
        if core::ptr::addr_of!(GRE_PROTECT_SPRITE_CONTENT)
            .read()
            .is_none()
        {
            if init_gre_protect_sprite_content() == 0 {
                return false;
            }
        }
        call_gre(hwnd, flags) != 0
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
        let pid = (*req).request_pid;
        zw_protect_window(hwnd, flags, pid) as u8
    }
}
