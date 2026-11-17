// Copyright (c) 2026 渟雲. All rights reserved.

#![no_std]
#![no_builtins]
#![allow(linker_messages)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

struct KernelPoolAllocator;

unsafe impl GlobalAlloc for KernelPoolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            if layout.size() == 0 {
                return core::ptr::NonNull::<u8>::dangling().as_ptr();
            }
            if _EX_ALLOCATE_POOL2.is_null() {
                return core::ptr::null_mut();
            }
            let f: ExAllocatePool2Fn = core::mem::transmute(_EX_ALLOCATE_POOL2);
            f(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                layout.size(),
                1953657665,
            ) as *mut u8
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            if ptr.is_null() || _EX_FREE_POOL_WITH_TAG.is_null() {
                return;
            }
            let f: ExFreePoolWithTagFn = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
            f(ptr as *mut c_void, 1953657665);
        }
    }
}

#[global_allocator]
static GLOBAL_POOL_ALLOCATOR: KernelPoolAllocator = KernelPoolAllocator;

mod anti_capture;
mod consts;
mod helpers;
mod imports;
mod keybd;
mod mouse;
mod pmem;
mod process;
mod protocol;
mod reimpl;
mod reimpl_ke;
mod reimpl_rtl;
mod request_handler;
mod request_layout;
mod sha256;
mod text;
mod types;
mod util;
mod wsk;
mod xxh32;

use core::ffi::c_void;

use crate::consts::*;
use crate::imports::*;
use crate::types::*;

static mut G_DRIVER_STATUS: NtStatus = STATUS_UNSUCCESSFUL;
pub static mut G_SERVER_RUNNING: bool = false;

#[inline(never)]
unsafe fn driver_teardown() {
    unsafe {
        wsk::stop_server();
        pmem::cleanup_pmem_pages();
        mouse::mouse_release();
        keybd::keyboard_release();
        G_SERVER_RUNNING = false;
    }
}

#[inline(never)]
unsafe fn driver_init() -> NtStatus {
    unsafe {
        pmem::init_pmem_pages();

        let status = wsk::start_server();
        if status < 0 {
            driver_teardown();
            return status;
        }

        G_SERVER_RUNNING = true;
        STATUS_SUCCESS
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "system" fn usugumo_entry(_driver: *mut c_void, _registry: *mut c_void) -> NtStatus {
    let status = resolve_imports();
    if status < 0 {
        unsafe {
            G_DRIVER_STATUS = status;
        }
        return status;
    }

    let result = unsafe { driver_init() };
    unsafe {
        G_DRIVER_STATUS = result;
    }
    result
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
