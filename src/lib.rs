// Copyright (c) 2026 渟雲. All rights reserved.

#![no_std]
#![no_builtins]
#![allow(linker_messages)]

mod anti_capture;
mod consts;
mod dispatches;
mod helpers;
mod imports;
mod keybd;
mod mouse;
mod pmem;
mod process;
mod random;
mod reimpl;
mod reimpl_ke;
mod reimpl_rtl;
mod reimpl_wdm;
mod request_handler;
mod sha256;
mod types;
mod util;

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use obfstr::obfwide;

use crate::consts::*;
use crate::dispatches::*;
use crate::imports::*;
use crate::types::*;
use crate::util::*;

unsafe extern "system" fn driver_unload(driver: *mut DriverObject) {
    unsafe {
        pmem::cleanup_pmem_pages();
        mouse::mouse_release();
        keybd::keyboard_release();
        let g = addr_of_mut!(G_SYMBOLIC_LINK_NAME);
        if !(*g).buffer.is_null() {
            if !_IO_DELETE_SYMBOLIC_LINK.is_null() {
                let f: IoDeleteSymbolicLinkFn = core::mem::transmute(_IO_DELETE_SYMBOLIC_LINK);
                f(addr_of_mut!(G_SYMBOLIC_LINK_NAME));
            }
            zero_memory((*g).buffer as *mut u8, (*g).maximum_length as usize);
            if !_EX_FREE_POOL_WITH_TAG.is_null() {
                let f: ExFreePoolWithTagFn = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
                f((*g).buffer as *mut c_void, SYMLINK_TAG);
            }
            (*g).buffer = core::ptr::null_mut();
            (*g).length = 0;
            (*g).maximum_length = 0;
        }

        if !(*driver).device_object.is_null() {
            if !_IO_DELETE_DEVICE.is_null() {
                let f: IoDeleteDeviceFn = core::mem::transmute(_IO_DELETE_DEVICE);
                f((*driver).device_object);
            }
            (*driver).device_object = core::ptr::null_mut();
        }
    }
}

unsafe extern "system" fn driver_init(
    driver: *mut DriverObject,
    _registry: *mut UnicodeString,
) -> NtStatus {
    unsafe {
        let mut status = pmem::init_pmem_pages();
        if status < 0 {
            return status;
        }

        random::random_engine_init();

        let mut serial = [0i8; 128];
        status = helpers::get_boot_volume_serial(serial.as_mut_ptr(), serial.len() as u32);
        if status < 0 {
            driver_unload(driver);
            return status;
        }
        let serial_len = serial.iter().position(|&c| c == 0).unwrap_or(serial.len());

        let mut obfuscated = [0u16; 32];
        status = helpers::generate_obfuscated_name(
            serial.as_ptr() as *const u8,
            serial_len as u32,
            obfuscated.as_mut_ptr(),
            obfuscated.len() as u32,
        );
        zero_memory(
            serial.as_mut_ptr() as *mut u8,
            core::mem::size_of::<[i8; 128]>(),
        );
        if status != STATUS_SUCCESS {
            driver_unload(driver);
            return status;
        }
        let obf_len = kwcslen(obfuscated.as_ptr());

        let mut device_name = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        let mut random_device_name_buf = [0u16; 64];
        let device_prefix = obfwide!("\\Device\\");
        let mut n = 0;
        for &c in device_prefix.iter() {
            random_device_name_buf[n] = c;
            n += 1;
        }
        let hex_chars = obfstr::obfbytes!(b"0123456789ABCDEF");
        let rand_val = random::random_engine_next();
        for i in 0..16 {
            let nibble = ((rand_val >> (i * 4)) & 0xF) as usize;
            random_device_name_buf[n] = hex_chars[nibble] as u16;
            n += 1;
        }
        random_device_name_buf[n] = 0;
        crate::reimpl_rtl::rtl_init_unicode_string(
            &mut device_name,
            random_device_name_buf.as_ptr(),
        );

        let mut sym_link_buf = [0u16; 256];
        let sym_prefix = obfwide!("\\DosDevices\\Global\\");
        let mut m = 0;
        for &c in sym_prefix.iter() {
            sym_link_buf[m] = c;
            m += 1;
        }
        for i in 0..obf_len {
            sym_link_buf[m + i] = obfuscated[i];
        }
        m += obf_len;
        sym_link_buf[m] = 0;
        zero_memory(
            obfuscated.as_mut_ptr() as *mut u8,
            core::mem::size_of::<[u16; 32]>(),
        );

        let sym_link_bytes = (kwcslen(sym_link_buf.as_ptr()) + 1) * core::mem::size_of::<u16>();
        let sym_link_pool = if _EX_ALLOCATE_POOL2.is_null() {
            core::ptr::null_mut()
        } else {
            let f: ExAllocatePool2Fn = core::mem::transmute(_EX_ALLOCATE_POOL2);
            f(POOL_FLAG_NON_PAGED, sym_link_bytes, SYMLINK_TAG)
        };
        if sym_link_pool.is_null() {
            driver_unload(driver);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::copy_nonoverlapping(
            sym_link_buf.as_ptr(),
            sym_link_pool as *mut u16,
            kwcslen(sym_link_buf.as_ptr()) + 1,
        );
        crate::reimpl_rtl::rtl_init_unicode_string(
            addr_of_mut!(G_SYMBOLIC_LINK_NAME),
            sym_link_pool as *const u16,
        );

        let mut device_object: *mut DeviceObject = core::ptr::null_mut();
        let sddl = obfwide!("D:P(A;;GA;;;WD)");
        let sddl_string = UnicodeString {
            length: (sddl.len() * 2) as u16,
            maximum_length: (sddl.len() * 2) as u16,
            buffer: sddl.as_ptr() as *mut u16,
        };
        status = reimpl_wdm::wdmlib_io_create_device_secure(
            driver,
            0,
            &mut device_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &sddl_string,
            core::ptr::null(),
            &mut device_object,
        );
        if status != STATUS_SUCCESS {
            driver_unload(driver);
            return status;
        }

        status = if _IO_CREATE_SYMBOLIC_LINK.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: IoCreateSymbolicLinkFn = core::mem::transmute(_IO_CREATE_SYMBOLIC_LINK);
            f(
                addr_of_mut!(G_SYMBOLIC_LINK_NAME),
                addr_of_mut!(device_name),
            )
        };
        if status != STATUS_SUCCESS {
            driver_unload(driver);
            return status;
        }

        let _ = anti_capture::init_gre_protect_sprite_content();

        (*device_object).flags |= DO_DIRECT_IO;
        (*device_object).flags &= !DO_BUFFERED_IO;

        (*driver).major_function[IRP_MJ_CREATE] = Some(default_dispatch);
        (*driver).major_function[IRP_MJ_CLOSE] = Some(default_dispatch);
        (*driver).major_function[IRP_MJ_READ] = Some(read_dispatch);
        (*driver).major_function[IRP_MJ_WRITE] = Some(write_dispatch);
        (*driver).driver_unload = Some(driver_unload);

        (*device_object).flags &= !DO_DEVICE_INITIALIZING;
        STATUS_SUCCESS
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn usugumo_entry(_driver: *mut c_void, _registry: *mut c_void) -> NtStatus {
    let status = resolve_imports();
    if status < 0 {
        return status;
    }

    unsafe {
        if _IO_CREATE_DRIVER.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        let create: IoCreateDriverFn = core::mem::transmute(_IO_CREATE_DRIVER);
        create(core::ptr::null_mut(), driver_init)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
