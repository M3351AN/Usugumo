#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod consts;
mod ffi;
mod globals;
mod imports;
mod types;
mod util;
mod xxh3;

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use crate::consts::*;
use crate::ffi::*;
use crate::globals::*;
use crate::imports::*;
use crate::types::*;
use crate::util::*;

#[unsafe(no_mangle)]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

unsafe extern "system" fn driver_unload(driver: *mut driver_object) {
    unsafe {
        CleanupPmemPages();
        MouseRelease();
        KeyboardRelease();

        let g = addr_of_mut!(g_symbolic_link_name);
        if !(*g).buffer.is_null() {
            if !_IoDeleteSymbolicLink.is_null() {
                let f: fn_io_delete_symbolic_link = core::mem::transmute(_IoDeleteSymbolicLink);
                f(addr_of_mut!(g_symbolic_link_name));
            }
            zero_memory((*g).buffer as *mut u8, (*g).maximum_length as usize);
            if !_ExFreePoolWithTag.is_null() {
                let f: fn_ex_free_pool_with_tag = core::mem::transmute(_ExFreePoolWithTag);
                f((*g).buffer as *mut c_void, symlink_tag);
            }
            (*g).buffer = core::ptr::null_mut();
            (*g).length = 0;
            (*g).maximum_length = 0;
        }

        if !(*driver).device_object.is_null() {
            if !_IoDeleteDevice.is_null() {
                let f: fn_io_delete_device = core::mem::transmute(_IoDeleteDevice);
                f((*driver).device_object);
            }
            (*driver).device_object = core::ptr::null_mut();
        }
    }
}

unsafe extern "system" fn driver_init(
    driver: *mut driver_object,
    _registry: *mut unicode_string,
) -> nt_status {
    unsafe {
        let mut status = InitPmemPages();
        if status < 0 {
            return status;
        }

        RandomEngineInit();

        let mut serial = [0i8; 128];
        status = GetBootVolumeSerial(serial.as_mut_ptr(), serial.len() as u32);
        if status < 0 {
            driver_unload(driver);
            return status;
        }

        let serial_len = serial.iter().position(|&c| c == 0).unwrap_or(serial.len());

        let mut obfuscated = [0u16; 32];
        status = GenerateObfuscatedName(
            serial.as_ptr() as *const u8,
            serial_len as u32,
            obfuscated.as_mut_ptr(),
            obfuscated.len() as u32,
        );
        zero_memory(serial.as_mut_ptr() as *mut u8, core::mem::size_of::<[i8; 128]>());
        if status != status_success {
            driver_unload(driver);
            return status;
        }
        let obf_len = wcslen(&obfuscated);

        let mut device_name = unicode_string {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        let mut random_device_name_buf = [0u16; 64];
        let mut n = 0;
        for &c in device_prefix.iter() {
            random_device_name_buf[n] = c;
            n += 1;
        }
        for i in 0..obf_len {
            random_device_name_buf[n + i] = obfuscated[i];
        }
        n += obf_len;
        random_device_name_buf[n] = 0;
        RtlInitUnicodeStringMeme(&mut device_name, random_device_name_buf.as_ptr());

        let mut sym_link_buf = [0u16; 256];
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
        zero_memory(obfuscated.as_mut_ptr() as *mut u8, core::mem::size_of::<[u16; 32]>());

        let sym_link_bytes = (wcslen(&sym_link_buf) + 1) * core::mem::size_of::<u16>();
        let sym_link_pool = if _ExAllocatePool2.is_null() {
            core::ptr::null_mut()
        } else {
            let f: fn_ex_allocate_pool2 = core::mem::transmute(_ExAllocatePool2);
            f(pool_flag_non_paged, sym_link_bytes, symlink_tag)
        };
        if sym_link_pool.is_null() {
            driver_unload(driver);
            return status_insufficient_resources;
        }
        core::ptr::copy_nonoverlapping(
            sym_link_buf.as_ptr(),
            sym_link_pool as *mut u16,
            wcslen(&sym_link_buf) + 1,
        );
        RtlInitUnicodeStringMeme(
            addr_of_mut!(g_symbolic_link_name),
            sym_link_pool as *const u16,
        );

        let mut device_object: *mut device_object = core::ptr::null_mut();
        status = WdmlibIoCreateDeviceSecureMeme(
            driver,
            0,
            &mut device_name,
            file_device_unknown,
            file_device_secure_open,
            0,
            &sddl_string,
            core::ptr::null(),
            &mut device_object,
        );
        if status != status_success {
            driver_unload(driver);
            return status;
        }

        status = if _IoCreateSymbolicLink.is_null() {
            status_unsuccessful
        } else {
            let f: fn_io_create_symbolic_link = core::mem::transmute(_IoCreateSymbolicLink);
            f(addr_of_mut!(g_symbolic_link_name), addr_of_mut!(device_name))
        };
        if status != status_success {
            driver_unload(driver);
            return status;
        }

        let _ = InitGreProtectSpriteContent();

        (*device_object).flags |= do_direct_io;
        (*device_object).flags &= !do_buffered_io;

        (*driver).major_function[irp_mj_create] = Some(DefaultDispatch);
        (*driver).major_function[irp_mj_close] = Some(DefaultDispatch);
        (*driver).major_function[irp_mj_read] = Some(ReadDispatch);
        (*driver).major_function[irp_mj_write] = Some(WriteDispatch);
        (*driver).driver_unload = Some(driver_unload);

        (*device_object).flags &= !do_device_initializing;
        status_success
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn UsugumoEntry(_driver: *mut c_void, _registry: *mut c_void) -> nt_status {
    let status = resolve_imports();
    if status < 0 {
        return status;
    }

    unsafe {
        if _IoCreateDriver.is_null() {
            return status_unsuccessful;
        }
        let create: io_create_driver_fn = core::mem::transmute(_IoCreateDriver);
        create(core::ptr::null_mut(), driver_init)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
