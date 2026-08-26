// Copyright (c) 2026 渟雲. All rights reserved.

#![no_std]
#![allow(linker_messages)]

mod consts;
mod dispatches;
mod ffi;
mod globals;
mod imports;
mod types;
mod util;
mod xxh3;

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use obfstr::obfwide;

use crate::consts::*;
use crate::dispatches::*;
use crate::ffi::*;
use crate::globals::*;
use crate::imports::*;
use crate::types::*;
use crate::util::*;

#[unsafe(no_mangle)]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

unsafe extern "system" fn driver_unload(driver: *mut DriverObject) {
    unsafe {
        CleanupPmemPages();
        MouseRelease();
        KeyboardRelease();

        let g = addr_of_mut!(G_SYMBOLIC_LINK_NAME);
        if !(*g).buffer.is_null() {
            if !_IoDeleteSymbolicLink.is_null() {
                let f: IoDeleteSymbolicLinkFn = core::mem::transmute(_IoDeleteSymbolicLink);
                f(addr_of_mut!(G_SYMBOLIC_LINK_NAME));
            }
            zero_memory((*g).buffer as *mut u8, (*g).maximum_length as usize);
            if !_ExFreePoolWithTag.is_null() {
                let f: ExFreePoolWithTagFn = core::mem::transmute(_ExFreePoolWithTag);
                f((*g).buffer as *mut c_void, SYMLINK_TAG);
            }
            (*g).buffer = core::ptr::null_mut();
            (*g).length = 0;
            (*g).maximum_length = 0;
        }

        if !(*driver).device_object.is_null() {
            if !_IoDeleteDevice.is_null() {
                let f: IoDeleteDeviceFn = core::mem::transmute(_IoDeleteDevice);
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
        zero_memory(
            serial.as_mut_ptr() as *mut u8,
            core::mem::size_of::<[i8; 128]>(),
        );
        if status != STATUS_SUCCESS {
            driver_unload(driver);
            return status;
        }
        let obf_len = wcslen(&obfuscated);

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
        for i in 0..obf_len {
            random_device_name_buf[n + i] = obfuscated[i];
        }
        n += obf_len;
        random_device_name_buf[n] = 0;
        RtlInitUnicodeStringMeme(&mut device_name, random_device_name_buf.as_ptr());

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

        let sym_link_bytes = (wcslen(&sym_link_buf) + 1) * core::mem::size_of::<u16>();
        let sym_link_pool = if _ExAllocatePool2.is_null() {
            core::ptr::null_mut()
        } else {
            let f: ExAllocatePool2Fn = core::mem::transmute(_ExAllocatePool2);
            f(POOL_FLAG_NON_PAGED, sym_link_bytes, SYMLINK_TAG)
        };
        if sym_link_pool.is_null() {
            driver_unload(driver);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::copy_nonoverlapping(
            sym_link_buf.as_ptr(),
            sym_link_pool as *mut u16,
            wcslen(&sym_link_buf) + 1,
        );
        RtlInitUnicodeStringMeme(
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
        status = WdmlibIoCreateDeviceSecureMeme(
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

        status = if _IoCreateSymbolicLink.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: IoCreateSymbolicLinkFn = core::mem::transmute(_IoCreateSymbolicLink);
            f(
                addr_of_mut!(G_SYMBOLIC_LINK_NAME),
                addr_of_mut!(device_name),
            )
        };
        if status != STATUS_SUCCESS {
            driver_unload(driver);
            return status;
        }

        let _ = InitGreProtectSpriteContent();

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
        if _IoCreateDriver.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        let create: IoCreateDriverFn = core::mem::transmute(_IoCreateDriver);
        create(core::ptr::null_mut(), driver_init)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
