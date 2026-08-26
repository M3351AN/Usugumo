// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::ffi::*;
use crate::imports::{_ExAllocatePool2, _ZwClose, _ZwCreateFile, _ZwQueryVolumeInformationFile};
use crate::sha256::sha256;
use crate::types::{FixedStr64, IoStatusBlock, NtStatus, UnicodeString};

type FnExAllocatePool2 = unsafe extern "system" fn(u64, usize, u32) -> *mut c_void;
type FnZwClose = unsafe extern "system" fn(usize) -> NtStatus;
type FnZwCreateFile = unsafe extern "system" fn(
    *mut usize,
    u32,
    *mut ObjectAttributes,
    *mut IoStatusBlock,
    *mut i64,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
    u32,
) -> NtStatus;
type FnZwQueryVolumeInformationFile =
    unsafe extern "system" fn(usize, *mut IoStatusBlock, *mut c_void, u32, u32) -> NtStatus;

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct FileFsVolumeInformation {
    volume_creation_time: i64,
    volume_serial_number: u32,
    volume_label_length: u32,
    supports_objects: u8,
    volume_label: [u8; 1],
}

const OBJ_KERNEL_HANDLE: u32 = 0x200;
const GENERIC_READ: u32 = 0x8000_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_OPEN: u32 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_FS_VOLUME_INFORMATION: u32 = 1;
const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SECTION_HEADER_SIZE: usize = 40;

pub fn decode_fixed_str64(fs: *const FixedStr64, output: *mut i8, orig_len: u64) {
    unsafe {
        let mut idx = 0usize;
        for block in 0..8 {
            for i in 0..8 {
                if idx as u64 >= orig_len {
                    break;
                }
                let shift = 8 * (7 - i);
                *output.add(idx) = (((*fs).blocks[block] >> shift) & 0xFF) as i8;
                idx += 1;
            }
        }
        *output.add(orig_len as usize) = 0;
    }
}

pub fn convert_to_pwstr(ascii_str: *const i8) -> *mut u16 {
    unsafe {
        let mut len = 0usize;
        while *ascii_str.add(len) != 0 {
            len += 1;
        }

        let w_str = if _ExAllocatePool2.is_null() {
            null_mut()
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_ExAllocatePool2);
            f(POOL_FLAG_NON_PAGED, (len + 1) * 2, 0x7265_6355)
        };
        if w_str.is_null() {
            return null_mut();
        }

        let w = w_str as *mut u16;
        for i in 0..len {
            *w.add(i) = *ascii_str.add(i) as u16;
        }
        *w.add(len) = 0;
        w
    }
}

pub fn search_sign_for_image(
    image_base: *mut c_void,
    pattern: *const u8,
    mask: *const i8,
    pattern_size: u32,
) -> *mut c_void {
    unsafe {
        let nt = RtlImageNtHeaderMeme(image_base) as *const u8;
        if nt.is_null() {
            return null_mut();
        }

        let num_sections = *(nt.add(6) as *const u16) as usize;
        let size_of_optional_header = *(nt.add(20) as *const u16) as usize;
        let mut section = nt.add(24 + size_of_optional_header);

        for _ in 0..num_sections {
            let name = section as *const i8;
            let virtual_size = *(section.add(8) as *const u32);
            let virtual_address = *(section.add(12) as *const u32);
            let characteristics = *(section.add(36) as *const u32);

            if kstricmp(name, b".text\0".as_ptr() as *const i8) == 0
                || (characteristics & IMAGE_SCN_CNT_CODE) != 0
            {
                let start = (image_base as *const u8).add(virtual_address as usize);
                let size = virtual_size as usize;
                if (pattern_size as usize) <= size {
                    for j in 0..=(size - pattern_size as usize) {
                        let mut found = true;
                        for k in 0..pattern_size as usize {
                            if *mask.add(k) == b'x' as i8 && *start.add(j + k) != *pattern.add(k) {
                                found = false;
                                break;
                            }
                        }
                        if found {
                            return start.add(j) as *mut c_void;
                        }
                    }
                }
            }
            section = section.add(IMAGE_SECTION_HEADER_SIZE);
        }

        null_mut()
    }
}

pub fn get_boot_volume_serial(out: *mut i8, out_len: u32) -> NtStatus {
    unsafe {
        if out.is_null() || out_len < 9 {
            return STATUS_INVALID_PARAMETER;
        }
        *out = 0;

        let vol_path_wide = obfstr::obfwide!("\\DosDevices\\C:");
        let mut vol_path = UnicodeString {
            length: (vol_path_wide.len() * 2) as u16,
            maximum_length: (vol_path_wide.len() * 2) as u16,
            buffer: vol_path_wide.as_ptr() as *mut u16,
        };
        let mut oa = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: &mut vol_path,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            security_descriptor: null_mut(),
            security_quality_of_service: null_mut(),
        };

        let mut handle = 0usize;
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut status = if _ZwCreateFile.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: FnZwCreateFile = core::mem::transmute(_ZwCreateFile);
            f(
                &mut handle,
                GENERIC_READ | SYNCHRONIZE,
                &mut oa,
                &mut iosb,
                null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                null_mut(),
                0,
            )
        };
        if status >= 0 {
            status = iosb.status;
        }
        if status < 0 {
            return status;
        }

        let mut vi = FileFsVolumeInformation {
            volume_creation_time: 0,
            volume_serial_number: 0,
            volume_label_length: 0,
            supports_objects: 0,
            volume_label: [0],
        };
        status = if _ZwQueryVolumeInformationFile.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: FnZwQueryVolumeInformationFile =
                core::mem::transmute(_ZwQueryVolumeInformationFile);
            f(
                handle,
                &mut iosb,
                (&mut vi) as *mut FileFsVolumeInformation as *mut c_void,
                core::mem::size_of::<FileFsVolumeInformation>() as u32,
                FILE_FS_VOLUME_INFORMATION,
            )
        };
        if status >= 0 {
            status = iosb.status;
        }
        if !_ZwClose.is_null() {
            let f: FnZwClose = core::mem::transmute(_ZwClose);
            f(handle);
        }
        if status < 0 {
            return status;
        }

        let mut sn = vi.volume_serial_number;
        const HEX: &[u8] = b"0123456789ABCDEF";
        for i in (0..8).rev() {
            *out.add(i) = HEX[(sn & 0xF) as usize] as i8;
            sn >>= 4;
        }
        *out.add(8) = 0;
        STATUS_SUCCESS
    }
}

pub fn generate_obfuscated_name(
    serial: *const u8,
    serial_len: u32,
    out: *mut u16,
    out_len: u32,
) -> NtStatus {
    unsafe {
        if out.is_null() || out_len <= 16 || serial.is_null() || serial_len == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let k_suffix = b"Usugumo";
        let mut input = [0u8; 8 + 7];
        let mut slen = serial_len as usize;
        if slen > 8 {
            slen = 8;
        }
        for i in 0..slen {
            input[i] = *serial.add(i);
        }
        for i in 0..k_suffix.len() {
            input[slen + i] = k_suffix[i];
        }

        let mut digest = [0u8; 32];
        sha256(input.as_ptr(), slen + k_suffix.len(), digest.as_mut_ptr());

        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for i in 0..16 {
            *out.add(i) = CHARS[(digest[i] % 36) as usize] as u16;
        }
        *out.add(16) = 0;
        STATUS_SUCCESS
    }
}
