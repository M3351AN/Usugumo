// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::imports::{
    _EX_ALLOCATE_POOL2, _PS_LOADED_MODULE_LIST, _ZW_CLOSE, _ZW_CREATE_FILE,
    _ZW_QUERY_VOLUME_INFORMATION_FILE,
};
use crate::sha256::sha256;
use crate::types::{FixedStr64, IoStatusBlock, NtStatus, Requests, UnicodeString};

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

        let w_str = if _EX_ALLOCATE_POOL2.is_null() {
            null_mut()
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_EX_ALLOCATE_POOL2);
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

fn hex_val(c: u8) -> i32 {
    match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a' + 10) as i32,
        b'A'..=b'F' => (c - b'A' + 10) as i32,
        _ => -1,
    }
}

fn is_pattern_space(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r' || c == b'\n'
}

pub fn pattern_scan(start: *const u8, end: *const u8, pattern: &[u8]) -> *mut c_void {
    if start.is_null() || end.is_null() || start as usize >= end as usize {
        return null_mut();
    }
    let mut bytes = [0u8; 64];
    let mut mask = [0u8; 64];
    let mut n = 0usize;
    let mut i = 0usize;
    let plen = pattern.len();
    while i < plen {
        while i < plen && is_pattern_space(pattern[i]) {
            i += 1;
        }
        if i >= plen {
            break;
        }
        if pattern[i] == b'?' {
            if i + 1 < plen && pattern[i + 1] == b'?' {
                i += 2;
            } else {
                i += 1;
            }
            mask[n] = 0;
            bytes[n] = 0;
            n += 1;
            continue;
        }
        if i + 1 >= plen {
            return null_mut();
        }
        let hi = hex_val(pattern[i]);
        let lo = hex_val(pattern[i + 1]);
        if hi < 0 || lo < 0 {
            return null_mut();
        }
        bytes[n] = ((hi as u8) << 4) | (lo as u8);
        mask[n] = 0xFF;
        n += 1;
        i += 2;
    }
    if n == 0 || n > bytes.len() {
        return null_mut();
    }

    let size = end as usize - start as usize;
    if size < n {
        return null_mut();
    }
    let limit = size - n;
    let mut o = 0usize;
    while o <= limit {
        let mut ok = true;
        for k in 0..n {
            if mask[k] != 0 && read_u8(start, o + k) != bytes[k] {
                ok = false;
                break;
            }
        }
        if ok {
            return (start as usize + o) as *mut c_void;
        }
        o += 1;
    }
    null_mut()
}

pub fn get_module_base(module_name: *const u16) -> *mut c_void {
    unsafe {
        if _PS_LOADED_MODULE_LIST.is_null() || module_name.is_null() {
            return null_mut();
        }
        let head = _PS_LOADED_MODULE_LIST as usize;
        let mut entry = read_u64(_PS_LOADED_MODULE_LIST as *const u8, 0) as usize;
        while entry != head {
            let module = entry as *mut u8;
            let base_dll_name_buffer = read_u64(module, 0x60) as usize;
            let dll_base = read_u64(module, 0x30) as usize;
            if base_dll_name_buffer != 0
                && crate::util::kwcsicmp(base_dll_name_buffer as *const u16, module_name) == 0
            {
                return dll_base as *mut c_void;
            }
            entry = read_u64(module, 0) as usize;
        }
        null_mut()
    }
}

pub fn get_image_end(image_base: *mut c_void) -> *mut c_void {
    unsafe {
        let nt = crate::reimpl_rtl::rtl_image_nt_header(image_base) as *const u8;
        if nt.is_null() {
            return null_mut();
        }
        let size_of_image = read_u32(nt, 0x18 + 0x38) as usize;
        (image_base as *const u8).add(size_of_image) as *mut c_void
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
        let mut status = if _ZW_CREATE_FILE.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: FnZwCreateFile = core::mem::transmute(_ZW_CREATE_FILE);
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
        status = if _ZW_QUERY_VOLUME_INFORMATION_FILE.is_null() {
            STATUS_UNSUCCESSFUL
        } else {
            let f: FnZwQueryVolumeInformationFile =
                core::mem::transmute(_ZW_QUERY_VOLUME_INFORMATION_FILE);
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
        if !_ZW_CLOSE.is_null() {
            let f: FnZwClose = core::mem::transmute(_ZW_CLOSE);
            f(handle);
        }
        if status < 0 {
            return status;
        }

        let mut sn = vi.volume_serial_number;
        let hex = obfstr::obfbytes!(b"0123456789ABCDEF");
        for i in (0..8).rev() {
            write_u8(out as *mut u8, i, hex[(sn & 0xF) as usize]);
            sn >>= 4;
        }
        write_u8(out as *mut u8, 8, 0);
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

        let k_suffix = obfstr::obfbytes!(b"Usugumo");
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

        let chars = obfstr::obfbytes!(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        for i in 0..16 {
            write_u16(
                out as *mut u8,
                i * 2,
                chars[(digest[i] % 36) as usize] as u16,
            );
        }
        write_u16(out as *mut u8, 32, 0);
        STATUS_SUCCESS
    }
}

static mut CRC64_INITIALIZED: bool = false;
static mut CRC64_TABLE: [u64; 256] = [0; 256];

fn init_crc64_table() {
    unsafe {
        if CRC64_INITIALIZED {
            return;
        }
        let mut rcx = 0usize;
        while rcx < 256 {
            let mut rax = rcx as u64;
            let mut i = 0;
            while i < 8 {
                if rax & 1 != 0 {
                    rax ^= 0x85E1C3D753D46D27;
                }
                rax >>= 1;
                i += 1;
            }
            CRC64_TABLE[rcx] = rax;
            rcx += 1;
        }
        CRC64_INITIALIZED = true;
    }
}

pub fn calculate_requests_checksum(req: *mut Requests) -> u64 {
    unsafe {
        if req.is_null() {
            return 0;
        }
        init_crc64_table();
        let bytes = core::slice::from_raw_parts(req as *const u8, 0xB8);
        let mut rax = 0xFFFFFFFFFFFFFFFFu64;
        for &b in bytes.iter() {
            rax ^= b as u64;
            let idx = (rax & 0xFF) as usize;
            rax >>= 8;
            rax ^= CRC64_TABLE[idx];
        }
        !rax
    }
}

pub fn resolve_relative_address(base: *mut c_void, offset: u32) -> *mut u8 {
    if base.is_null() {
        return null_mut();
    }
    unsafe {
        let b = base as *const u8;
        let disp = crate::helpers::read_u32(b, offset as usize) as i32 as i64;
        b.add(offset as usize + 4).offset(disp as isize) as *mut u8
    }
}

pub fn read_u8(p: *const u8, off: usize) -> u8 {
    unsafe { *p.add(off) }
}

pub fn read_u16(p: *const u8, off: usize) -> u16 {
    unsafe { (p.add(off) as *const u16).read_unaligned() }
}

pub fn read_u32(p: *const u8, off: usize) -> u32 {
    unsafe { (p.add(off) as *const u32).read_unaligned() }
}

pub fn read_u64(p: *const u8, off: usize) -> u64 {
    unsafe { (p.add(off) as *const u64).read_unaligned() }
}

pub fn write_u8(p: *mut u8, off: usize, v: u8) {
    unsafe { *p.add(off) = v }
}

pub fn write_u16(p: *mut u8, off: usize, v: u16) {
    unsafe { (p.add(off) as *mut u16).write_unaligned(v) }
}

pub fn write_u64(p: *mut u8, off: usize, v: u64) {
    unsafe { (p.add(off) as *mut u64).write_unaligned(v) }
}
