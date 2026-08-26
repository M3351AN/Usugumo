// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

use crate::consts::{STATUS_NOT_FOUND, STATUS_SUCCESS};
use crate::sha256::sha256_const;
use crate::types::{DeviceObject, NtStatus, UnicodeString};

pub type IoCreateSymbolicLinkFn =
    unsafe extern "system" fn(*mut UnicodeString, *mut UnicodeString) -> NtStatus;
pub type IoDeleteSymbolicLinkFn = unsafe extern "system" fn(*mut UnicodeString) -> NtStatus;
pub type ExAllocatePool2Fn = unsafe extern "system" fn(u64, usize, u32) -> *mut c_void;
pub type ExFreePoolWithTagFn = unsafe extern "system" fn(*mut c_void, u32);
pub type IoDeleteDeviceFn = unsafe extern "system" fn(*mut DeviceObject) -> NtStatus;

#[unsafe(no_mangle)]
pub static mut _KeAcquireSpinLockAtDpcLevel: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _KeReleaseSpinLockFromDpcLevel: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IofCompleteRequest: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IoReleaseRemoveLockEx: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IoCreateDriver: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ObReferenceObjectByName: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ObfReferenceObject: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ObfDereferenceObject: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _MmMapLockedPagesSpecifyCache: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _MmIsAddressValid: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _MmAllocateContiguousMemory: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _MmFreeContiguousMemory: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _PsLookupProcessByProcessId: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IoCreateSymbolicLink: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IoDeleteDevice: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _IoDeleteSymbolicLink: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ExAllocatePool2: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ExFreePoolWithTag: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ZwClose: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ZwCreateFile: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ZwDeviceIoControlFile: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _ZwQueryVolumeInformationFile: *mut c_void = null_mut();

#[unsafe(no_mangle)]
pub static mut _IoDriverObjectType: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _PsLoadedModuleList: *mut c_void = null_mut();
#[unsafe(no_mangle)]
pub static mut _NtBuildNumber: u16 = 0;

static mut G_NTOSKRNL_BASE: *mut c_void = null_mut();
static mut G_NTOSKRNL_RESOLVED: bool = false;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry64 {
    offset_low: u16,
    selector: u16,
    ist_index: u8,
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

fn hash_cstring(ptr: *const u8) -> [u8; 32] {
    let mut buf = [0u8; 128];
    let mut len = 0;
    while len < buf.len() && unsafe { *ptr.add(len) } != 0 {
        buf[len] = unsafe { *ptr.add(len) };
        len += 1;
    }
    if unsafe { *ptr.add(len) } != 0 {
        return [0u8; 32];
    }
    sha256_const(&buf[..len])
}

unsafe fn read_gs_qword(offset: usize) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, qword ptr gs:[rcx]",
            in("rcx") offset,
            out("rax") out,
            options(nostack),
        );
    }
    out
}

unsafe fn search_bytes(start: u64, max_len: u64, pat: &[u8], wildcard: u8, dir: i32) -> u64 {
    for i in 0..max_len {
        let addr = if dir > 0 {
            start.wrapping_add(i)
        } else {
            start.wrapping_sub(i)
        };
        let mut matched = true;
        for (j, &pb) in pat.iter().enumerate() {
            let p = if dir > 0 {
                addr.wrapping_add(j as u64)
            } else {
                addr.wrapping_sub(j as u64)
            };
            if pb != wildcard && unsafe { *(p as *const u8) } != pb {
                matched = false;
                break;
            }
        }
        if matched {
            return addr;
        }
    }
    0
}

unsafe fn search_in_image(start: u64, max_len: u64, pat: &[u8], wildcard: u8, dir: i32) -> u64 {
    unsafe { search_bytes(start, max_len, pat, wildcard, dir) }
}

fn idt_handler_offset(idt: *const IdtEntry64, index: usize) -> u64 {
    let e = unsafe { idt.add(index).read_unaligned() };
    e.offset_low as u64 | ((e.offset_middle as u64) << 16) | ((e.offset_high as u64) << 32)
}

unsafe fn find_ntoskrnl_by_idt() -> *mut c_void {
    unsafe {
        let idt_base = read_gs_qword(0x38);
        if idt_base == 0 {
            return null_mut();
        }
        let p_idt = idt_base as *const IdtEntry64;
        if p_idt.is_null() {
            return null_mut();
        }

        let mut handler = idt_handler_offset(p_idt, 0);
        if handler == 0 {
            return null_mut();
        }

        let pat_jump = [0x0F, 0xAE, 0xE8, 0xE9];
        let jump_start = search_in_image(handler, 0x1000, &pat_jump, 0, 1);
        if jump_start != 0 {
            let e9 = jump_start + 0x03;
            let disp = *((e9 + 0x01) as *const i32);
            handler = (e9 + 0x05).wrapping_add(disp as i64 as u64);
        }

        let mut rdata = 0u64;
        let pat_rdata1 = [
            0x48, 0x8D, 0x35, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x8B, 0x44, 0xC6,
        ];
        let lea_start1 = search_in_image(handler, 0x400000, &pat_rdata1, 0xAA, 1);
        if lea_start1 != 0 {
            let disp = *((lea_start1 + 0x03) as *const i32);
            rdata = (lea_start1 + 0x07).wrapping_add(disp as i64 as u64);
        }
        if rdata == 0 {
            let pat_rdata2 = [
                0x48, 0x8D, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0x49, 0xC7, 0x43, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0x49,
            ];
            let lea_start2 = search_in_image(handler, 0x400000, &pat_rdata2, 0xAA, 1);
            if lea_start2 != 0 {
                let disp = *((lea_start2 + 0x03) as *const i32);
                rdata = (lea_start2 + 0x07).wrapping_add(disp as i64 as u64);
            }
        }
        if rdata == 0 {
            return null_mut();
        }

        let mut scan = (rdata & !0xFFFu64).wrapping_add(0x1000);
        loop {
            scan = scan.wrapping_sub(0x1000);
            let dos = (scan as *const ImageDosHeader).read_unaligned();
            if dos.e_magic != IMAGE_DOS_SIGNATURE {
                continue;
            }
            let nt_addr = scan.wrapping_add((dos.e_lfanew as u32 & 0xFFFF) as u64);
            let nt = (nt_addr as *const ImageNtHeaders64).read_unaligned();
            if nt.signature != IMAGE_NT_SIGNATURE {
                continue;
            }
            if nt.file_header.number_of_sections < 0x18 {
                continue;
            }
            return scan as *mut c_void;
        }
    }
}

unsafe fn find_ntoskrnl_base() -> *mut c_void {
    unsafe {
        if G_NTOSKRNL_RESOLVED {
            return G_NTOSKRNL_BASE;
        }
        if G_NTOSKRNL_BASE.is_null() {
            G_NTOSKRNL_BASE = find_ntoskrnl_by_idt();
        }
        G_NTOSKRNL_RESOLVED = true;
        G_NTOSKRNL_BASE
    }
}

unsafe fn find_exported_symbol(image_base: *mut c_void, target_hash: [u8; 32]) -> *mut c_void {
    unsafe {
        if image_base.is_null() {
            return null_mut();
        }
        let base = image_base as usize;

        let dos = (base as *const ImageDosHeader).read_unaligned();
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }
        let nt_addr = base.wrapping_add(dos.e_lfanew as usize);
        let nt = (nt_addr as *const ImageNtHeaders64).read_unaligned();
        if nt.signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }

        let exp_dir = nt.optional_header.data_directory[0];
        if exp_dir.virtual_address == 0 || exp_dir.size == 0 {
            return null_mut();
        }

        let exp_addr = base.wrapping_add(exp_dir.virtual_address as usize);
        let exp = (exp_addr as *const ImageExportDirectory).read_unaligned();

        let name_rvas = base.wrapping_add(exp.address_of_names as usize) as *const u32;
        let ordinals = base.wrapping_add(exp.address_of_name_ordinals as usize) as *const u16;
        let function_rvas = base.wrapping_add(exp.address_of_functions as usize) as *const u32;

        for i in 0..exp.number_of_names {
            let name_ptr =
                base.wrapping_add(name_rvas.add(i as usize).read_unaligned() as usize) as *const u8;
            if hash_cstring(name_ptr) == target_hash {
                let ordinal = ordinals.add(i as usize).read_unaligned() as usize;
                let func_rva = function_rvas.add(ordinal).read_unaligned();
                return base.wrapping_add(func_rva as usize) as *mut c_void;
            }
        }
        null_mut()
    }
}

unsafe fn find_kernel_proc_address(export_hash: [u8; 32]) -> *mut c_void {
    unsafe {
        let base = find_ntoskrnl_base();
        if base.is_null() {
            return null_mut();
        }
        find_exported_symbol(base, export_hash)
    }
}

pub fn resolve_kernel_export(export_hash: [u8; 32]) -> *mut c_void {
    unsafe { find_kernel_proc_address(export_hash) }
}

#[unsafe(no_mangle)]
pub extern "system" fn FindKernelProcAddress(export_name: *const i8) -> *mut c_void {
    unsafe {
        if export_name.is_null() {
            return null_mut();
        }
        find_kernel_proc_address(hash_cstring(export_name as *const u8))
    }
}

pub fn resolve_imports() -> NtStatus {
    unsafe {
        if find_ntoskrnl_base().is_null() {
            return STATUS_NOT_FOUND;
        }

        const FUNC_HASHES: [[u8; 32]; 22] = [
            sha256_const(b"KeAcquireSpinLockAtDpcLevel"),
            sha256_const(b"KeReleaseSpinLockFromDpcLevel"),
            sha256_const(b"IofCompleteRequest"),
            sha256_const(b"IoReleaseRemoveLockEx"),
            sha256_const(b"IoCreateDriver"),
            sha256_const(b"ObReferenceObjectByName"),
            sha256_const(b"ObfReferenceObject"),
            sha256_const(b"ObfDereferenceObject"),
            sha256_const(b"MmMapLockedPagesSpecifyCache"),
            sha256_const(b"MmIsAddressValid"),
            sha256_const(b"MmAllocateContiguousMemory"),
            sha256_const(b"MmFreeContiguousMemory"),
            sha256_const(b"PsLookupProcessByProcessId"),
            sha256_const(b"IoCreateSymbolicLink"),
            sha256_const(b"IoDeleteDevice"),
            sha256_const(b"IoDeleteSymbolicLink"),
            sha256_const(b"ExAllocatePool2"),
            sha256_const(b"ExFreePoolWithTag"),
            sha256_const(b"ZwClose"),
            sha256_const(b"ZwCreateFile"),
            sha256_const(b"ZwDeviceIoControlFile"),
            sha256_const(b"ZwQueryVolumeInformationFile"),
        ];

        let func_slots: [*mut *mut c_void; 22] = [
            addr_of_mut!(_KeAcquireSpinLockAtDpcLevel) as *mut *mut c_void,
            addr_of_mut!(_KeReleaseSpinLockFromDpcLevel) as *mut *mut c_void,
            addr_of_mut!(_IofCompleteRequest) as *mut *mut c_void,
            addr_of_mut!(_IoReleaseRemoveLockEx) as *mut *mut c_void,
            addr_of_mut!(_IoCreateDriver) as *mut *mut c_void,
            addr_of_mut!(_ObReferenceObjectByName) as *mut *mut c_void,
            addr_of_mut!(_ObfReferenceObject) as *mut *mut c_void,
            addr_of_mut!(_ObfDereferenceObject) as *mut *mut c_void,
            addr_of_mut!(_MmMapLockedPagesSpecifyCache) as *mut *mut c_void,
            addr_of_mut!(_MmIsAddressValid) as *mut *mut c_void,
            addr_of_mut!(_MmAllocateContiguousMemory) as *mut *mut c_void,
            addr_of_mut!(_MmFreeContiguousMemory) as *mut *mut c_void,
            addr_of_mut!(_PsLookupProcessByProcessId) as *mut *mut c_void,
            addr_of_mut!(_IoCreateSymbolicLink) as *mut *mut c_void,
            addr_of_mut!(_IoDeleteDevice) as *mut *mut c_void,
            addr_of_mut!(_IoDeleteSymbolicLink) as *mut *mut c_void,
            addr_of_mut!(_ExAllocatePool2) as *mut *mut c_void,
            addr_of_mut!(_ExFreePoolWithTag) as *mut *mut c_void,
            addr_of_mut!(_ZwClose) as *mut *mut c_void,
            addr_of_mut!(_ZwCreateFile) as *mut *mut c_void,
            addr_of_mut!(_ZwDeviceIoControlFile) as *mut *mut c_void,
            addr_of_mut!(_ZwQueryVolumeInformationFile) as *mut *mut c_void,
        ];

        for i in 0..FUNC_HASHES.len() {
            let address = find_kernel_proc_address(FUNC_HASHES[i]);
            if address.is_null() {
                return STATUS_NOT_FOUND;
            }
            *func_slots[i] = address;
        }

        let data_address = find_kernel_proc_address(sha256_const(b"IoDriverObjectType"));
        if data_address.is_null() {
            return STATUS_NOT_FOUND;
        }
        _IoDriverObjectType = *(data_address as *const *mut c_void);

        let list_address = find_kernel_proc_address(sha256_const(b"PsLoadedModuleList"));
        if list_address.is_null() {
            return STATUS_NOT_FOUND;
        }
        _PsLoadedModuleList = *(list_address as *const *mut c_void);

        let build_address = find_kernel_proc_address(sha256_const(b"NtBuildNumber"));
        if build_address.is_null() {
            return STATUS_NOT_FOUND;
        }
        _NtBuildNumber = (*(build_address as *const u32) & 0xFFFF) as u16;

        STATUS_SUCCESS
    }
}
