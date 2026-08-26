// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::ffi::*;
use crate::imports::{
    _ExFreePoolWithTag, _NtBuildNumber, _ObfDereferenceObject, _ObfReferenceObject,
    _PsLookupProcessByProcessId,
};
use crate::reimpl_pmem::{copy_virtual_memory, read_process_memory};
use crate::request_handler::verify_secure_key;
use crate::types::{NtStatus, Requests, UnicodeString};

type FnPsLookupProcessByProcessId = unsafe extern "system" fn(usize, *mut *mut c_void) -> NtStatus;
type FnObfDereferenceObject = unsafe extern "system" fn(*mut c_void) -> isize;
type FnObfReferenceObject = unsafe extern "system" fn(*mut c_void) -> isize;
type FnExFreePoolWithTag = unsafe extern "system" fn(*mut c_void, u32);

pub static mut G_ACTIVE_PROCESS_LINKS_OFFSET: u32 = 0;
pub static mut G_USER_DIRECTORY_TABLE_BASE_OFFSET: u32 = 0;

const OFF_PEB_LDR: u64 = 0x18;
const OFF_LDR_INLOAD_ORDER: u64 = 0x10;
const OFF_ENTRY_INLOAD_LINKS: u64 = 0x00;
const OFF_ENTRY_DLLBASE: u64 = 0x30;
const OFF_ENTRY_SIZEIMAGE: u64 = 0x40;
const OFF_ENTRY_BASENAME: u64 = 0x58;

fn lookup_process(pid: u64, out: *mut *mut c_void) -> NtStatus {
    unsafe {
        if _PsLookupProcessByProcessId.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        let f: FnPsLookupProcessByProcessId = core::mem::transmute(_PsLookupProcessByProcessId);
        f(pid as usize, out)
    }
}

fn deref_process(obj: *mut c_void) {
    unsafe {
        if !_ObfDereferenceObject.is_null() {
            let f: FnObfDereferenceObject = core::mem::transmute(_ObfDereferenceObject);
            f(obj);
        }
    }
}

fn ref_process(obj: *mut c_void) {
    unsafe {
        if !_ObfReferenceObject.is_null() {
            let f: FnObfReferenceObject = core::mem::transmute(_ObfReferenceObject);
            f(obj);
        }
    }
}

fn free_converted_pwstr(ppw_str: *mut *mut u16) {
    unsafe {
        if ppw_str.is_null() || (*ppw_str).is_null() {
            return;
        }
        let cch = kwcslen(*ppw_str) + 1;
        let byte_size = cch * core::mem::size_of::<u16>();
        core::ptr::write_bytes(*ppw_str as *mut u8, 0, byte_size);
        if !_ExFreePoolWithTag.is_null() {
            let f: FnExFreePoolWithTag = core::mem::transmute(_ExFreePoolWithTag);
            f(*ppw_str as *mut c_void, 0x7265_6355);
        }
        *ppw_str = null_mut();
    }
}

pub fn read_vm(in_req: *mut Requests) -> u8 {
    unsafe {
        if KeGetCurrentIrqlMeme() > PASSIVE_LEVEL {
            return 0;
        }
        if (*in_req).request_pid == 0 || (*in_req).target_pid == 0 {
            return 0;
        }

        let mut to_process: *mut c_void = null_mut();
        let mut from_process: *mut c_void = null_mut();

        if lookup_process((*in_req).request_pid, &mut to_process) < 0 {
            return 0;
        }
        if lookup_process((*in_req).target_pid, &mut from_process) < 0 {
            deref_process(to_process);
            return 0;
        }

        if PsGetProcessExitStatusTrick(from_process) != STATUS_PENDING {
            deref_process(from_process);
            deref_process(to_process);
            return 0;
        }

        let status = copy_virtual_memory(
            from_process,
            (*in_req).target_addr,
            to_process,
            (*in_req).request_addr,
            (*in_req).mem_size as usize,
        );

        deref_process(from_process);
        deref_process(to_process);
        (status >= 0) as u8
    }
}

pub fn write_vm(in_req: *mut Requests) -> u8 {
    unsafe {
        if KeGetCurrentIrqlMeme() > PASSIVE_LEVEL {
            return 0;
        }
        if (*in_req).request_pid == 0 || (*in_req).target_pid == 0 {
            return 0;
        }

        let mut from_process: *mut c_void = null_mut();
        let mut to_process: *mut c_void = null_mut();

        if lookup_process((*in_req).request_pid, &mut from_process) < 0 {
            return 0;
        }
        if lookup_process((*in_req).target_pid, &mut to_process) < 0 {
            deref_process(from_process);
            return 0;
        }

        if PsGetProcessExitStatusTrick(to_process) != STATUS_PENDING {
            deref_process(from_process);
            deref_process(to_process);
            return 0;
        }

        let status = copy_virtual_memory(
            from_process,
            (*in_req).request_addr,
            to_process,
            (*in_req).target_addr,
            (*in_req).mem_size as usize,
        );

        deref_process(from_process);
        deref_process(to_process);
        (status >= 0) as u8
    }
}

fn get_module_base(proc: *mut c_void, module_name: UnicodeString, get_size: bool) -> u64 {
    unsafe {
        if proc.is_null() {
            return 0;
        }
        if KeGetCurrentIrqlMeme() > PASSIVE_LEVEL {
            return 0;
        }
        if module_name.buffer.is_null() || module_name.length == 0 {
            return 0;
        }

        let peb_va = PsGetProcessPebTrick(proc) as u64;
        if peb_va == 0 {
            return 0;
        }

        let mut result = 0u64;
        let mut ldr_va = 0u64;
        if read_process_memory(
            proc,
            peb_va + OFF_PEB_LDR,
            (&mut ldr_va) as *mut u64 as *mut c_void,
            8,
        ) < 0
        {
            return 0;
        }
        if ldr_va == 0 {
            return 0;
        }

        let head = ldr_va + OFF_LDR_INLOAD_ORDER;
        let mut flink = 0u64;
        if read_process_memory(proc, head, (&mut flink) as *mut u64 as *mut c_void, 8) < 0 {
            return 0;
        }

        for _ in 0..0x1000 {
            if flink == 0 || flink == head {
                break;
            }
            if flink < 0x10000 || (flink & 0x7) != 0 {
                break;
            }

            let entry_va = flink - OFF_ENTRY_INLOAD_LINKS;
            let mut raw = [0u8; 0x68];
            if read_process_memory(proc, entry_va, raw.as_mut_ptr() as *mut c_void, raw.len()) < 0 {
                break;
            }

            let dll_base = u64::from_le_bytes(
                raw[OFF_ENTRY_DLLBASE as usize..OFF_ENTRY_DLLBASE as usize + 8]
                    .try_into()
                    .unwrap(),
            );
            let size_of_image = u64::from_le_bytes(
                raw[OFF_ENTRY_SIZEIMAGE as usize..OFF_ENTRY_SIZEIMAGE as usize + 8]
                    .try_into()
                    .unwrap(),
            );
            let name_len = u16::from_le_bytes(
                raw[OFF_ENTRY_BASENAME as usize..OFF_ENTRY_BASENAME as usize + 2]
                    .try_into()
                    .unwrap(),
            );
            let name_buf = u64::from_le_bytes(
                raw[OFF_ENTRY_BASENAME as usize + 8..OFF_ENTRY_BASENAME as usize + 16]
                    .try_into()
                    .unwrap(),
            );

            if name_len > 0 && name_len <= 0x400 && name_buf != 0 {
                let mut local_name = [0u16; 256];
                let bytes = if (name_len as usize) < (local_name.len() * 2 - 2) {
                    name_len as usize
                } else {
                    local_name.len() * 2 - 2
                };
                if read_process_memory(
                    proc,
                    name_buf,
                    local_name.as_mut_ptr() as *mut c_void,
                    bytes,
                ) >= 0
                {
                    local_name[bytes / 2] = 0;
                    if kwcsicmp(local_name.as_ptr(), module_name.buffer) == 0 {
                        result = if get_size { size_of_image } else { dll_base };
                        break;
                    }
                }
            }

            let next = u64::from_le_bytes(
                raw[OFF_ENTRY_INLOAD_LINKS as usize..OFF_ENTRY_INLOAD_LINKS as usize + 8]
                    .try_into()
                    .unwrap(),
            );
            if next == 0 || next == flink {
                break;
            }
            flink = next;
        }

        result
    }
}

fn get_dll_base_or_size(in_req: *mut Requests, get_size: bool) -> u64 {
    unsafe {
        if (*in_req).target_pid == 0 {
            return 0;
        }
        if KeGetCurrentIrqlMeme() > PASSIVE_LEVEL {
            return 0;
        }
        if !verify_secure_key((*in_req).secure_key) {
            return 0;
        }

        let mut source_process: *mut c_void = null_mut();
        if lookup_process((*in_req).target_pid, &mut source_process) < 0 {
            return 0;
        }

        if PsGetProcessExitStatusTrick(source_process) != STATUS_PENDING {
            deref_process(source_process);
            return 0;
        }

        let mut decoded = [0i8; 65];
        kmemset(decoded.as_mut_ptr() as *mut c_void, 0, decoded.len());
        DecodeFixedStr64(
            &(*in_req).name_str,
            decoded.as_mut_ptr(),
            (*in_req).name_length,
        );
        let mut w_str = ConvertToPWSTR(decoded.as_ptr());
        if w_str.is_null() {
            free_converted_pwstr(&mut w_str);
            deref_process(source_process);
            return 0;
        }

        let mut module_name = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: null_mut(),
        };
        RtlInitUnicodeStringMeme(&mut module_name, w_str);
        let result = get_module_base(source_process, module_name, get_size);

        free_converted_pwstr(&mut w_str);
        deref_process(source_process);
        result
    }
}

pub fn get_dll_address(in_req: *mut Requests) -> u64 {
    get_dll_base_or_size(in_req, false)
}

pub fn get_dll_size(in_req: *mut Requests) -> u64 {
    get_dll_base_or_size(in_req, true)
}

pub fn init_offsets_by_version() -> bool {
    unsafe {
        G_ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
        G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x278;

        if _NtBuildNumber >= 26000 {
            G_ACTIVE_PROCESS_LINKS_OFFSET = 0x1d8;
            G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x388;
            return true;
        } else if _NtBuildNumber >= 22000 {
            G_ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
            G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x388;
            return true;
        } else if _NtBuildNumber >= 19041 {
            G_ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
            G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x388;
            return true;
        } else if _NtBuildNumber >= 18362 {
            G_ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
            G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x280;
            return true;
        } else if _NtBuildNumber >= 10240 {
            G_ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
            G_USER_DIRECTORY_TABLE_BASE_OFFSET = 0x278;
            return true;
        }
        false
    }
}

pub fn get_process_id_by_name(in_req: *mut Requests) -> u64 {
    unsafe {
        if in_req.is_null() || (*in_req).name_length == 0 || (*in_req).name_length > 64 {
            return 0;
        }
        if !verify_secure_key((*in_req).secure_key) {
            return 0;
        }
        if KeGetCurrentIrqlMeme() > PASSIVE_LEVEL {
            return 0;
        }
        if G_ACTIVE_PROCESS_LINKS_OFFSET == 0 {
            if !init_offsets_by_version() {
                return 0;
            }
        }

        let mut target_name = [0i8; 65];
        kmemset(
            target_name.as_mut_ptr() as *mut c_void,
            0,
            target_name.len(),
        );
        DecodeFixedStr64(
            &(*in_req).name_str,
            target_name.as_mut_ptr(),
            (*in_req).name_length,
        );

        let mut start_process: *mut c_void = null_mut();
        if lookup_process(4, &mut start_process) < 0 {
            return 0;
        }

        let mut current_process = start_process;
        ref_process(current_process);
        let mut found_pid = 0u64;
        let mut process_count = 0u32;

        while !current_process.is_null() && process_count < 1000 {
            process_count += 1;
            let current_pid = PsGetProcessIdTrick(current_process);
            let image_name = PsGetProcessImageFileNameTrick(current_process);

            if !image_name.is_null() && *image_name != 0 {
                if kstricmp(target_name.as_ptr(), image_name) == 0 {
                    found_pid = current_pid as u64;
                    break;
                }
            }

            let list_entry =
                (current_process as usize + G_ACTIVE_PROCESS_LINKS_OFFSET as usize) as *const usize;
            let flink = *list_entry;
            if flink == 0 || flink == list_entry as usize {
                break;
            }

            let next_addr = flink - G_ACTIVE_PROCESS_LINKS_OFFSET as usize;
            let next_process = next_addr as *mut c_void;
            let next_pid = PsGetProcessIdTrick(next_process);

            let mut next_safe: *mut c_void = null_mut();
            if next_pid != 0 && lookup_process(next_pid as u64, &mut next_safe) >= 0 {
                if next_safe == start_process {
                    deref_process(next_safe);
                    break;
                }
                deref_process(current_process);
                current_process = next_safe;
            } else {
                break;
            }
        }

        if !current_process.is_null() && current_process != start_process {
            deref_process(current_process);
        }
        if !start_process.is_null() {
            deref_process(start_process);
        }

        found_pid
    }
}
