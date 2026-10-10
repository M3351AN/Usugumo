// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};

use crate::imports::resolve_kernel_export;

fn extract_load_disp32(func: *mut c_void, cap: usize) -> u32 {
    unsafe {
        if func.is_null() {
            return 0;
        }
        let data = core::slice::from_raw_parts(func as *const u8, 0x60);
        let mut dec = Decoder::with_ip(64, data, func as u64, DecoderOptions::NONE);
        for _ in 0..cap {
            let insn = dec.decode();
            if insn.code() == Code::INVALID {
                return 0;
            }
            if insn.mnemonic() != Mnemonic::Mov && insn.mnemonic() != Mnemonic::Lea {
                continue;
            }
            if insn.memory_base() == Register::None || insn.is_ip_rel_memory_operand() {
                continue;
            }
            if insn.op0_kind() != OpKind::Register {
                continue;
            }
            let base = insn.memory_base();
            if base == Register::RSP || base == Register::RBP {
                continue;
            }
            if insn.memory_index() != Register::None {
                continue;
            }
            let d = insn.memory_displacement64();
            if d > 0x10 && d <= 0x1000 {
                return d as u32;
            }
        }
        0
    }
}

static mut G_PEB_OFFSET: u32 = 0;

fn get_peb_offset() -> u32 {
    unsafe {
        if G_PEB_OFFSET != 0 {
            return G_PEB_OFFSET;
        }
        let off = extract_load_disp32(resolve_kernel_export(crate::hash!(b"PsGetProcessPeb")), 10);
        if off != 0 {
            G_PEB_OFFSET = off;
        }
        off
    }
}

pub fn ps_get_process_peb_trick(process: *mut c_void) -> *mut c_void {
    let off = get_peb_offset();
    if off == 0 {
        return null_mut();
    }
    crate::helpers::read_u64(process as *const u8, off as usize) as *mut c_void
}

static mut G_IMAGE_FILE_NAME_OFFSET: u32 = 0;

fn get_image_file_name_offset() -> u32 {
    unsafe {
        if G_IMAGE_FILE_NAME_OFFSET != 0 {
            return G_IMAGE_FILE_NAME_OFFSET;
        }
        let off = extract_load_disp32(
            resolve_kernel_export(crate::hash!(b"PsGetProcessImageFileName")),
            10,
        );
        if off != 0 {
            G_IMAGE_FILE_NAME_OFFSET = off;
        }
        off
    }
}

pub fn ps_get_process_image_file_name_trick(process: *mut c_void) -> *mut i8 {
    unsafe {
        let off = get_image_file_name_offset();
        if off == 0 {
            return null_mut();
        }
        (process as *const u8).add(off as usize) as *mut i8
    }
}

static mut G_PROCESS_ID_OFFSET: u32 = 0;

fn get_process_id_offset() -> u32 {
    unsafe {
        if G_PROCESS_ID_OFFSET != 0 {
            return G_PROCESS_ID_OFFSET;
        }
        let off = extract_load_disp32(resolve_kernel_export(crate::hash!(b"PsGetProcessId")), 10);
        if off != 0 {
            G_PROCESS_ID_OFFSET = off;
        }
        off
    }
}

pub fn ps_get_process_id_trick(process: *mut c_void) -> usize {
    let off = get_process_id_offset();
    if off == 0 {
        return 0;
    }
    crate::helpers::read_u64(process as *const u8, off as usize) as usize
}

static mut G_PROCESS_EXIT_STATUS_OFFSET: u32 = 0;

fn get_process_exit_status_offset() -> u32 {
    unsafe {
        if G_PROCESS_EXIT_STATUS_OFFSET != 0 {
            return G_PROCESS_EXIT_STATUS_OFFSET;
        }
        let off = extract_load_disp32(
            resolve_kernel_export(crate::hash!(b"PsGetProcessExitStatus")),
            10,
        );
        if off != 0 {
            G_PROCESS_EXIT_STATUS_OFFSET = off;
        }
        off
    }
}

pub fn ps_get_process_exit_status_trick(process: *mut c_void) -> i32 {
    let off = get_process_exit_status_offset();
    if off == 0 {
        return 0;
    }
    crate::helpers::read_u32(process as *const u8, off as usize) as i32
}

static mut G_PFN_BASE: u64 = 0;
static mut G_PTE_BASE: u64 = 0;

fn parse_bases() {
    unsafe {
        if G_PFN_BASE != 0 && G_PTE_BASE != 0 {
            return;
        }
        let func = resolve_kernel_export(crate::hash!(b"MmGetVirtualForPhysical"));
        if func.is_null() {
            return;
        }
        let data = core::slice::from_raw_parts(func as *const u8, 0x60);
        let mut dec = Decoder::with_ip(64, data, func as u64, DecoderOptions::NONE);
        let mut caps = [0u64; 6];
        let mut nc = 0usize;
        for _ in 0..16 {
            let insn = dec.decode();
            if insn.code() == Code::INVALID {
                break;
            }
            let c = match insn.code() {
                Code::Mov_r64_imm64 => Some(insn.immediate64()),
                Code::Mov_rm64_imm32 => Some(insn.immediate32() as i32 as i64 as u64),
                _ => {
                    if insn.mnemonic() == Mnemonic::Mov || insn.mnemonic() == Mnemonic::Lea {
                        if insn.is_ip_rel_memory_operand() && insn.op0_kind() == OpKind::Register {
                            let disp = insn.memory_displacement64() as i64;
                            let mut v = (insn.next_ip() as u64).wrapping_add_signed(disp);
                            if insn.mnemonic() == Mnemonic::Mov {
                                v = crate::helpers::read_u64(v as *const u8, 0);
                            }
                            if (v >> 47) as u16 == 0xFFFF {
                                Some(v)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            };
            if let Some(c) = c {
                if c != 0 && nc < caps.len() {
                    caps[nc] = c;
                    nc += 1;
                }
            }
        }
        if nc == 0 {
            return;
        }
        let mut pte = 0u64;
        let mut pfn = 0u64;
        for i in 0..nc {
            if caps[i] & 0x0fff_ffff == 0 {
                pte = caps[i];
                if i > 0 {
                    pfn = caps[0];
                }
                break;
            }
        }
        if pte == 0 {
            pte = caps[0];
            pfn = if nc > 1 { caps[1] } else { 0 };
        } else if pfn == 0 {
            pfn = caps.iter().copied().find(|&c| c != pte).unwrap_or(0);
        }
        G_PTE_BASE = pte;
        G_PFN_BASE = pfn;
    }
}

pub fn mm_get_virtual_for_physical_trick(physical_address: u64) -> *mut c_void {
    unsafe {
        parse_bases();
        let pfn = physical_address >> 12;
        let offset = physical_address & 0xFFF;
        let val = crate::helpers::read_u64((G_PFN_BASE + pfn * 48) as *const u8, 0);
        let shifted = val << 25;
        let base2_shifted = G_PTE_BASE << 25;
        let diff = (shifted.wrapping_sub(base2_shifted) as i64) >> 16;
        (diff as u64 + offset) as *mut c_void
    }
}
