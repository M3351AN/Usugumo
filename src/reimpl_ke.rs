// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use crate::consts::*;

pub fn query_system_time() -> i64 {
    crate::helpers::read_u64(KUSER_SHARED_SYSTEM_TIME as *const u8, 0) as i64
}

pub fn ke_get_current_irql() -> u8 {
    let irql: u64;
    unsafe {
        core::arch::asm!("mov {}, cr8", out(reg) irql, options(nostack));
    }
    irql as u8
}

pub fn kz_raise_irql(new_irql: u8) -> u8 {
    let old: u64;
    let new = new_irql as u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr8",
            "mov cr8, {1}",
            out(reg) old,
            in(reg) new,
            options(nostack)
        );
    }
    old as u8
}

pub fn kz_lower_irql(new_irql: u8) {
    let new = new_irql as u64;
    unsafe {
        core::arch::asm!("mov cr8, {}", in(reg) new, options(nostack));
    }
}

type FnKeSetAddressPolicy = unsafe extern "system" fn(u8);

#[derive(Clone, Copy)]
struct KiAttachAddr {
    kva_shadow: *const u8,
    ki_set_address_policy: *mut c_void,
    ki_flush_pcid: *const u8,
}

static mut G_KI_ATTACH: Option<KiAttachAddr> = None;

const KI_ATTACH_SCAN_LEN: usize = 0x280;

#[inline]
fn in_kernel_range(value: u64) -> bool {
    (value as usize) >= KERNEL_IMAGE_MIN
}

type FnMmIsAddressValid = unsafe extern "system" fn(u64) -> u8;

fn is_mapped(target: u64) -> bool {
    if !in_kernel_range(target) {
        return false;
    }
    unsafe {
        if crate::imports::_MM_IS_ADDRESS_VALID.is_null() {
            return false;
        }
        let valid: FnMmIsAddressValid = core::mem::transmute(crate::imports::_MM_IS_ADDRESS_VALID);
        valid(target) != 0 && valid(target + 4) != 0
    }
}

fn looks_like_code(target: u64) -> bool {
    if !is_mapped(target) || !is_mapped(target + 8) {
        return false;
    }
    unsafe {
        let head = target as *const u8;
        let sig = core::ptr::read_volatile(head);
        if sig == 0 || sig == 0xCC || sig == 0xFF {
            return false;
        }
        match decoder_for(head, 16) {
            Some(mut dec) => dec.decode().code() != Code::INVALID,
            None => false,
        }
    }
}

fn decoder_for(code: *const u8, len: usize) -> Option<Decoder<'static>> {
    if code.is_null() || len == 0 {
        return None;
    }
    unsafe {
        let data = core::slice::from_raw_parts(code, len);
        Some(Decoder::with_ip(
            64,
            data,
            code as u64,
            DecoderOptions::NONE,
        ))
    }
}

fn call_target(insn: &Instruction) -> Option<u64> {
    if insn.mnemonic() != Mnemonic::Call || insn.op0_kind() != OpKind::NearBranch64 {
        return None;
    }
    let target = insn.near_branch64();
    if in_kernel_range(target) {
        Some(target)
    } else {
        None
    }
}

fn rip_operand(insn: &Instruction) -> Option<u64> {
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Memory && insn.memory_base() == iced_x86::Register::RIP {
            let target = insn.memory_displacement64();
            if in_kernel_range(target) {
                return Some(target);
            }
        }
    }
    None
}

unsafe fn find_ki_attach() -> Option<KiAttachAddr> {
    unsafe {
        let ke_attach = crate::imports::_KE_ATTACH_PROCESS;
        if ke_attach.is_null() {
            return None;
        }

        let mut dec = decoder_for(ke_attach as *const u8, 0x120)?;
        for _ in 0..0x40 {
            let insn = dec.decode();
            if insn.code() == Code::INVALID {
                break;
            }
            let Some(target) = call_target(&insn) else {
                continue;
            };
            if let Some(addr) = scan_ki_attach_body(target as *const u8) {
                return Some(addr);
            }
        }
        None
    }
}

unsafe fn scan_ki_attach_body(ki_attach: *const u8) -> Option<KiAttachAddr> {
    let mut dec = decoder_for(ki_attach, KI_ATTACH_SCAN_LEN)?;
    let mut kva_shadow = 0u64;
    let mut set_policy = 0u64;
    let mut ki_flush_pcid = 0u64;

    for _ in 0..KI_ATTACH_SCAN_LEN {
        let insn = dec.decode();
        if insn.code() == Code::INVALID {
            break;
        }

        if let Some(target) = rip_operand(&insn) {
            if insn.mnemonic() == Mnemonic::Mov {
                continue;
            }
            if insn.mnemonic() == Mnemonic::Cmp {
                let is_zero = match insn.op1_kind() {
                    OpKind::Immediate8 => insn.immediate8() == 0,
                    OpKind::Immediate32 => insn.immediate32() == 0,
                    _ => false,
                };
                if is_zero {
                    if kva_shadow == 0 {
                        kva_shadow = target;
                    } else if target != kva_shadow && ki_flush_pcid == 0 {
                        ki_flush_pcid = target;
                    }
                }
            }
            continue;
        }

        if kva_shadow != 0
            && set_policy == 0
            && let Some(target) = call_target(&insn)
        {
            set_policy = target;
        }
    }

    if kva_shadow == 0 || set_policy == 0 || ki_flush_pcid == 0 {
        return None;
    }
    if !looks_like_code(set_policy) {
        return None;
    }
    if !is_mapped(kva_shadow) || !is_mapped(ki_flush_pcid) {
        return None;
    }
    Some(KiAttachAddr {
        kva_shadow: kva_shadow as *const u8,
        ki_set_address_policy: set_policy as *mut c_void,
        ki_flush_pcid: ki_flush_pcid as *const u8,
    })
}

fn ki_attach_addr() -> Option<KiAttachAddr> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(G_KI_ATTACH);
        if (*slot).is_none() {
            *slot = find_ki_attach();
        }
        *slot
    }
}

fn current_process_ptr() -> *mut c_void {
    unsafe {
        let kthread = crate::helpers::current_kthread();
        if kthread.is_null() {
            return null_mut();
        }
        core::ptr::read_volatile(
            kthread
                .add(KTHREAD_APC_PROCESS_OFFSET)
                .cast::<*mut c_void>(),
        )
    }
}

fn swap_apc_state(process: *mut c_void) {
    unsafe {
        let kthread = crate::helpers::current_kthread();
        if kthread.is_null() {
            return;
        }

        core::ptr::copy_nonoverlapping(
            kthread.add(KTHREAD_APC_PROCESS_OFFSET),
            kthread.add(KTHREAD_SAVED_APC_STATE_OFFSET + KAPC_STATE_PROCESS_OFFSET),
            8,
        );

        core::ptr::write_volatile(
            kthread
                .add(KTHREAD_APC_PROCESS_OFFSET)
                .cast::<*mut c_void>(),
            process,
        );
    }
}

fn restore_apc_state() {
    unsafe {
        let kthread = crate::helpers::current_kthread();
        if kthread.is_null() {
            return;
        }

        core::ptr::copy_nonoverlapping(
            kthread.add(KTHREAD_SAVED_APC_STATE_OFFSET + KAPC_STATE_PROCESS_OFFSET),
            kthread.add(KTHREAD_APC_PROCESS_OFFSET),
            8,
        );
    }
}

fn read_gs_kva_base() -> u64 {
    unsafe {
        let value: u64;
        core::arch::asm!(
            "mov {}, qword ptr gs:[{off}]",
            out(reg) value,
            off = const GS_KVA_BASE_OFFSET,
            options(nostack, readonly),
        );
        value
    }
}

fn write_gs_kva_base(value: u64) {
    unsafe {
        core::arch::asm!(
            "mov qword ptr gs:[{off}], {value}",
            off = const GS_KVA_BASE_OFFSET,
            value = in(reg) value,
            options(nostack),
        );
    }
}

fn flush_tlb_kva_shadow(addr: &KiAttachAddr) {
    unsafe {
        if core::ptr::read_volatile(addr.ki_flush_pcid) != 0 {
            return;
        }
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
        if cr4 & 0x20080 == 0 {
            // Without PGE/PCIDE the kernel falls back to rewriting CR3.
            let cr3 = crate::helpers::read_cr3();
            crate::helpers::write_cr3(cr3);
            return;
        }
        let toggled = cr4 & !0x80;
        core::arch::asm!("mov cr4, {}", in(reg) toggled, options(nostack));
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
    }
}

static mut G_ATTACH_STATE: Option<KeAttachProcessStateTrick> = None;

fn switch_address_space_trick(addr: &KiAttachAddr, dtb: u64, kva_shadow: bool) {
    crate::helpers::write_cr3(dtb);
    if kva_shadow {
        flush_tlb_kva_shadow(addr);
    }
}

#[derive(Clone, Copy)]
struct KeAttachProcessStateTrick {
    saved_dtb: u64,
    saved_gs_kva: u64,
    saved_policy: u8,
    kva_shadow: bool,
}

pub fn ke_attach_process_trick(process: *mut c_void) -> bool {
    let addr = match ki_attach_addr() {
        Some(a) => a,
        None => return false,
    };
    unsafe {
        if process.is_null() {
            return false;
        }
        let dtb =
            core::ptr::read_volatile((process as *const u8).add(KPROCESS_DTB_OFFSET) as *const u64);
        if dtb == 0 {
            return false;
        }
        let source = current_process_ptr();
        if source.is_null() {
            return false;
        }

        let kva_shadow = core::ptr::read_volatile(addr.kva_shadow) != 0;
        let saved = KeAttachProcessStateTrick {
            saved_dtb: crate::helpers::read_cr3(),
            saved_gs_kva: read_gs_kva_base(),
            saved_policy: core::ptr::read_volatile(
                (source as *const u8).add(KPROCESS_ADDRESS_POLICY_OFFSET),
            ),
            kva_shadow,
        };
        *core::ptr::addr_of_mut!(G_ATTACH_STATE) = Some(saved);

        swap_apc_state(process);

        if kva_shadow {
            let shifted = if dtb & 2 == 0 {
                dtb
            } else {
                dtb | KVA_SHADOW_SHIFT
            };
            write_gs_kva_base(shifted);
            let policy = core::ptr::read_volatile(
                (process as *const u8).add(KPROCESS_ADDRESS_POLICY_OFFSET),
            );
            let f: FnKeSetAddressPolicy = core::mem::transmute(addr.ki_set_address_policy);
            f(policy);
        }

        switch_address_space_trick(&addr, dtb, kva_shadow);
        true
    }
}

pub fn ke_detach_process_trick() {
    let addr = match ki_attach_addr() {
        Some(a) => a,
        None => return,
    };
    unsafe {
        let slot = core::ptr::addr_of_mut!(G_ATTACH_STATE);
        let saved = match *slot {
            Some(s) => s,
            None => return,
        };
        if saved.kva_shadow {
            write_gs_kva_base(saved.saved_gs_kva);
            let f: FnKeSetAddressPolicy = core::mem::transmute(addr.ki_set_address_policy);
            f(saved.saved_policy);
        }
        switch_address_space_trick(&addr, saved.saved_dtb, saved.kva_shadow);
        restore_apc_state();
        *slot = None;
    }
}
