// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::imports::{
    _EX_ALLOCATE_POOL2, _EX_FREE_POOL_WITH_TAG, _MM_ALLOCATE_CONTIGUOUS_MEMORY,
    _MM_FREE_CONTIGUOUS_MEMORY,
};
use crate::process::init_offsets_by_version;
use crate::types::NtStatus;

type FnMmAllocateContiguousMemory = unsafe extern "system" fn(usize, u64) -> *mut c_void;
type FnMmFreeContiguousMemory = unsafe extern "system" fn(*mut c_void);
type FnExAllocatePool2 = unsafe extern "system" fn(u64, usize, u32) -> *mut c_void;
type FnExFreePoolWithTag = unsafe extern "system" fn(*mut c_void, u32);

#[derive(Clone, Copy)]
struct PMemPage {
    virtual_address: *mut c_void,
    pte_long: *mut u64,
}

static mut G_PMEM_PAGES: [PMemPage; PMEM_MAX_CPU_PAGES] = [PMemPage {
    virtual_address: null_mut(),
    pte_long: null_mut(),
}; PMEM_MAX_CPU_PAGES];

const SYSTEM_CODEINTEGRITY_INFORMATION_CLASS: u32 = 103;
const CODEINTEGRITY_HVCI_ENABLED: u32 = 0x400;

#[repr(C)]
struct CodeIntegrityInfo {
    length: u32,
    flags: u32,
}

type FnZwQuerySystemInformation =
    unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> NtStatus;

pub(crate) fn hvci_enabled() -> bool {
    unsafe {
        let resolve = crate::imports::resolve_kernel_export;
        let func = resolve(crate::hash!(b"ZwQuerySystemInformation"));
        if func.is_null() {
            return false;
        }
        let query: FnZwQuerySystemInformation = core::mem::transmute(func);
        let mut info = CodeIntegrityInfo {
            length: core::mem::size_of::<CodeIntegrityInfo>() as u32,
            flags: 0,
        };
        let mut returned = 0u32;
        let status = query(
            SYSTEM_CODEINTEGRITY_INFORMATION_CLASS,
            (&mut info) as *mut CodeIntegrityInfo as *mut c_void,
            info.length,
            &mut returned,
        );
        if status < 0 {
            return false;
        }
        info.flags & CODEINTEGRITY_HVCI_ENABLED != 0
    }
}

fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
    }
    cr3
}

fn write_cr3(value: u64) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) value, options(nostack));
    }
}

#[allow(dead_code)]
fn read_flags() -> u64 {
    let r: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) r, options(nostack));
    }
    r
}

#[allow(dead_code)]
fn write_flags(value: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) value, options(nostack));
    }
}

#[allow(dead_code)]
fn cli() {
    unsafe {
        core::arch::asm!("cli", options(nostack));
    }
}

#[allow(dead_code)]
fn sti() {
    unsafe {
        core::arch::asm!("sti", options(nostack));
    }
}

fn mfence() {
    unsafe {
        core::arch::asm!("mfence", options(nostack));
    }
}

fn invlpg(address: u64) {
    unsafe {
        core::arch::asm!("invlpg [{0}]", in(reg) address, options(nostack));
    }
}

const KPCR_PRCB_OFFSET: usize = 0x20;
const KPRCB_NUMBER_OFFSET: usize = 0xD0;

fn current_processor_index() -> u32 {
    unsafe {
        let prcb: u64;
        core::arch::asm!(
            "mov {}, qword ptr gs:[{}]",
            out(reg) prcb,
            const KPCR_PRCB_OFFSET,
            options(nostack, readonly),
        );
        if prcb < 0xFFFF_8000_0000_0000 {
            return 0;
        }
        crate::helpers::read_u8(prcb as *const u8, KPRCB_NUMBER_OFFSET) as u32
    }
}

fn secure_zero(ptr: *mut u8, len: usize) {
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
    }
}

fn pmem_phys_to_va(physical_address: u64) -> *mut c_void {
    crate::reimpl::mm_get_virtual_for_physical_trick(physical_address)
}

fn pmem_get_pte(address: u64) -> *mut u64 {
    let cr3 = read_cr3() & !0xF;
    let pml4_index = (address >> 39) & 0x1FF;
    let pdpt_index = (address >> 30) & 0x1FF;
    let pd_index = (address >> 21) & 0x1FF;
    let pt_index = (address >> 12) & 0x1FF;

    let pml4_va = pmem_phys_to_va(cr3);
    if pml4_va.is_null() {
        return null_mut();
    }
    let pml4e = crate::helpers::read_u64(pml4_va as *const u8, (pml4_index * 8) as usize);
    if pml4e & 1 == 0 {
        return null_mut();
    }

    let pdpt_va = pmem_phys_to_va(pml4e & PMEM_PMASK);
    if pdpt_va.is_null() {
        return null_mut();
    }
    let pdpte = crate::helpers::read_u64(pdpt_va as *const u8, (pdpt_index * 8) as usize);
    if pdpte & 1 == 0 {
        return null_mut();
    }
    if pdpte & 0x80 != 0 {
        return null_mut();
    }

    let pd_va = pmem_phys_to_va(pdpte & PMEM_PMASK);
    if pd_va.is_null() {
        return null_mut();
    }
    let pde = crate::helpers::read_u64(pd_va as *const u8, (pd_index * 8) as usize);
    if pde & 1 == 0 {
        return null_mut();
    }
    if pde & 0x80 != 0 {
        return null_mut();
    }

    let pt_va = pmem_phys_to_va(pde & PMEM_PMASK);
    if pt_va.is_null() {
        return null_mut();
    }
    if crate::helpers::read_u64(pt_va as *const u8, (pt_index * 8) as usize) & 1 == 0 {
        return null_mut();
    }
    unsafe { (pt_va as *mut u64).add(pt_index as usize) }
}

fn pmem_swap_phys(
    physical_address: u64,
    buffer: *mut c_void,
    size: usize,
    write: bool,
) -> NtStatus {
    unsafe {
        if size == 0 {
            return STATUS_SUCCESS;
        }

        let mut idx = current_processor_index();
        if idx as usize >= PMEM_MAX_CPU_PAGES {
            idx = 0;
        }
        if G_PMEM_PAGES[idx as usize].virtual_address.is_null() {
            let status = ensure_page(idx as usize);
            if status < 0 {
                return status;
            }
        }
        let page = &mut G_PMEM_PAGES[idx as usize];
        if page.virtual_address.is_null() || page.pte_long.is_null() {
            return STATUS_UNSUCCESSFUL;
        }

        let page_start = physical_address & !(PMEM_PAGE_SIZE as u64 - 1);
        let page_offset = (physical_address & (PMEM_PAGE_SIZE as u64 - 1)) as usize;
        if page_offset + size > PMEM_PAGE_SIZE {
            return STATUS_INVALID_PARAMETER;
        }

        let old_value = crate::helpers::read_u64(page.pte_long as *const u8, 0);
        crate::helpers::write_u64(
            page.pte_long as *mut u8,
            0,
            (old_value & !PMEM_PMASK) | page_start,
        );
        mfence();
        invlpg(page.virtual_address as u64);

        let target = (page.virtual_address as *mut u8).add(page_offset);
        if write {
            crate::util::kmemmove(target as *mut c_void, buffer, size);
        } else {
            crate::util::kmemmove(buffer, target as *const c_void, size);
        }

        crate::helpers::write_u64(page.pte_long as *mut u8, 0, old_value);
        mfence();
        invlpg(page.virtual_address as u64);

        STATUS_SUCCESS
    }
}

pub fn read_physical(physical_address: u64, buffer: *mut c_void, size: usize) -> NtStatus {
    pmem_swap_phys(physical_address, buffer, size, false)
}

pub fn write_physical(physical_address: u64, buffer: *const c_void, size: usize) -> NtStatus {
    pmem_swap_phys(physical_address, buffer as *mut c_void, size, true)
}

fn read_physical_u64(physical_address: u64) -> u64 {
    let mut value = 0u64;
    let status = pmem_swap_phys(
        physical_address,
        (&mut value) as *mut u64 as *mut c_void,
        8,
        false,
    );
    if status < 0 {
        return 0;
    }
    value
}

pub fn init_pmem_pages() -> NtStatus {
    let mut idx = current_processor_index() as usize;
    if idx >= PMEM_MAX_CPU_PAGES {
        idx = 0;
    }
    ensure_page(idx)
}

fn ensure_page(idx: usize) -> NtStatus {
    unsafe {
        if idx >= PMEM_MAX_CPU_PAGES {
            return STATUS_UNSUCCESSFUL;
        }
        if !G_PMEM_PAGES[idx].virtual_address.is_null() {
            return STATUS_SUCCESS;
        }
        let va = if _MM_ALLOCATE_CONTIGUOUS_MEMORY.is_null() {
            null_mut()
        } else {
            let f: FnMmAllocateContiguousMemory =
                core::mem::transmute(_MM_ALLOCATE_CONTIGUOUS_MEMORY);
            f(PMEM_PAGE_SIZE, u64::MAX)
        };
        if va.is_null() {
            return 0;
        }
        let pte = pmem_get_pte(va as u64);
        if pte.is_null() {
            if !_MM_FREE_CONTIGUOUS_MEMORY.is_null() {
                let f: FnMmFreeContiguousMemory = core::mem::transmute(_MM_FREE_CONTIGUOUS_MEMORY);
                f(va);
            }
            return STATUS_UNSUCCESSFUL;
        }
        G_PMEM_PAGES[idx].virtual_address = va;
        G_PMEM_PAGES[idx].pte_long = pte;
        STATUS_SUCCESS
    }
}

pub fn cleanup_pmem_pages() {
    unsafe {
        let pages = core::ptr::addr_of_mut!(G_PMEM_PAGES) as *mut PMemPage;
        for i in 0..PMEM_MAX_CPU_PAGES {
            let page = &mut *pages.add(i);
            if !page.virtual_address.is_null() {
                if !_MM_FREE_CONTIGUOUS_MEMORY.is_null() {
                    let f: FnMmFreeContiguousMemory =
                        core::mem::transmute(_MM_FREE_CONTIGUOUS_MEMORY);
                    f(page.virtual_address);
                }
                page.virtual_address = null_mut();
                page.pte_long = null_mut();
            }
        }
    }
}

pub fn translate_linear_address(directory_table_base: u64, virtual_address: u64) -> u64 {
    let directory_table_base = directory_table_base & !0xF;
    let page_offset = virtual_address & !(!0u64 << 12);
    let pte = (virtual_address >> 12) & 0x1FF;
    let pt = (virtual_address >> 21) & 0x1FF;
    let pd = (virtual_address >> 30) & 0x1FF;
    let pdp = (virtual_address >> 39) & 0x1FF;

    let pdp_value = read_physical_u64(directory_table_base + pdp * 0x08);
    if pdp_value & 0x01 == 0 {
        return 0;
    }

    let pd_value = read_physical_u64((pdp_value & PMEM_PMASK) + pd * 0x08);
    if pd_value & 0x01 == 0 {
        return 0;
    }
    if pd_value & 0x80 != 0 {
        return (pd_value & (0xFFFF_FFFF_FFFF_FFFFu64 << 42 >> 12))
            + (virtual_address & !(!0u64 << 30));
    }

    let pt_value = read_physical_u64((pd_value & PMEM_PMASK) + pt * 0x08);
    if pt_value & 0x01 == 0 {
        return 0;
    }
    if pt_value & 0x80 != 0 {
        return (pt_value & PMEM_PMASK) + (virtual_address & !(!0u64 << 21));
    }

    let pte_value = read_physical_u64((pt_value & PMEM_PMASK) + pte * 0x08) & PMEM_PMASK;
    if pte_value == 0 {
        return 0;
    }
    pte_value + page_offset
}

pub fn get_process_cr3(process: *mut c_void) -> u64 {
    if process.is_null() {
        return 0;
    }
    let dtb = crate::helpers::read_u64(process as *const u8, 0x28);
    if dtb != 0 {
        return dtb;
    }
    if unsafe { G_USER_DIRECTORY_TABLE_BASE_OFFSET == 0 } && !init_offsets_by_version() {
        return 0;
    }
    crate::helpers::read_u64(
        process as *const u8,
        unsafe { G_USER_DIRECTORY_TABLE_BASE_OFFSET } as usize,
    )
}

pub fn read_process_memory(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *mut c_void,
    size: usize,
) -> usize {
    unsafe {
        if process.is_null() || buffer.is_null() {
            return 0;
        }
        if hvci_enabled() {
            return cr3_switch_read(process, virtual_address, buffer, size);
        }
        let dtb = get_process_cr3(process);
        if dtb == 0 {
            return 0;
        }

        let irql = crate::reimpl_ke::kz_raise_irql(DISPATCH_LEVEL);
        let dst = buffer as *mut u8;
        let mut offset = 0usize;
        while offset < size {
            let remaining = size - offset;
            let va = virtual_address + offset as u64;
            let mut chunk = PMEM_PAGE_SIZE - (va & (PMEM_PAGE_SIZE as u64 - 1)) as usize;
            if chunk > remaining {
                chunk = remaining;
            }

            let phys = translate_linear_address(dtb, va);
            if phys == 0 {
                break;
            }

            let rstatus = read_physical(phys, dst.add(offset) as *mut c_void, chunk);
            if rstatus < 0 {
                break;
            }
            offset += chunk;
        }
        crate::reimpl_ke::kz_lower_irql(irql);
        offset
    }
}

#[allow(dead_code)]
type FnMmIsAddressValid = unsafe extern "system" fn(u64) -> u8;

fn is_user_address(address: u64, size: usize) -> bool {
    const USER_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
    if address == 0 || address > USER_MAX {
        return false;
    }
    match address.checked_add(size as u64) {
        Some(end) => end <= USER_MAX,
        None => false,
    }
}

fn is_range_mapped(address: u64, size: usize) -> bool {
    unsafe {
        if crate::imports::_MM_IS_ADDRESS_VALID.is_null() {
            return false;
        }
        let f: FnMmIsAddressValid = core::mem::transmute(crate::imports::_MM_IS_ADDRESS_VALID);
        let mut off = 0usize;
        while off < size {
            if f(address + off as u64) == 0 {
                return false;
            }
            off += PMEM_PAGE_SIZE;
        }
        true
    }
}

fn cr3_switch_read(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *mut c_void,
    size: usize,
) -> usize {
    unsafe {
        if size == 0 || !is_user_address(virtual_address, size) {
            return 0;
        }
        if crate::imports::_MM_IS_ADDRESS_VALID.is_null() {
            return 0;
        }
        let target_cr3 = get_process_cr3(process);
        if target_cr3 == 0 {
            return 0;
        }

        let old_cr3 = read_cr3();
        write_cr3(target_cr3);

        if !is_range_mapped(virtual_address, size) {
            write_cr3(old_cr3);
            return 0;
        }

        let src = virtual_address as *const u8;
        crate::util::kmemmove(buffer, src as *const c_void, size);

        write_cr3(old_cr3);
        size
    }
}

fn cr3_switch_write(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *const c_void,
    size: usize,
) -> usize {
    unsafe {
        if size == 0 || !is_user_address(virtual_address, size) {
            return 0;
        }
        let target_cr3 = get_process_cr3(process);
        if target_cr3 == 0 {
            return 0;
        }

        if crate::imports::_MM_IS_ADDRESS_VALID.is_null() {
            return 0;
        }

        let old_cr3 = read_cr3();
        write_cr3(target_cr3);

        if !is_range_mapped(virtual_address, size) {
            write_cr3(old_cr3);
            return 0;
        }

        let dst = virtual_address as *mut u8;
        crate::util::kmemmove(dst as *mut c_void, buffer, size);

        write_cr3(old_cr3);
        size
    }
}

pub fn copy_virtual_memory(
    from_process: *mut c_void,
    from_address: u64,
    to_process: *mut c_void,
    to_address: u64,
    size: usize,
) -> usize {
    unsafe {
        if from_process.is_null() || to_process.is_null() || size == 0 {
            return 0;
        }

        let scratch = if _EX_ALLOCATE_POOL2.is_null() {
            null_mut()
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_EX_ALLOCATE_POOL2);
            f(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                PMEM_PAGE_SIZE,
                POOL_TAG_COPY,
            )
        };
        if scratch.is_null() {
            return 0;
        }

        let hvci = hvci_enabled();
        let from_dtb = if hvci {
            0
        } else {
            let d = get_process_cr3(from_process);
            if d == 0 {
                secure_zero(scratch as *mut u8, PMEM_PAGE_SIZE);
                if !_EX_FREE_POOL_WITH_TAG.is_null() {
                    let f: FnExFreePoolWithTag = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
                    f(scratch, POOL_TAG_COPY);
                }
                return 0;
            }
            d
        };
        let to_dtb = if hvci { 0 } else { get_process_cr3(to_process) };

        let mut offset = 0usize;
        while offset < size {
            let remaining = size - offset;
            let fva = from_address + offset as u64;
            let tva = to_address + offset as u64;

            let mut chunk = PMEM_PAGE_SIZE - (fva & (PMEM_PAGE_SIZE as u64 - 1)) as usize;
            let chunk2 = PMEM_PAGE_SIZE - (tva & (PMEM_PAGE_SIZE as u64 - 1)) as usize;
            if chunk2 < chunk {
                chunk = chunk2;
            }
            if chunk > remaining {
                chunk = remaining;
            }

            if hvci {
                if cr3_switch_read(from_process, fva, scratch, chunk) != chunk {
                    break;
                }
                if cr3_switch_write(to_process, tva, scratch, chunk) != chunk {
                    break;
                }
                offset += chunk;
                continue;
            }

            let fphys = translate_linear_address(from_dtb, fva);
            if fphys == 0 {
                break;
            }

            let rstatus = read_physical(fphys, scratch, chunk);
            if rstatus < 0 {
                break;
            }

            let tphys = translate_linear_address(to_dtb, tva);
            if tphys == 0 {
                break;
            }

            let wstatus = write_physical(tphys, scratch, chunk);
            if wstatus < 0 {
                break;
            }

            offset += chunk;
        }

        secure_zero(scratch as *mut u8, PMEM_PAGE_SIZE);
        if !_EX_FREE_POOL_WITH_TAG.is_null() {
            let f: FnExFreePoolWithTag = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
            f(scratch, POOL_TAG_COPY);
        }

        offset
    }
}
