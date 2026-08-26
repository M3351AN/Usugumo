// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::ffi::*;
use crate::imports::{
    _ExAllocatePool2, _ExFreePoolWithTag, _MmAllocateContiguousMemory, _MmFreeContiguousMemory,
};
use crate::process::{G_USER_DIRECTORY_TABLE_BASE_OFFSET, init_offsets_by_version};
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

fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
    }
    cr3
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

fn current_processor_index() -> u32 {
    let idx: u32;
    unsafe {
        core::arch::asm!("mov eax, gs:[0x1C]", out("eax") idx, options(nostack));
    }
    idx
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
    unsafe {
        let cr3 = read_cr3() & !0xF;
        let pml4_index = (address >> 39) & 0x1FF;
        let pdpt_index = (address >> 30) & 0x1FF;
        let pd_index = (address >> 21) & 0x1FF;
        let pt_index = (address >> 12) & 0x1FF;

        let pml4_va = pmem_phys_to_va(cr3);
        if pml4_va.is_null() {
            return null_mut();
        }
        let pml4e = *(pml4_va as *const u64).add(pml4_index as usize);
        if pml4e & 1 == 0 {
            return null_mut();
        }

        let pdpt_va = pmem_phys_to_va(pml4e & PMEM_PMASK);
        if pdpt_va.is_null() {
            return null_mut();
        }
        let pdpte = *(pdpt_va as *const u64).add(pdpt_index as usize);
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
        let pde = *(pd_va as *const u64).add(pd_index as usize);
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
        let pte = (pt_va as *mut u64).add(pt_index as usize);
        if *pte & 1 == 0 {
            return null_mut();
        }
        pte
    }
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
            idx = (PMEM_MAX_CPU_PAGES - 1) as u32;
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

        let old_value = *page.pte_long;
        *page.pte_long = (old_value & !PMEM_PMASK) | page_start;
        mfence();
        invlpg(page.virtual_address as u64);

        let target = (page.virtual_address as *mut u8).add(page_offset);
        if write {
            kmemmove(target as *mut c_void, buffer, size);
        } else {
            kmemmove(buffer, target as *const c_void, size);
        }

        *page.pte_long = old_value;
        mfence();
        invlpg(page.virtual_address as u64);

        STATUS_SUCCESS
    }
}

pub fn read_physical(physical_address: u64, buffer: *mut c_void, size: usize) -> NtStatus {
    let status = pmem_swap_phys(physical_address, buffer, size, false);
    status
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
    unsafe {
        for i in 0..PMEM_MAX_CPU_PAGES {
            let va = if _MmAllocateContiguousMemory.is_null() {
                null_mut()
            } else {
                let f: FnMmAllocateContiguousMemory =
                    core::mem::transmute(_MmAllocateContiguousMemory);
                f(PMEM_PAGE_SIZE, u64::MAX)
            };
            if va.is_null() {
                cleanup_pmem_pages();
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            let pte = pmem_get_pte(va as u64);
            if pte.is_null() {
                if !_MmFreeContiguousMemory.is_null() {
                    let f: FnMmFreeContiguousMemory = core::mem::transmute(_MmFreeContiguousMemory);
                    f(va);
                }
                cleanup_pmem_pages();
                return STATUS_UNSUCCESSFUL;
            }
            G_PMEM_PAGES[i].virtual_address = va;
            G_PMEM_PAGES[i].pte_long = pte;
        }
        STATUS_SUCCESS
    }
}

pub fn cleanup_pmem_pages() {
    unsafe {
        for i in 0..PMEM_MAX_CPU_PAGES {
            if !G_PMEM_PAGES[i].virtual_address.is_null() {
                if !_MmFreeContiguousMemory.is_null() {
                    let f: FnMmFreeContiguousMemory = core::mem::transmute(_MmFreeContiguousMemory);
                    f(G_PMEM_PAGES[i].virtual_address);
                }
                G_PMEM_PAGES[i].virtual_address = null_mut();
                G_PMEM_PAGES[i].pte_long = null_mut();
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
    unsafe {
        let dtb = *(process as *const u64).add(0x28 / 8);
        if dtb != 0 {
            return dtb;
        }
        if G_USER_DIRECTORY_TABLE_BASE_OFFSET == 0 {
            if !init_offsets_by_version() {
                return 0;
            }
        }
        *(process as *const u64).add(G_USER_DIRECTORY_TABLE_BASE_OFFSET as usize / 8)
    }
}

pub fn read_process_memory(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *mut c_void,
    size: usize,
) -> NtStatus {
    unsafe {
        if process.is_null() || buffer.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let dtb = get_process_cr3(process);
        if dtb == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let irql = KzRaiseIrqlMeme(DISPATCH_LEVEL);
        let dst = buffer as *mut u8;
        let mut offset = 0usize;
        let mut status = STATUS_SUCCESS;
        while offset < size {
            let remaining = size - offset;
            let va = virtual_address + offset as u64;
            let mut chunk = PMEM_PAGE_SIZE - (va & (PMEM_PAGE_SIZE as u64 - 1)) as usize;
            if chunk > remaining {
                chunk = remaining;
            }

            let phys = translate_linear_address(dtb, va);
            if phys == 0 {
                status = STATUS_PARTIAL_COPY;
                break;
            }

            let rstatus = read_physical(phys, dst.add(offset) as *mut c_void, chunk);
            if rstatus < 0 {
                status = rstatus;
                break;
            }
            offset += chunk;
        }
        KzLowerIrqlMeme(irql);
        status
    }
}

pub fn copy_virtual_memory(
    from_process: *mut c_void,
    from_address: u64,
    to_process: *mut c_void,
    to_address: u64,
    size: usize,
) -> NtStatus {
    unsafe {
        if from_process.is_null() || to_process.is_null() || size == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let from_dtb = get_process_cr3(from_process);
        let to_dtb = get_process_cr3(to_process);
        if from_dtb == 0 || to_dtb == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let scratch = if _ExAllocatePool2.is_null() {
            null_mut()
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_ExAllocatePool2);
            f(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                PMEM_PAGE_SIZE,
                POOL_TAG_COPY,
            )
        };
        if scratch.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let mut status = STATUS_SUCCESS;
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

            let fphys = translate_linear_address(from_dtb, fva);
            if fphys == 0 {
                status = STATUS_PARTIAL_COPY;
                break;
            }

            let rstatus = read_physical(fphys, scratch, chunk);
            if rstatus < 0 {
                status = rstatus;
                break;
            }

            let tphys = translate_linear_address(to_dtb, tva);
            if tphys == 0 {
                status = STATUS_PARTIAL_COPY;
                break;
            }

            let wstatus = write_physical(tphys, scratch, chunk);
            if wstatus < 0 {
                status = wstatus;
                break;
            }

            offset += chunk;
        }

        secure_zero(scratch as *mut u8, PMEM_PAGE_SIZE);
        if !_ExFreePoolWithTag.is_null() {
            let f: FnExFreePoolWithTag = core::mem::transmute(_ExFreePoolWithTag);
            f(scratch, POOL_TAG_COPY);
        }

        status
    }
}
