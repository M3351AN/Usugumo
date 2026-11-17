// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::consts::*;
use crate::imports::{
    _EX_ALLOCATE_POOL2, _EX_FREE_POOL_WITH_TAG, _KE_STACK_ATTACH_PROCESS,
    _KE_UNSTACK_DETACH_PROCESS, _MM_ALLOCATE_CONTIGUOUS_MEMORY, _MM_FREE_CONTIGUOUS_MEMORY,
    _MM_MAP_LOCKED_PAGES_SPECIFY_CACHE, _MM_PROBE_AND_LOCK_PAGES, _MM_SIZE_OF_MDL,
    _MM_UNLOCK_PAGES, _MM_UNMAP_LOCKED_PAGES,
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

// -1 unknown, 0 off, 1 on
static mut G_HVCI_STATE: i8 = -1;

pub(crate) fn hvci_status() -> i8 {
    unsafe {
        if G_HVCI_STATE >= 0 {
            G_HVCI_STATE
        } else {
            // Direct page-table manipulation (the pmem page-walk path) cannot
            // be initialized under HVCI, so a failed init implies HVCI.
            let pagewalk_ok = init_pmem_pages() == STATUS_SUCCESS;
            G_HVCI_STATE = if pagewalk_ok { 0 } else { 1 };
            G_HVCI_STATE
        }
    }
}

pub(crate) fn hvci_enabled() -> bool {
    hvci_status() == 1
}

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
            return STATUS_UNSUCCESSFUL;
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

const MDL_COPY_PAGES: usize = 14;

type FnMmSizeOfMdl = unsafe extern "system" fn(*const c_void, usize) -> usize;
type FnMmProbeAndLockPages = unsafe extern "system" fn(*mut c_void, u8, u32);
type FnMmUnlockPages = unsafe extern "system" fn(*mut c_void);
type FnMmUnmapLockedPages = unsafe extern "system" fn(*mut c_void, *mut c_void);
type FnMmMapLockedPagesSpecifyCache =
    unsafe extern "system" fn(*mut c_void, u8, i32, *mut c_void, u8, i32) -> *mut c_void;
type FnKeStackAttachProcess = unsafe extern "system" fn(*mut c_void, *mut c_void);
type FnKeUnstackDetachProcess = unsafe extern "system" fn(*mut c_void);

// MmInitializeMdl is a header macro, not a kernel export. Field offsets follow
// the kernel _MDL layout: Size@0x08, MdlFlags@0x0a, MappedSystemVa@0x18,
// StartVa@0x20, ByteCount@0x28, ByteOffset@0x2c.
#[inline]
unsafe fn init_mdl_header(mdl: *mut c_void, base_va: *mut c_void, length: usize) {
    const MDL_SIZE: u16 = 0x30;
    unsafe {
        let b = mdl as *mut u8;
        let va = base_va as usize;
        core::ptr::write_volatile(b.add(0x08) as *mut u16, MDL_SIZE);
        core::ptr::write_volatile(b.add(0x0a) as *mut u16, 0);
        core::ptr::write_volatile(b.add(0x20) as *mut u64, (va & !(PMEM_PAGE_SIZE - 1)) as u64);
        core::ptr::write_volatile(b.add(0x28) as *mut u32, length as u32);
        core::ptr::write_volatile(b.add(0x2c) as *mut u32, (va & (PMEM_PAGE_SIZE - 1)) as u32);
    }
}

fn mdl_map_payload(mdl: *mut c_void) -> *mut c_void {
    unsafe {
        if _MM_MAP_LOCKED_PAGES_SPECIFY_CACHE.is_null() {
            return core::ptr::null_mut();
        }
        let f: FnMmMapLockedPagesSpecifyCache =
            core::mem::transmute(_MM_MAP_LOCKED_PAGES_SPECIFY_CACHE);
        f(mdl, 0, 1, core::ptr::null_mut(), 0, 2)
    }
}

fn mdl_unmap(mapped: *mut c_void, mdl: *mut c_void) {
    unsafe {
        if !_MM_UNMAP_LOCKED_PAGES.is_null() {
            let f: FnMmUnmapLockedPages = core::mem::transmute(_MM_UNMAP_LOCKED_PAGES);
            f(mapped, mdl);
        }
    }
}

fn mdl_unlock(mdl: *mut c_void) {
    unsafe {
        if !_MM_UNLOCK_PAGES.is_null() {
            let f: FnMmUnlockPages = core::mem::transmute(_MM_UNLOCK_PAGES);
            f(mdl);
        }
    }
}

fn mdl_read_into(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *mut c_void,
    size: usize,
) -> usize {
    unsafe {
        if process.is_null() || buffer.is_null() || size == 0 {
            return 0;
        }
        if !is_user_address(virtual_address, size) {
            return 0;
        }
        if _MM_SIZE_OF_MDL.is_null()
            || _MM_PROBE_AND_LOCK_PAGES.is_null()
            || _KE_STACK_ATTACH_PROCESS.is_null()
            || _KE_UNSTACK_DETACH_PROCESS.is_null()
        {
            return 0;
        }

        let size_of_mdl: FnMmSizeOfMdl = core::mem::transmute(_MM_SIZE_OF_MDL);
        let probe_lock: FnMmProbeAndLockPages = core::mem::transmute(_MM_PROBE_AND_LOCK_PAGES);
        let stack_attach: FnKeStackAttachProcess = core::mem::transmute(_KE_STACK_ATTACH_PROCESS);
        let stack_detach: FnKeUnstackDetachProcess =
            core::mem::transmute(_KE_UNSTACK_DETACH_PROCESS);

        let max_chunk = MDL_COPY_PAGES * PMEM_PAGE_SIZE;
        let mdl_size = size_of_mdl(virtual_address as *const c_void, max_chunk);
        if mdl_size == 0 {
            return 0;
        }
        let mdl = if _EX_ALLOCATE_POOL2.is_null() {
            return 0;
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_EX_ALLOCATE_POOL2);
            f(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                mdl_size,
                POOL_TAG_COPY,
            )
        };
        if mdl.is_null() {
            return 0;
        }

        let dst = buffer as *mut u8;
        let mut offset = 0usize;
        let mut apc_state = [0u8; 0x40];
        while offset < size {
            let remaining = size - offset;
            let va = virtual_address + offset as u64;
            let mut chunk = MDL_COPY_PAGES * PMEM_PAGE_SIZE;
            if chunk > remaining {
                chunk = remaining;
            }

            stack_attach(process, apc_state.as_mut_ptr() as *mut c_void);
            if !is_range_mapped(va, chunk) {
                stack_detach(apc_state.as_mut_ptr() as *mut c_void);
                offset += chunk;
                continue;
            }
            init_mdl_header(mdl, va as *mut c_void, chunk);
            probe_lock(mdl, 1, 0); // UserMode, IoReadAccess
            stack_detach(apc_state.as_mut_ptr() as *mut c_void);

            let mapped = mdl_map_payload(mdl);
            if mapped.is_null() {
                mdl_unlock(mdl);
                break;
            }
            crate::util::kmemmove(
                dst.add(offset) as *mut c_void,
                mapped as *const c_void,
                chunk,
            );
            mdl_unmap(mapped, mdl);
            mdl_unlock(mdl);

            offset += chunk;
        }

        if !_EX_FREE_POOL_WITH_TAG.is_null() {
            let f: FnExFreePoolWithTag = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
            f(mdl, POOL_TAG_COPY);
        }
        offset
    }
}

fn mdl_write_from(
    process: *mut c_void,
    virtual_address: u64,
    buffer: *const c_void,
    size: usize,
) -> usize {
    unsafe {
        if process.is_null() || buffer.is_null() || size == 0 {
            return 0;
        }
        if !is_user_address(virtual_address, size) {
            return 0;
        }
        if _MM_SIZE_OF_MDL.is_null()
            || _MM_PROBE_AND_LOCK_PAGES.is_null()
            || _KE_STACK_ATTACH_PROCESS.is_null()
            || _KE_UNSTACK_DETACH_PROCESS.is_null()
        {
            return 0;
        }

        let size_of_mdl: FnMmSizeOfMdl = core::mem::transmute(_MM_SIZE_OF_MDL);
        let probe_lock: FnMmProbeAndLockPages = core::mem::transmute(_MM_PROBE_AND_LOCK_PAGES);
        let stack_attach: FnKeStackAttachProcess = core::mem::transmute(_KE_STACK_ATTACH_PROCESS);
        let stack_detach: FnKeUnstackDetachProcess =
            core::mem::transmute(_KE_UNSTACK_DETACH_PROCESS);

        let max_chunk = MDL_COPY_PAGES * PMEM_PAGE_SIZE;
        let mdl_size = size_of_mdl(virtual_address as *const c_void, max_chunk);
        if mdl_size == 0 {
            return 0;
        }
        let mdl = if _EX_ALLOCATE_POOL2.is_null() {
            return 0;
        } else {
            let f: FnExAllocatePool2 = core::mem::transmute(_EX_ALLOCATE_POOL2);
            f(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
                mdl_size,
                POOL_TAG_COPY,
            )
        };
        if mdl.is_null() {
            return 0;
        }

        let src = buffer as *const u8;
        let mut offset = 0usize;
        let mut apc_state = [0u8; 0x40];
        while offset < size {
            let remaining = size - offset;
            let va = virtual_address + offset as u64;
            let mut chunk = MDL_COPY_PAGES * PMEM_PAGE_SIZE;
            if chunk > remaining {
                chunk = remaining;
            }

            stack_attach(process, apc_state.as_mut_ptr() as *mut c_void);
            if !is_range_mapped(va, chunk) {
                stack_detach(apc_state.as_mut_ptr() as *mut c_void);
                offset += chunk;
                continue;
            }
            init_mdl_header(mdl, va as *mut c_void, chunk);
            probe_lock(mdl, 1, 1); // UserMode, IoWriteAccess
            stack_detach(apc_state.as_mut_ptr() as *mut c_void);

            let mapped = mdl_map_payload(mdl);
            if mapped.is_null() {
                mdl_unlock(mdl);
                break;
            }
            crate::util::kmemmove(mapped, src.add(offset) as *const c_void, chunk);
            mdl_unmap(mapped, mdl);
            mdl_unlock(mdl);

            offset += chunk;
        }

        if !_EX_FREE_POOL_WITH_TAG.is_null() {
            let f: FnExFreePoolWithTag = core::mem::transmute(_EX_FREE_POOL_WITH_TAG);
            f(mdl, POOL_TAG_COPY);
        }
        offset
    }
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
            return mdl_read_into(process, virtual_address, buffer, size);
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

type FnMmIsAddressValid = unsafe extern "system" fn(u64) -> u8;

// Must only be called after attaching to the target process: MmIsAddressValid
// resolves against the current address space.
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
                if mdl_read_into(from_process, fva, scratch, chunk) != chunk {
                    break;
                }
                if mdl_write_from(to_process, tva, scratch, chunk) != chunk {
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
