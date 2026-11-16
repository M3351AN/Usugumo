// Copyright (c) 2026 渟雲. All rights reserved.

use std::ffi::{c_char, c_void};

pub(crate) const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const PROCESS_BASIC_INFORMATION: u32 = 0;
const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const PAGE_READWRITE: u32 = 0x04;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

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
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    _pad0: u32,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    _pad1: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ListEntry {
    flink: usize,
    blink: usize,
}

#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u8,
    _pad0: [u8; 3],
    ss_handle: usize,
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    spare: u8,
    _pad0: u32,
    mutant: usize,
    image_base_address: usize,
    ldr: usize,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: usize,
    entry_point: usize,
    size_of_image: u32,
    _pad0: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    _working_set_private_size: usize,
    _hard_fault_count: u32,
    _threads_high_watermark: u32,
    _cycle_time: u64,
    _create_time: usize,
    _user_time: usize,
    _kernel_time: usize,
    image_name: UnicodeString,
    _base_priority: u32,
    _pad0: u32,
    process_id: usize,
    _inherited_from_process_id: usize,
}

#[repr(C)]
struct MouseInput {
    dx: i32,
    dy: i32,
    mouse_data: u32,
    flags: u32,
    time: u32,
    _pad0: u32,
    extra_info: usize,
}

#[repr(C)]
struct KeybdInput {
    vk: u16,
    scan: u16,
    flags: u32,
    time: u32,
    _pad0: u32,
    extra_info: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenProcess(
        handle: *mut usize,
        access: u32,
        attributes: *mut ObjectAttributes,
        client_id: *mut ClientId,
    ) -> i32;
    fn NtReadVirtualMemory(
        process: usize,
        base: *mut c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn NtWriteVirtualMemory(
        process: usize,
        base: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn NtProtectVirtualMemory(
        process: usize,
        base: *mut *mut c_void,
        size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    fn NtQueryInformationProcess(
        process: usize,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> i32;
    fn NtClose(handle: usize) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> usize;
    fn GetProcAddress(module: usize, name: *const c_char) -> *mut c_void;
    fn GetModuleHandleA(name: *const c_char) -> usize;
    fn VirtualAlloc(address: *mut c_void, size: usize, ty: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, ty: u32) -> i32;
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

pub(crate) struct Native {
    handle: usize,
    pid: u64,
}

impl Native {
    pub(crate) const fn new() -> Self {
        Self { handle: 0, pid: 0 }
    }

    pub(crate) fn pid(&self) -> u64 {
        self.pid
    }

    pub(crate) fn raw_handle(&self) -> usize {
        self.handle
    }

    pub(crate) fn adopt_handle(&mut self, handle: usize) -> bool {
        if handle == 0 {
            return false;
        }
        self.close();
        self.handle = handle;
        true
    }

    pub(crate) fn close(&mut self) {
        if self.handle != 0 {
            unsafe {
                NtClose(self.handle);
            }
            self.handle = 0;
        }
        self.pid = 0;
    }

    pub(crate) fn open_by_pid(&mut self, pid: u64, access: u32) -> bool {
        if self.handle != 0 && self.pid == pid {
            return true;
        }
        self.close();
        if pid == 0 {
            return false;
        }

        let mut name = [0u16; 1];
        let mut attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let _ = &mut name;
        let mut client_id = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };
        let mut handle = 0usize;
        let status = unsafe { NtOpenProcess(&mut handle, access, &mut attributes, &mut client_id) };
        if status < 0 || handle == 0 {
            return false;
        }
        self.handle = handle;
        self.pid = pid;
        true
    }

    pub(crate) fn open_by_name(&mut self, name: &[u16], access: u32) -> bool {
        let pid = Self::process_id_by_name(name);
        if pid == 0 {
            return false;
        }
        self.open_by_pid(pid, access)
    }

    pub(crate) fn read(&self, address: u64, buffer: *mut c_void, size: usize) -> u32 {
        if self.handle == 0 || address == 0 || buffer.is_null() || size == 0 {
            return 0;
        }
        let mut read = 0usize;
        let status = unsafe {
            NtReadVirtualMemory(self.handle, address as *mut c_void, buffer, size, &mut read)
        };
        if status >= 0 { read as u32 } else { 0 }
    }

    pub(crate) fn write(&self, address: u64, buffer: *const c_void, size: usize) -> u32 {
        if self.handle == 0 || address == 0 || buffer.is_null() || size == 0 {
            return 0;
        }
        let mut base = address as *mut c_void;
        let mut region = size;
        let mut old_protect = 0u32;
        let status = unsafe {
            NtProtectVirtualMemory(
                self.handle,
                &mut base,
                &mut region,
                PAGE_READWRITE,
                &mut old_protect,
            )
        };
        if status < 0 {
            return 0;
        }

        let mut written = 0usize;
        let status = unsafe {
            NtWriteVirtualMemory(
                self.handle,
                address as *mut c_void,
                buffer,
                size,
                &mut written,
            )
        };

        let mut restore = address as *mut c_void;
        let mut restore_size = size;
        let mut ignored = 0u32;
        unsafe {
            NtProtectVirtualMemory(
                self.handle,
                &mut restore,
                &mut restore_size,
                old_protect,
                &mut ignored,
            );
        }

        if status >= 0 { written as u32 } else { 0 }
    }

    fn peb(&self) -> Option<Peb> {
        if self.handle == 0 {
            return None;
        }
        let mut info = ProcessBasicInformation {
            exit_status: 0,
            _pad0: 0,
            peb_base_address: 0,
            affinity_mask: 0,
            base_priority: 0,
            _pad1: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: 0,
        };
        let mut ret_len = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                PROCESS_BASIC_INFORMATION,
                &mut info as *mut ProcessBasicInformation as *mut c_void,
                core::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        if status < 0 || info.peb_base_address == 0 {
            return None;
        }
        let mut peb = Peb {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            spare: 0,
            _pad0: 0,
            mutant: 0,
            image_base_address: 0,
            ldr: 0,
        };
        if self.read(
            info.peb_base_address as u64,
            &mut peb as *mut Peb as *mut c_void,
            core::mem::size_of::<Peb>(),
        ) as usize
            != core::mem::size_of::<Peb>()
        {
            return None;
        }
        Some(peb)
    }

    fn find_ldr_entry(&self, name: &[u16]) -> Option<LdrDataTableEntry> {
        let peb = self.peb()?;
        if peb.ldr == 0 {
            return None;
        }

        let mut ldr = PebLdrData {
            length: 0,
            initialized: 0,
            _pad0: [0; 3],
            ss_handle: 0,
            in_load_order_module_list: ListEntry { flink: 0, blink: 0 },
        };
        if self.read(
            peb.ldr as u64,
            &mut ldr as *mut PebLdrData as *mut c_void,
            core::mem::size_of::<PebLdrData>(),
        ) as usize
            != core::mem::size_of::<PebLdrData>()
        {
            return None;
        }

        let head = peb.ldr + core::mem::offset_of!(PebLdrData, in_load_order_module_list);
        let mut cursor = ldr.in_load_order_module_list.flink;
        let mut guard = 0usize;
        let entry_size = core::mem::size_of::<LdrDataTableEntry>();
        let mut entry = LdrDataTableEntry {
            in_load_order_links: ListEntry { flink: 0, blink: 0 },
            in_memory_order_links: ListEntry { flink: 0, blink: 0 },
            in_initialization_order_links: ListEntry { flink: 0, blink: 0 },
            dll_base: 0,
            entry_point: 0,
            size_of_image: 0,
            _pad0: 0,
            full_dll_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: std::ptr::null_mut(),
            },
            base_dll_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: std::ptr::null_mut(),
            },
        };

        while cursor != 0 && cursor != head && guard < 0x1000 {
            guard += 1;
            if self.read(
                cursor as u64,
                &mut entry as *mut LdrDataTableEntry as *mut c_void,
                entry_size,
            ) as usize
                != entry_size
            {
                return None;
            }

            if !entry.base_dll_name.buffer.is_null() && entry.base_dll_name.length > 0 {
                let chars = (entry.base_dll_name.length / 2) as usize;
                let chars = chars.min(64);
                let mut current = [0u16; 64];
                if self.read(
                    entry.base_dll_name.buffer as u64,
                    current.as_mut_ptr() as *mut c_void,
                    chars * 2,
                ) as usize
                    == chars * 2
                    && wide_equals(&current[..chars], name)
                {
                    return Some(entry);
                }
            }

            cursor = entry.in_load_order_links.flink;
        }
        None
    }

    pub(crate) fn module_base(&self, name: &[u16]) -> u64 {
        self.find_ldr_entry(name)
            .map(|e| e.dll_base as u64)
            .unwrap_or(0)
    }

    pub(crate) fn module_size(&self, name: &[u16]) -> u64 {
        self.find_ldr_entry(name)
            .map(|e| e.size_of_image as u64)
            .unwrap_or(0)
    }

    pub(crate) fn process_id_by_name(name: &[u16]) -> u64 {
        let mut size = 0x10000u32;
        loop {
            let buffer = unsafe {
                VirtualAlloc(
                    std::ptr::null_mut(),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if buffer.is_null() {
                return 0;
            }

            let mut ret_len = 0u32;
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_PROCESS_INFORMATION_CLASS,
                    buffer,
                    size,
                    &mut ret_len,
                )
            };

            if status == STATUS_INFO_LENGTH_MISMATCH {
                unsafe {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                if size >= 0x1000_0000 {
                    return 0;
                }
                size = size.saturating_mul(2);
                continue;
            }

            if status < 0 {
                unsafe {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return 0;
            }

            let mut found = 0u64;
            let mut cursor = buffer as *const u8;
            loop {
                let entry = unsafe { &*(cursor as *const SystemProcessInformation) };
                if !entry.image_name.buffer.is_null() && entry.process_id != 0 {
                    let chars = ((entry.image_name.length / 2) as usize).min(64);
                    let mut name_buf = [0u16; 64];
                    name_buf[..chars].copy_from_slice(unsafe {
                        core::slice::from_raw_parts(entry.image_name.buffer, chars)
                    });
                    if wide_equals(&name_buf[..chars], name) {
                        found = entry.process_id as u64;
                        break;
                    }
                }
                if entry.next_entry_offset == 0 {
                    break;
                }
                cursor = unsafe { cursor.add(entry.next_entry_offset as usize) };
            }

            unsafe {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            return found;
        }
    }

    pub(crate) fn mouse_event(
        &mut self,
        flags: u32,
        dx: i32,
        dy: i32,
        data: u32,
        extra: u64,
    ) -> bool {
        let inject = match nt_user_inject_mouse_input() {
            Some(f) => f,
            None => return false,
        };
        let mut input = MouseInput {
            dx,
            dy,
            mouse_data: data,
            flags,
            time: 0,
            _pad0: 0,
            extra_info: extra as usize,
        };
        unsafe { inject(&mut input, 1) }
    }

    pub(crate) fn keybd_event(&mut self, vk: u8, scan: u8, flags: u32, extra: u64) -> bool {
        let inject = match nt_user_inject_keyboard_input() {
            Some(f) => f,
            None => return false,
        };
        let mut input = KeybdInput {
            vk: vk as u16,
            scan: scan as u16,
            flags,
            time: 0,
            _pad0: 0,
            extra_info: extra as usize,
        };
        unsafe { inject(&mut input, 1) };
        true
    }

    pub(crate) fn anti_capture(&mut self, window: u64, enable: bool) -> bool {
        let affinity = match nt_user_set_window_display_affinity() {
            Some(f) => f,
            None => return false,
        };
        unsafe { affinity(window as usize, if enable { 0x11 } else { 0 }) != 0 }
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn wide_equals(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(&x, &y)| {
        let mut x = x;
        let mut y = y;
        if (65..=90).contains(&x) {
            x += 32;
        }
        if (65..=90).contains(&y) {
            y += 32;
        }
        x == y
    })
}

pub(crate) fn to_wide(text: &[u8]) -> Vec<u16> {
    text.iter().map(|&c| c as u16).collect()
}

fn resolve(module: usize, name: &[u8]) -> *mut c_void {
    if module == 0 {
        return std::ptr::null_mut();
    }
    let mut buffer = [0u8; 64];
    let n = name.len().min(buffer.len() - 1);
    buffer[..n].copy_from_slice(&name[..n]);
    unsafe { GetProcAddress(module, buffer.as_ptr() as *const c_char) }
}

fn win32u_module() -> usize {
    let name: Vec<u16> = "win32u.dll\0".encode_utf16().collect();
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    if module != 0 {
        return module;
    }
    let fallback = b"win32u.dll\0";
    unsafe { GetModuleHandleA(fallback.as_ptr() as *const c_char) }
}

type InjectMouse = unsafe extern "system" fn(*mut MouseInput, i32) -> bool;
type InjectKeybd = unsafe extern "system" fn(*mut KeybdInput, i32);
type SetAffinity = unsafe extern "system" fn(usize, u32) -> i32;

fn nt_user_inject_mouse_input() -> Option<InjectMouse> {
    let p = resolve(win32u_module(), b"NtUserInjectMouseInput\0");
    if p.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut c_void, InjectMouse>(p) })
    }
}

fn nt_user_inject_keyboard_input() -> Option<InjectKeybd> {
    let p = resolve(win32u_module(), b"NtUserInjectKeyboardInput\0");
    if p.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut c_void, InjectKeybd>(p) })
    }
}

fn nt_user_set_window_display_affinity() -> Option<SetAffinity> {
    let p = resolve(win32u_module(), b"NtUserSetWindowDisplayAffinity\0");
    if p.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut c_void, SetAffinity>(p) })
    }
}
