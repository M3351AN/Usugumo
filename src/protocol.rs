// Copyright (c) 2026 渟雲. All rights reserved.

use crate::text;

pub const PROTOCOL_VERSION: u64 = 2;
pub const LENGTH_PREFIX_SIZE: usize = 4;
pub const MAX_FRAME_SIZE: usize = 1024;

pub const TAG_VERSION: [u8; 8] = text::key_of("v");
pub const TAG_FUNCTION: [u8; 8] = text::key_of("fn");
pub const TAG_RETURN: [u8; 8] = text::key_of("ret");
pub const TAG_CHECKSUM: [u8; 8] = text::key_of("ck");
pub const TAG_TIMESTAMP: [u8; 8] = text::key_of("ts");
pub const TAG_SECURE_KEY: [u8; 8] = text::key_of("sk");
pub const TAG_REQUEST_PID: [u8; 8] = text::key_of("rpid");
pub const TAG_REQUEST_ADDR: [u8; 8] = text::key_of("raddr");
pub const TAG_TARGET_PID: [u8; 8] = text::key_of("tpid");
pub const TAG_TARGET_ADDR: [u8; 8] = text::key_of("taddr");
pub const TAG_SIZE: [u8; 8] = text::key_of("sz");
pub const TAG_FLAGS: [u8; 8] = text::key_of("fl");
pub const TAG_DX: [u8; 8] = text::key_of("dx");
pub const TAG_DY: [u8; 8] = text::key_of("dy");
pub const TAG_DATA: [u8; 8] = text::key_of("dd");
pub const TAG_EXTRA: [u8; 8] = text::key_of("ex");
pub const TAG_VK: [u8; 8] = text::key_of("vk");
pub const TAG_SCAN: [u8; 8] = text::key_of("sc");
pub const TAG_NAME: [u8; 8] = text::key_of("nm");
pub const TAG_WINDOW: [u8; 8] = text::key_of("wh");
pub const TAG_PROTECT: [u8; 8] = text::key_of("pf");

#[derive(Clone, Copy)]
pub struct Request {
    pub version: u64,
    pub function: u64,
    pub return_value: u64,
    pub checksum: u64,
    pub timestamp: u64,
    pub secure_key: u64,
    pub request_pid: u64,
    pub request_addr: u64,
    pub target_pid: u64,
    pub target_addr: u64,
    pub size: u64,
    pub flags: u32,
    pub dx: u32,
    pub dy: u32,
    pub data: u32,
    pub extra: u64,
    pub vk: u16,
    pub scan: u16,
    pub window: u64,
    pub protect: u32,
    name_len: usize,
    name: [u8; 64],
}

impl Request {
    pub const fn new() -> Self {
        Self {
            version: 0,
            function: 0,
            return_value: 0,
            checksum: 0,
            timestamp: 0,
            secure_key: 0,
            request_pid: 0,
            request_addr: 0,
            target_pid: 0,
            target_addr: 0,
            size: 0,
            flags: 0,
            dx: 0,
            dy: 0,
            data: 0,
            extra: 0,
            vk: 0,
            scan: 0,
            window: 0,
            protect: 0,
            name_len: 0,
            name: [0u8; 64],
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn set_name(&mut self, value: &[u8]) {
        let n = value.len().min(self.name.len());
        self.name[..n].copy_from_slice(&value[..n]);
        self.name_len = n;
    }

    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut r = Self::new();
        r.version = text::find_u64_by_tag(body, &TAG_VERSION)?;
        r.function = text::find_u64_by_tag(body, &TAG_FUNCTION).unwrap_or(0);
        r.return_value = text::find_u64_by_tag(body, &TAG_RETURN).unwrap_or(0);
        r.checksum = text::find_u64_by_tag(body, &TAG_CHECKSUM).unwrap_or(0);
        r.timestamp = text::find_u64_by_tag(body, &TAG_TIMESTAMP).unwrap_or(0);
        r.secure_key = text::find_u64_by_tag(body, &TAG_SECURE_KEY).unwrap_or(0);
        r.request_pid = text::find_u64_by_tag(body, &TAG_REQUEST_PID).unwrap_or(0);
        r.request_addr = text::find_u64_by_tag(body, &TAG_REQUEST_ADDR).unwrap_or(0);
        r.target_pid = text::find_u64_by_tag(body, &TAG_TARGET_PID).unwrap_or(0);
        r.target_addr = text::find_u64_by_tag(body, &TAG_TARGET_ADDR).unwrap_or(0);
        r.size = text::find_u64_by_tag(body, &TAG_SIZE).unwrap_or(0);
        r.flags = text::find_u64_by_tag(body, &TAG_FLAGS).unwrap_or(0) as u32;
        r.dx = text::find_u64_by_tag(body, &TAG_DX).unwrap_or(0) as u32;
        r.dy = text::find_u64_by_tag(body, &TAG_DY).unwrap_or(0) as u32;
        r.data = text::find_u64_by_tag(body, &TAG_DATA).unwrap_or(0) as u32;
        r.extra = text::find_u64_by_tag(body, &TAG_EXTRA).unwrap_or(0);
        r.vk = text::find_u64_by_tag(body, &TAG_VK).unwrap_or(0) as u16;
        r.scan = text::find_u64_by_tag(body, &TAG_SCAN).unwrap_or(0) as u16;
        r.window = text::find_u64_by_tag(body, &TAG_WINDOW).unwrap_or(0);
        r.protect = text::find_u64_by_tag(body, &TAG_PROTECT).unwrap_or(0) as u32;
        if let Some(name) = text::find_by_tag(body, &TAG_NAME) {
            r.set_name(name);
        }
        Some(r)
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let mut w = text::Writer::new(buf);
        w.u64(&TAG_VERSION, self.version);
        w.u64(&TAG_FUNCTION, self.function);
        w.u64(&TAG_RETURN, self.return_value);
        w.u64(&TAG_CHECKSUM, self.checksum);
        w.u64(&TAG_TIMESTAMP, self.timestamp);
        w.u64(&TAG_SECURE_KEY, self.secure_key);
        if self.request_pid != 0 {
            w.u64(&TAG_REQUEST_PID, self.request_pid);
        }
        if self.request_addr != 0 {
            w.u64(&TAG_REQUEST_ADDR, self.request_addr);
        }
        if self.target_pid != 0 {
            w.u64(&TAG_TARGET_PID, self.target_pid);
        }
        if self.target_addr != 0 {
            w.u64(&TAG_TARGET_ADDR, self.target_addr);
        }
        if self.size != 0 {
            w.u64(&TAG_SIZE, self.size);
        }
        if self.flags != 0 {
            w.u64(&TAG_FLAGS, self.flags as u64);
        }
        if self.dx != 0 {
            w.u64(&TAG_DX, self.dx as u64);
        }
        if self.dy != 0 {
            w.u64(&TAG_DY, self.dy as u64);
        }
        if self.data != 0 {
            w.u64(&TAG_DATA, self.data as u64);
        }
        if self.extra != 0 {
            w.u64(&TAG_EXTRA, self.extra);
        }
        if self.vk != 0 {
            w.u64(&TAG_VK, self.vk as u64);
        }
        if self.scan != 0 {
            w.u64(&TAG_SCAN, self.scan as u64);
        }
        if self.window != 0 {
            w.u64(&TAG_WINDOW, self.window);
        }
        if self.protect != 0 {
            w.u64(&TAG_PROTECT, self.protect as u64);
        }
        if self.name_len != 0 {
            w.bytes(&TAG_NAME, self.name());
        }
        w.finish()
    }
}

pub fn write_length_prefix(buf: &mut [u8], payload_len: usize) -> bool {
    if buf.len() < LENGTH_PREFIX_SIZE || payload_len > MAX_FRAME_SIZE {
        return false;
    }
    buf[..LENGTH_PREFIX_SIZE].copy_from_slice(&(payload_len as u32).to_le_bytes());
    true
}

pub fn read_length_prefix(buf: &[u8]) -> Option<usize> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return None;
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n == 0 || n > MAX_FRAME_SIZE {
        None
    } else {
        Some(n)
    }
}

pub fn compute_checksum(payload: &[u8]) -> u64 {
    crate::helpers::crc64(payload)
}

pub fn request_from_wire(wire: &Request) -> crate::types::Requests {
    let mut out: crate::types::Requests = unsafe { core::mem::zeroed() };
    out.request_key = wire.function | crate::consts::USUGUMO_SIGNATURE_MASK;
    out.return_value = wire.return_value;
    out.request_pid = wire.request_pid;
    out.request_addr = wire.request_addr;
    out.target_pid = wire.target_pid;
    out.target_addr = wire.target_addr;
    out.mem_size = wire.size;
    out.dw_flags = wire.flags;
    out.dx = wire.dx;
    out.dy = wire.dy;
    out.dw_data = wire.data;
    out.dw_extra_info = wire.extra;
    out.b_vk = wire.vk;
    out.b_scan = wire.scan;
    out.window_handle = wire.window as usize;
    out.protect_flags = wire.protect;
    out.time_stamp = wire.timestamp;
    out.secure_key = wire.secure_key;
    out.check_sum = wire.checksum;
    let name = wire.name();
    out.name_length = name.len() as u64;
    crate::helpers::encode_fixed_str64(name, &mut out.name_str);
    out
}

pub fn request_to_wire(req: &crate::types::Requests) -> Request {
    let mut wire = Request::new();
    wire.version = PROTOCOL_VERSION;
    wire.function = req.request_key & crate::consts::USUGUMO_FUNC_BITS;
    wire.return_value = req.return_value;
    wire.checksum = req.check_sum;
    wire.timestamp = req.time_stamp;
    wire.secure_key = req.secure_key;
    wire.request_pid = req.request_pid;
    wire.request_addr = req.request_addr;
    wire.target_pid = req.target_pid;
    wire.target_addr = req.target_addr;
    wire.size = req.mem_size;
    wire.flags = req.dw_flags;
    wire.dx = req.dx;
    wire.dy = req.dy;
    wire.data = req.dw_data;
    wire.extra = req.dw_extra_info;
    wire.vk = req.b_vk;
    wire.scan = req.b_scan;
    wire.window = req.window_handle as u64;
    wire.protect = req.protect_flags;
    if req.name_length != 0 {
        let mut decoded = [0u8; 64];
        crate::helpers::decode_fixed_str64(
            &req.name_str,
            decoded.as_mut_ptr() as *mut i8,
            req.name_length,
        );
        let n = (req.name_length as usize).min(64);
        wire.set_name(&decoded[..n]);
    }
    wire
}
