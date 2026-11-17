// Copyright (c) 2026 渟雲. All rights reserved.

use crate::consts;
use crate::protocol;
use crate::transport::{Connection, TransportError};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemTimeAsFileTime(time: *mut u64);
    fn GetCurrentProcessId() -> u32;
}

pub(crate) struct Session {
    connection: Connection,
    target_pid: u64,
    current_pid: u64,
    driver_version: u16,
    supported: u16,
    hvci: bool,
    last_wire: protocol::Request,
}

impl Session {
    pub(crate) const fn new() -> Self {
        Self {
            connection: Connection::new(),
            target_pid: 0,
            current_pid: 0,
            driver_version: 0,
            supported: 0,
            hvci: false,
            last_wire: protocol::Request::new(),
        }
    }

    pub(crate) fn ensure_connected(&mut self) -> bool {
        self.connection.is_connected() || self.connection.connect()
    }

    pub(crate) fn last_error(&self) -> TransportError {
        self.connection.last_error()
    }

    pub(crate) fn last_wsa_error(&self) -> i32 {
        self.connection.last_wsa_error()
    }

    pub(crate) fn port(&self) -> u16 {
        self.connection.port()
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    pub(crate) fn target_pid(&self) -> u64 {
        self.target_pid
    }

    pub(crate) fn driver_version(&self) -> u16 {
        self.driver_version
    }

    pub(crate) fn supported(&self) -> u16 {
        self.supported
    }

    pub(crate) fn set_target_pid(&mut self, pid: u64) {
        self.target_pid = pid;
        self.current_pid = unsafe { GetCurrentProcessId() } as u64;
    }

    pub(crate) fn current_pid(&mut self) -> u64 {
        if self.current_pid == 0 {
            self.current_pid = unsafe { GetCurrentProcessId() } as u64;
        }
        self.current_pid
    }

    fn timestamp() -> u64 {
        let mut ft = 0u64;
        unsafe {
            GetSystemTimeAsFileTime(&mut ft);
        }
        ft
    }

    pub(crate) fn exchange(&mut self, request: protocol::Request) -> bool {
        if !self.connection.is_connected() {
            return false;
        }
        let mut outgoing = request;
        outgoing.version = protocol::PROTOCOL_VERSION;
        outgoing.timestamp = Self::timestamp();
        outgoing.secure_key = crate::SECURE_KEY;
        match self.connection.round_trip(&outgoing) {
            Some(reply) => {
                self.last_wire = reply;
                true
            }
            None => false,
        }
    }

    pub(crate) fn probe(&mut self) -> u64 {
        let mut request = protocol::Request::new();
        request.function = consts::USUGUMO_PROBE;
        if !self.exchange(request) {
            return 0;
        }
        let reply = self.last_wire.return_value;
        self.driver_version = ((reply >> consts::USUGUMO_PROTOCOL_VERSION_SHIFT) & 0xFFFF) as u16;
        self.supported = (reply & consts::USUGUMO_FUNC_BITS) as u16;
        self.hvci = reply & consts::USUGUMO_PROBE_HVCI_MASK != 0;
        reply
    }

    pub(crate) fn read_memory(&mut self, target_addr: u64, local_addr: u64, size: usize) -> u32 {
        self.memory_transfer(consts::USUGUMO_READ, target_addr, local_addr, size)
    }

    pub(crate) fn write_memory(&mut self, target_addr: u64, local_addr: u64, size: usize) -> u32 {
        self.memory_transfer(consts::USUGUMO_WRITE, target_addr, local_addr, size)
    }

    fn memory_transfer(
        &mut self,
        function: u64,
        target_addr: u64,
        local_addr: u64,
        size: usize,
    ) -> u32 {
        if self.target_pid == 0 || target_addr == 0 || local_addr == 0 || size == 0 {
            return 0;
        }
        let mut request = protocol::Request::new();
        request.function = function;
        request.request_pid = self.current_pid();
        request.request_addr = local_addr;
        request.target_pid = self.target_pid;
        request.target_addr = target_addr;
        request.size = size as u64;
        if self.exchange(request) {
            self.last_wire.return_value as u32
        } else {
            0
        }
    }

    fn named_query(&mut self, function: u64, name: &[u8]) -> u64 {
        let mut request = protocol::Request::new();
        request.function = function;
        request.target_pid = self.target_pid;
        request.set_name(name);
        if !self.exchange(request) {
            return 0;
        }
        self.last_wire.return_value
    }

    pub(crate) fn module_base(&mut self, name: &[u8]) -> u64 {
        self.named_query(consts::USUGUMO_MODULE_BASE, name)
    }

    pub(crate) fn module_size(&mut self, name: &[u8]) -> u64 {
        self.named_query(consts::USUGUMO_MODULE_SIZE, name)
    }

    pub(crate) fn process_id_by_name(&mut self, name: &[u8]) -> u64 {
        self.named_query(consts::USUGUMO_PID, name)
    }

    pub(crate) fn mouse_event(
        &mut self,
        flags: u32,
        dx: i32,
        dy: i32,
        data: u32,
        extra: u64,
    ) -> bool {
        let mut request = protocol::Request::new();
        request.function = consts::USUGUMO_MOUSE;
        request.flags = flags;
        request.dx = dx as u32;
        request.dy = dy as u32;
        request.data = data;
        request.extra = extra;
        self.exchange(request)
    }

    pub(crate) fn keybd_event(&mut self, vk: u8, scan: u8, flags: u32, extra: u64) -> bool {
        let mut request = protocol::Request::new();
        request.function = consts::USUGUMO_KEYBD;
        request.vk = vk as u16;
        request.scan = scan as u16;
        request.flags = flags;
        request.extra = extra;
        self.exchange(request)
    }

    pub(crate) fn anti_capture(&mut self, window: u64, enable: bool) -> bool {
        let mut request = protocol::Request::new();
        request.function = consts::USUGUMO_ANTI_CAPTURE;
        request.request_pid = self.current_pid();
        request.window = window;
        request.protect = if enable { 0xFFFF_FFFF } else { 0 };
        self.exchange(request)
    }
}
