// Copyright (c) 2026 渟雲. All rights reserved.

use std::ffi::c_void;

use crate::protocol;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;

pub(crate) const WSAECONNREFUSED: i32 = 10061;
pub(crate) const WSAETIMEDOUT: i32 = 10060;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut c_void) -> i32;
    fn WSACleanup() -> i32;
    fn socket(af: i32, ty: i32, protocol: i32) -> usize;
    fn connect(s: usize, name: *const SockAddrIn, namelen: i32) -> i32;
    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
    fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn WSAGetLastError() -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemWindowsDirectoryA(buf: *mut u8, len: u32) -> u32;
    fn GetVolumeInformationA(
        root: *const u8,
        label: *mut u8,
        label_len: u32,
        serial: *mut u32,
        max_component_len: *mut u32,
        flags: *mut u32,
        fs_name: *mut u8,
        fs_name_len: u32,
    ) -> i32;
}

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    None = 0,
    WsaStartup = 1,
    PortDerive = 2,
    Socket = 3,
    ConnectRefused = 4,
    ConnectTimeout = 5,
    ConnectOther = 6,
    Send = 7,
    Receive = 8,
    Frame = 9,
    Rejected = 10,
}

pub(crate) fn derive_port() -> u16 {
    let mut win_dir = [0u8; 260];
    let n = unsafe { GetSystemWindowsDirectoryA(win_dir.as_mut_ptr(), win_dir.len() as u32) };
    if n == 0 || n as usize >= win_dir.len() {
        return 0;
    }

    let mut root = [0u8; 4];
    root[..3].copy_from_slice(&win_dir[..3]);

    let mut serial: u32 = 0;
    let ok = unsafe {
        GetVolumeInformationA(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return 0;
    }

    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut text = [0u8; 8];
    let mut sn = serial;
    for i in (0..8).rev() {
        text[i] = HEX[(sn & 0xF) as usize];
        sn >>= 4;
    }

    const SUFFIX: &[u8] = b"UsugumoPort";
    let mut input = [0u8; 8 + SUFFIX.len()];
    input[..8].copy_from_slice(&text);
    input[8..].copy_from_slice(SUFFIX);

    let mut digest = [0u8; 32];
    crate::sha256::sha256(input.as_ptr(), input.len(), digest.as_mut_ptr());

    let raw = ((digest[0] as u16) << 8) | digest[1] as u16;
    crate::consts::PORT_BASE + (raw % crate::consts::PORT_RANGE)
}

pub(crate) struct Connection {
    socket: usize,
    wsa_started: bool,
    connected: bool,
    last_error: TransportError,
    last_wsa_error: i32,
    port: u16,
}

impl Connection {
    pub(crate) const fn new() -> Self {
        Self {
            socket: INVALID_SOCKET,
            wsa_started: false,
            connected: false,
            last_error: TransportError::None,
            last_wsa_error: 0,
            port: 0,
        }
    }

    pub(crate) fn last_error(&self) -> TransportError {
        self.last_error
    }

    pub(crate) fn last_wsa_error(&self) -> i32 {
        self.last_wsa_error
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.connected
    }

    fn fail(&mut self, error: TransportError) -> bool {
        self.last_error = error;
        self.close();
        false
    }

    pub(crate) fn connect(&mut self) -> bool {
        if self.connected {
            return true;
        }
        self.last_error = TransportError::None;
        self.last_wsa_error = 0;

        let mut wsa_data = [0u8; 512];
        if unsafe { WSAStartup(0x0202, wsa_data.as_mut_ptr() as *mut c_void) } != 0 {
            self.last_error = TransportError::WsaStartup;
            return false;
        }
        self.wsa_started = true;

        let port = derive_port();
        if port == 0 {
            self.last_error = TransportError::PortDerive;
            self.close();
            return false;
        }
        self.port = port;

        self.socket = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        if self.socket == INVALID_SOCKET {
            self.last_error = TransportError::Socket;
            self.last_wsa_error = unsafe { WSAGetLastError() };
            self.close();
            return false;
        }

        let addr = SockAddrIn {
            sin_family: AF_INET as i16,
            sin_port: port.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0u8; 8],
        };

        let rc = unsafe {
            connect(
                self.socket,
                &addr,
                core::mem::size_of::<SockAddrIn>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            let wsa = unsafe { WSAGetLastError() };
            self.last_wsa_error = wsa;
            self.last_error = if wsa == WSAECONNREFUSED {
                TransportError::ConnectRefused
            } else if wsa == WSAETIMEDOUT {
                TransportError::ConnectTimeout
            } else {
                TransportError::ConnectOther
            };
            self.close();
            return false;
        }

        self.connected = true;
        true
    }

    pub(crate) fn close(&mut self) {
        if self.socket != INVALID_SOCKET {
            unsafe {
                closesocket(self.socket);
            }
            self.socket = INVALID_SOCKET;
        }
        if self.wsa_started {
            unsafe {
                WSACleanup();
            }
            self.wsa_started = false;
        }
        self.connected = false;
    }

    fn send_all(&mut self, data: &[u8]) -> bool {
        if !self.connected {
            return false;
        }
        let mut sent = 0usize;
        while sent < data.len() {
            let n = unsafe {
                send(
                    self.socket,
                    data[sent..].as_ptr(),
                    (data.len() - sent) as i32,
                    0,
                )
            };
            if n <= 0 {
                self.last_error = TransportError::Send;
                self.last_wsa_error = unsafe { WSAGetLastError() };
                return false;
            }
            sent += n as usize;
        }
        true
    }

    fn receive_all(&mut self, data: &mut [u8]) -> bool {
        if !self.connected {
            return false;
        }
        let mut received = 0usize;
        while received < data.len() {
            let n = unsafe {
                recv(
                    self.socket,
                    data[received..].as_mut_ptr(),
                    (data.len() - received) as i32,
                    0,
                )
            };
            if n <= 0 {
                self.last_error = TransportError::Receive;
                self.last_wsa_error = if n == 0 {
                    0
                } else {
                    unsafe { WSAGetLastError() }
                };
                return false;
            }
            received += n as usize;
        }
        true
    }

    pub(crate) fn round_trip(&mut self, request: &protocol::Request) -> Option<protocol::Request> {
        let mut zeroed = *request;
        zeroed.checksum = 0;
        let mut scratch = [0u8; protocol::MAX_FRAME_SIZE];
        let n = zeroed.serialize(&mut scratch)?;
        let sum = protocol::compute_checksum(&scratch[..n]);

        let mut outgoing = *request;
        outgoing.checksum = sum;
        let mut payload = [0u8; protocol::MAX_FRAME_SIZE];
        let body_len = outgoing.serialize(&mut payload)?;

        let mut prefix = [0u8; protocol::LENGTH_PREFIX_SIZE];
        if !protocol::write_length_prefix(&mut prefix, body_len) {
            self.fail(TransportError::Frame);
            return None;
        }
        if !self.send_all(&prefix) || !self.send_all(&payload[..body_len]) {
            self.close();
            return None;
        }

        let mut reply_prefix = [0u8; protocol::LENGTH_PREFIX_SIZE];
        if !self.receive_all(&mut reply_prefix) {
            self.close();
            return None;
        }
        let reply_len = protocol::read_length_prefix(&reply_prefix)?;
        let mut reply = [0u8; protocol::MAX_FRAME_SIZE];
        if !self.receive_all(&mut reply[..reply_len]) {
            self.close();
            return None;
        }

        let wire = protocol::Request::parse(&reply[..reply_len])?;
        if wire.version > protocol::PROTOCOL_VERSION {
            self.fail(TransportError::Frame);
            return None;
        }
        let mut verify = wire;
        verify.checksum = 0;
        let mut canon = [0u8; protocol::MAX_FRAME_SIZE];
        let m = verify.serialize(&mut canon)?;
        if protocol::compute_checksum(&canon[..m]) != wire.checksum {
            self.fail(TransportError::Rejected);
            return None;
        }
        Some(wire)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}
