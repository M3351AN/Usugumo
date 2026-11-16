// Copyright (c) 2026 渟雲. All rights reserved.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

use obfstr::obfbytes;

use crate::consts::*;
use crate::imports::*;
use crate::types::*;

pub const WSK_INFINITE_WAIT: u32 = 0xFFFF_FFFF;

pub const WSK_FLAG_LISTEN_SOCKET: u32 = 0x0000_0001;
pub const WSK_FLAG_NODELAY: u32 = 0x0000_0002;
pub const WSK_FLAG_WAITALL: u32 = 0x0000_0002;

pub const AF_INET: u16 = 2;
pub const SOCK_STREAM: u16 = 1;
pub const IPPROTO_TCP: u32 = 6;

pub type PwskClient = *mut c_void;
pub type PwskSocket = *mut WskSocket;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskClientDispatch {
    pub version: u16,
    pub reserved: u16,
    pub wsk_client_event: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskClientNpi {
    pub client_context: *mut c_void,
    pub dispatch: *const WskClientDispatch,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskRegistration {
    pub reserved_registration_state: u64,
    pub reserved_registration_context: *mut c_void,
    pub reserved_registration_lock: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderDispatch {
    pub version: u16,
    pub reserved: u16,
    pub wsk_socket: *mut c_void,
    pub wsk_socket_connect: *mut c_void,
    pub wsk_control_client: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderNpi {
    pub client: PwskClient,
    pub dispatch: *const WskProviderDispatch,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskSocket {
    pub dispatch: *const c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskBuf {
    pub mdl: *mut c_void,
    pub offset: u32,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderBasicDispatch {
    pub wsk_control_socket: *mut c_void,
    pub wsk_close_socket: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderConnectionDispatch {
    pub basic: WskProviderBasicDispatch,
    pub wsk_bind: *mut c_void,
    pub wsk_connect: *mut c_void,
    pub wsk_get_local_address: *mut c_void,
    pub wsk_get_remote_address: *mut c_void,
    pub wsk_send: *mut c_void,
    pub wsk_receive: *mut c_void,
    pub wsk_disconnect: *mut c_void,
    pub wsk_release: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderListenDispatch {
    pub basic: WskProviderBasicDispatch,
    pub wsk_bind: *mut c_void,
    pub wsk_accept: *mut c_void,
    pub wsk_inspect_complete: *mut c_void,
    pub wsk_get_local_address: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct KEvent {
    pub header: i32,
    pub signal_state: i32,
    pub wait_list: [usize; 2],
}

pub type FnWskRegister =
    unsafe extern "system" fn(*mut WskClientNpi, *mut WskRegistration) -> NtStatus;
pub type FnWskDeregister = unsafe extern "system" fn(*mut WskRegistration);
pub type FnWskCaptureProviderNpi =
    unsafe extern "system" fn(*mut WskRegistration, u32, *mut WskProviderNpi) -> NtStatus;
pub type FnWskReleaseProviderNpi = unsafe extern "system" fn(*mut WskRegistration);

pub type FnWskSocket = unsafe extern "system" fn(
    PwskClient,
    u16,
    u16,
    u32,
    u32,
    *mut c_void,
    *const c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut Irp,
) -> NtStatus;
pub type FnWskBind =
    unsafe extern "system" fn(PwskSocket, *mut SockaddrIn, u32, *mut Irp) -> NtStatus;
pub type FnWskAccept = unsafe extern "system" fn(
    PwskSocket,
    u32,
    *mut c_void,
    *const c_void,
    *mut SockaddrIn,
    *mut SockaddrIn,
    *mut Irp,
) -> NtStatus;
pub type FnWskSend = unsafe extern "system" fn(PwskSocket, *mut WskBuf, u32, *mut Irp) -> NtStatus;
pub type FnWskReceive =
    unsafe extern "system" fn(PwskSocket, *mut WskBuf, u32, *mut Irp) -> NtStatus;
pub type FnWskCloseSocket = unsafe extern "system" fn(PwskSocket, *mut Irp) -> NtStatus;

pub type FnIoAllocateIrp = unsafe extern "system" fn(u8, u8) -> *mut Irp;
pub type FnIoFreeIrp = unsafe extern "system" fn(*mut Irp);
pub type FnIoAllocateMdl =
    unsafe extern "system" fn(*mut c_void, u32, u8, u8, *mut Irp) -> *mut c_void;
pub type FnIoFreeMdl = unsafe extern "system" fn(*mut c_void);
pub type FnMmBuildMdlForNonPagedPool = unsafe extern "system" fn(*mut c_void);
pub type FnKeInitializeEvent = unsafe extern "system" fn(*mut KEvent, u32, u8);
pub type FnKeSetEvent = unsafe extern "system" fn(*mut KEvent, i8, u8) -> u8;
pub type FnKeResetEvent = unsafe extern "system" fn(*mut KEvent) -> i32;
pub type FnKeWaitForSingleObject =
    unsafe extern "system" fn(*mut c_void, u32, u8, u8, *mut i64) -> NtStatus;
pub type FnPsCreateSystemThread = unsafe extern "system" fn(
    *mut usize,
    u32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    unsafe extern "system" fn(*mut c_void),
    *mut c_void,
) -> NtStatus;
pub type FnPsTerminateSystemThread = unsafe extern "system" fn(NtStatus) -> NtStatus;
pub type FnKeDelayExecutionThread = unsafe extern "system" fn(u8, u8, *mut i64) -> NtStatus;
pub type FnZwClose = unsafe extern "system" fn(usize) -> NtStatus;

pub const NOTIFICATION_EVENT: u32 = 0;
pub const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
pub const EXECUTIVE: u32 = 0;
pub const KERNEL_MODE_WAIT: u8 = 0;
pub const NON_ALERTABLE: u8 = 0;
pub const FALSE: u8 = 0;
pub const IO_NO_INCREMENT: i8 = 0;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const STATUS_MORE_PROCESSING_REQUIRED: NtStatus = 0xC000_0016u32 as i32;
pub const WSK_CLIENT_DISPATCH_VERSION: u16 = 0x0101;

#[repr(C)]
pub struct WskState {
    pub registration: WskRegistration,
    pub provider: WskProviderNpi,
    pub listen_socket: PwskSocket,
    pub connection_socket: PwskSocket,
    pub client_dispatch: WskClientDispatch,
    pub registered: bool,
    pub captured: bool,
    pub thread_handle: usize,
    pub thread_should_stop: bool,
    pub thread_exited: bool,
    pub exit_event: KEvent,
    pub port: u16,
}

pub static mut G_WSK: WskState = WskState {
    registration: WskRegistration {
        reserved_registration_state: 0,
        reserved_registration_context: null_mut(),
        reserved_registration_lock: 0,
    },
    provider: WskProviderNpi {
        client: null_mut(),
        dispatch: null_mut(),
    },
    listen_socket: null_mut(),
    connection_socket: null_mut(),
    client_dispatch: WskClientDispatch {
        version: WSK_CLIENT_DISPATCH_VERSION,
        reserved: 0,
        wsk_client_event: null_mut(),
    },
    registered: false,
    captured: false,
    thread_handle: 0,
    thread_should_stop: false,
    thread_exited: false,
    exit_event: KEvent {
        header: 0,
        signal_state: 0,
        wait_list: [0; 2],
    },
    port: 0,
};

unsafe fn wsk_register_fn() -> Option<FnWskRegister> {
    unsafe {
        if _WSK_REGISTER.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnWskRegister>(
                _WSK_REGISTER,
            ))
        }
    }
}

unsafe fn wsk_deregister_fn() -> Option<FnWskDeregister> {
    unsafe {
        if _WSK_DEREGISTER.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnWskDeregister>(
                _WSK_DEREGISTER,
            ))
        }
    }
}

unsafe fn wsk_capture_fn() -> Option<FnWskCaptureProviderNpi> {
    unsafe {
        if _WSK_CAPTURE_PROVIDER_NPI.is_null() {
            None
        } else {
            Some(
                core::mem::transmute::<*mut c_void, FnWskCaptureProviderNpi>(
                    _WSK_CAPTURE_PROVIDER_NPI,
                ),
            )
        }
    }
}

unsafe fn wsk_release_fn() -> Option<FnWskReleaseProviderNpi> {
    unsafe {
        if _WSK_RELEASE_PROVIDER_NPI.is_null() {
            None
        } else {
            Some(
                core::mem::transmute::<*mut c_void, FnWskReleaseProviderNpi>(
                    _WSK_RELEASE_PROVIDER_NPI,
                ),
            )
        }
    }
}

unsafe fn io_allocate_irp_fn() -> Option<FnIoAllocateIrp> {
    unsafe {
        if _IO_ALLOCATE_IRP.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnIoAllocateIrp>(
                _IO_ALLOCATE_IRP,
            ))
        }
    }
}

unsafe fn io_free_irp_fn() -> Option<FnIoFreeIrp> {
    unsafe {
        if _IO_FREE_IRP.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnIoFreeIrp>(
                _IO_FREE_IRP,
            ))
        }
    }
}

unsafe fn io_allocate_mdl_fn() -> Option<FnIoAllocateMdl> {
    unsafe {
        if _IO_ALLOCATE_MDL.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnIoAllocateMdl>(
                _IO_ALLOCATE_MDL,
            ))
        }
    }
}

unsafe fn io_free_mdl_fn() -> Option<FnIoFreeMdl> {
    unsafe {
        if _IO_FREE_MDL.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnIoFreeMdl>(
                _IO_FREE_MDL,
            ))
        }
    }
}

unsafe fn mm_build_mdl_fn() -> Option<FnMmBuildMdlForNonPagedPool> {
    unsafe {
        if _MM_BUILD_MDL_FOR_NON_PAGED_POOL.is_null() {
            None
        } else {
            Some(core::mem::transmute::<
                *mut c_void,
                FnMmBuildMdlForNonPagedPool,
            >(_MM_BUILD_MDL_FOR_NON_PAGED_POOL))
        }
    }
}

unsafe fn ke_initialize_event_fn() -> Option<FnKeInitializeEvent> {
    unsafe {
        if _KE_INITIALIZE_EVENT.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnKeInitializeEvent>(
                _KE_INITIALIZE_EVENT,
            ))
        }
    }
}

unsafe fn ke_reset_event_fn() -> Option<FnKeResetEvent> {
    unsafe {
        if _KE_RESET_EVENT.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnKeResetEvent>(
                _KE_RESET_EVENT,
            ))
        }
    }
}

unsafe fn ke_set_event_fn() -> Option<FnKeSetEvent> {
    unsafe {
        if _KE_SET_EVENT.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnKeSetEvent>(
                _KE_SET_EVENT,
            ))
        }
    }
}

unsafe fn ke_wait_fn() -> Option<FnKeWaitForSingleObject> {
    unsafe {
        if _KE_WAIT_FOR_SINGLE_OBJECT.is_null() {
            None
        } else {
            Some(
                core::mem::transmute::<*mut c_void, FnKeWaitForSingleObject>(
                    _KE_WAIT_FOR_SINGLE_OBJECT,
                ),
            )
        }
    }
}

unsafe fn ps_create_thread_fn() -> Option<FnPsCreateSystemThread> {
    unsafe {
        if _PS_CREATE_SYSTEM_THREAD.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnPsCreateSystemThread>(
                _PS_CREATE_SYSTEM_THREAD,
            ))
        }
    }
}

unsafe fn ps_terminate_thread_fn() -> Option<FnPsTerminateSystemThread> {
    unsafe {
        if _PS_TERMINATE_SYSTEM_THREAD.is_null() {
            None
        } else {
            Some(
                core::mem::transmute::<*mut c_void, FnPsTerminateSystemThread>(
                    _PS_TERMINATE_SYSTEM_THREAD,
                ),
            )
        }
    }
}

unsafe fn zw_close_fn() -> Option<FnZwClose> {
    unsafe {
        if _ZW_CLOSE.is_null() {
            None
        } else {
            Some(core::mem::transmute::<*mut c_void, FnZwClose>(_ZW_CLOSE))
        }
    }
}

pub unsafe fn init_event(event: *mut KEvent) -> bool {
    unsafe {
        match ke_initialize_event_fn() {
            Some(f) => {
                f(event, NOTIFICATION_EVENT, FALSE);
                true
            }
            None => false,
        }
    }
}

pub unsafe fn reset_event(event: *mut KEvent) {
    unsafe {
        if let Some(f) = ke_reset_event_fn() {
            f(event);
        }
    }
}

pub unsafe fn set_event(event: *mut KEvent) {
    unsafe {
        if let Some(f) = ke_set_event_fn() {
            f(event, IO_NO_INCREMENT, FALSE);
        }
    }
}

pub unsafe fn wait_event(event: *mut KEvent) -> NtStatus {
    unsafe {
        match ke_wait_fn() {
            Some(f) => f(
                event as *mut c_void,
                EXECUTIVE,
                KERNEL_MODE_WAIT,
                NON_ALERTABLE,
                null_mut(),
            ),
            None => STATUS_UNSUCCESSFUL,
        }
    }
}

pub fn cpu_relax(microseconds: i64) {
    unsafe {
        if crate::imports::_KE_DELAY_EXECUTION_THREAD.is_null() {
            return;
        }
        let f = core::mem::transmute::<*mut c_void, FnKeDelayExecutionThread>(
            crate::imports::_KE_DELAY_EXECUTION_THREAD,
        );
        let mut interval: i64 = -10 * microseconds;
        f(KERNEL_MODE_WAIT, FALSE, &mut interval);
    }
}

#[repr(C)]
pub struct IrpContext {
    pub event: KEvent,
    pub status: NtStatus,
    pub information: usize,
    pub irp: *mut Irp,
}

pub unsafe fn new_irp_context() -> *mut IrpContext {
    unsafe {
        let ctx = crate::util::kalloc(core::mem::size_of::<IrpContext>()) as *mut IrpContext;
        if ctx.is_null() {
            return null_mut();
        }
        core::ptr::write_bytes(ctx as *mut u8, 0, core::mem::size_of::<IrpContext>());
        if !init_event(addr_of_mut!((*ctx).event)) {
            crate::util::kfree(ctx as *mut c_void);
            return null_mut();
        }
        ctx
    }
}

pub unsafe fn free_irp_context(ctx: *mut IrpContext) {
    if !ctx.is_null() {
        crate::util::kfree(ctx as *mut c_void);
    }
}

unsafe extern "system" fn wsk_completion_routine(
    _device_object: *mut c_void,
    irp: *mut Irp,
    context: *mut c_void,
) -> NtStatus {
    unsafe {
        if !context.is_null() {
            let ctx = context as *mut IrpContext;
            (*ctx).status = (*irp).io_status.status;
            (*ctx).information = (*irp).io_status.information;
            crate::wsk::set_event(addr_of_mut!((*ctx).event));
        }
        STATUS_MORE_PROCESSING_REQUIRED
    }
}

unsafe fn hook_completion_routine(irp: *mut Irp, ctx: *mut IrpContext) {
    unsafe {
        let stack = next_irp_stack_location(irp);
        if stack.is_null() {
            return;
        }
        (*stack).control = 0;
        (*stack).control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        (*stack).completion_routine = wsk_completion_routine as *const () as usize;
        (*stack).context = ctx as *mut c_void;
    }
}

unsafe fn next_irp_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    unsafe {
        if irp.is_null() {
            return null_mut();
        }
        let current = (*irp).current_stack_location;
        if current.is_null() {
            return null_mut();
        }
        (current as *mut u8).sub(core::mem::size_of::<IoStackLocation>()) as *mut IoStackLocation
    }
}

pub unsafe fn allocate_sync_irp(ctx: *mut IrpContext) -> *mut Irp {
    unsafe {
        let alloc = match io_allocate_irp_fn() {
            Some(f) => f,
            None => return null_mut(),
        };
        let irp = alloc(1, FALSE);
        if irp.is_null() {
            return null_mut();
        }
        reset_event(addr_of_mut!((*ctx).event));
        (*ctx).status = STATUS_PENDING_VALUE;
        (*ctx).information = 0;
        (*ctx).irp = irp;
        (*irp).io_status.status = STATUS_PENDING_VALUE;
        (*irp).io_status.information = 0;
        hook_completion_routine(irp, ctx);
        irp
    }
}

pub unsafe fn free_sync_irp(irp: *mut Irp) {
    unsafe {
        if !irp.is_null()
            && let Some(f) = io_free_irp_fn()
        {
            f(irp);
        }
    }
}

pub unsafe fn finish_irp(ctx: *mut IrpContext, irp: *mut Irp, status: NtStatus) -> NtStatus {
    unsafe {
        let final_status = if status == STATUS_PENDING_VALUE {
            await_irp(ctx)
        } else {
            status
        };
        if irp.is_null() {
            return final_status;
        }
        let irp_status = (*irp).io_status.status;
        if final_status < 0 {
            return final_status;
        }
        if irp_status < 0 {
            return irp_status;
        }
        if status != STATUS_PENDING_VALUE && irp_status == STATUS_PENDING_VALUE {
            return STATUS_UNSUCCESSFUL;
        }
        final_status
    }
}

pub unsafe fn irp_information(irp: *mut Irp) -> usize {
    unsafe {
        if irp.is_null() {
            0
        } else {
            (*irp).io_status.information
        }
    }
}

pub unsafe fn await_irp(ctx: *mut IrpContext) -> NtStatus {
    unsafe {
        wait_event(addr_of_mut!((*ctx).event));
        (*ctx).status
    }
}

pub unsafe fn build_mdl(buffer: *mut c_void, length: u32) -> *mut c_void {
    unsafe {
        let alloc = match io_allocate_mdl_fn() {
            Some(f) => f,
            None => return null_mut(),
        };
        let build = match mm_build_mdl_fn() {
            Some(f) => f,
            None => return null_mut(),
        };
        let mdl = alloc(buffer, length, FALSE, FALSE, null_mut());
        if mdl.is_null() {
            return null_mut();
        }
        build(mdl);
        mdl
    }
}

pub unsafe fn free_mdl(mdl: *mut c_void) {
    unsafe {
        if !mdl.is_null()
            && let Some(f) = io_free_mdl_fn()
        {
            f(mdl);
        }
    }
}

unsafe fn provider_dispatch() -> *const WskProviderDispatch {
    unsafe { (*addr_of_mut!(G_WSK)).provider.dispatch }
}

unsafe fn listen_dispatch() -> *const WskProviderListenDispatch {
    unsafe {
        let socket = (*addr_of_mut!(G_WSK)).listen_socket;
        if socket.is_null() {
            return null_mut();
        }
        (*socket).dispatch as *const WskProviderListenDispatch
    }
}

unsafe fn connection_dispatch() -> *const WskProviderConnectionDispatch {
    unsafe {
        let socket = (*addr_of_mut!(G_WSK)).connection_socket;
        if socket.is_null() {
            return null_mut();
        }
        (*socket).dispatch as *const WskProviderConnectionDispatch
    }
}

pub unsafe fn register_client() -> NtStatus {
    unsafe {
        let register = match wsk_register_fn() {
            Some(f) => f,
            None => return STATUS_UNSUCCESSFUL,
        };
        let state = addr_of_mut!(G_WSK);
        (*state).client_dispatch.version = WSK_CLIENT_DISPATCH_VERSION;
        (*state).client_dispatch.reserved = 0;
        (*state).client_dispatch.wsk_client_event = null_mut();

        let mut npi = WskClientNpi {
            client_context: state as *mut c_void,
            dispatch: addr_of_mut!((*state).client_dispatch),
        };
        let status = register(&mut npi, addr_of_mut!((*state).registration));
        if status >= 0 {
            (*state).registered = true;
        }
        status
    }
}

pub unsafe fn capture_provider() -> NtStatus {
    unsafe {
        let capture = match wsk_capture_fn() {
            Some(f) => f,
            None => return STATUS_UNSUCCESSFUL,
        };
        let state = addr_of_mut!(G_WSK);
        let status = capture(
            addr_of_mut!((*state).registration),
            WSK_INFINITE_WAIT,
            addr_of_mut!((*state).provider),
        );
        if status >= 0 {
            if (*state).provider.dispatch.is_null() || (*state).provider.client.is_null() {
                return STATUS_UNSUCCESSFUL;
            }
            (*state).captured = true;
        }
        status
    }
}

pub unsafe fn release_provider() {
    unsafe {
        let state = addr_of_mut!(G_WSK);
        if (*state).captured {
            if let Some(f) = wsk_release_fn() {
                f(addr_of_mut!((*state).registration));
            }
            (*state).captured = false;
        }
    }
}

pub unsafe fn deregister_client() {
    unsafe {
        let state = addr_of_mut!(G_WSK);
        if (*state).registered {
            if let Some(f) = wsk_deregister_fn() {
                f(addr_of_mut!((*state).registration));
            }
            (*state).registered = false;
        }
    }
}

pub unsafe fn create_listen_socket() -> NtStatus {
    unsafe {
        let dispatch = provider_dispatch();
        if dispatch.is_null() {
            return STATUS_INVALID_DEVICE_STATE;
        }
        let create = core::mem::transmute::<*mut c_void, FnWskSocket>((*dispatch).wsk_socket);
        let ctx = new_irp_context();
        if ctx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let state = addr_of_mut!(G_WSK);
        let status = create(
            (*state).provider.client,
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            WSK_FLAG_LISTEN_SOCKET,
            state as *mut c_void,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            irp,
        );

        let final_status = finish_irp(ctx, irp, status);

        if final_status >= 0 {
            (*state).listen_socket = irp_information(irp) as PwskSocket;
        }

        free_sync_irp(irp);
        free_irp_context(ctx);

        if final_status >= 0 && (*state).listen_socket.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        final_status
    }
}

pub unsafe fn bind_listen_socket(port: u16) -> NtStatus {
    unsafe {
        let listen = listen_dispatch();
        if listen.is_null() {
            return STATUS_INVALID_DEVICE_STATE;
        }
        let bind = core::mem::transmute::<*mut c_void, FnWskBind>((*listen).wsk_bind);
        let ctx = new_irp_context();
        if ctx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let state = addr_of_mut!(G_WSK);
        let mut addr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: 0x0100_007F,
            sin_zero: [0; 8],
        };
        (*state).port = port;

        let status = bind((*state).listen_socket, &mut addr, 0, irp);
        let final_status = finish_irp(ctx, irp, status);

        free_sync_irp(irp);
        free_irp_context(ctx);
        final_status
    }
}

pub unsafe fn accept_connection() -> NtStatus {
    unsafe {
        let listen = listen_dispatch();
        if listen.is_null() {
            return STATUS_INVALID_DEVICE_STATE;
        }
        let accept = core::mem::transmute::<*mut c_void, FnWskAccept>((*listen).wsk_accept);
        let ctx = new_irp_context();
        if ctx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let state = addr_of_mut!(G_WSK);
        let mut local = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        };
        let mut remote = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        let status = accept(
            (*state).listen_socket,
            0,
            state as *mut c_void,
            null_mut(),
            &mut local,
            &mut remote,
            irp,
        );
        let final_status = finish_irp(ctx, irp, status);

        if final_status >= 0 {
            (*state).connection_socket = irp_information(irp) as PwskSocket;
        }

        free_sync_irp(irp);
        free_irp_context(ctx);

        if final_status >= 0 && (*state).connection_socket.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        final_status
    }
}

pub unsafe fn socket_send(data: *const u8, length: usize) -> NtStatus {
    unsafe {
        let dispatch = connection_dispatch();
        if dispatch.is_null() {
            return STATUS_INVALID_DEVICE_STATE;
        }
        let send = core::mem::transmute::<*mut c_void, FnWskSend>((*dispatch).wsk_send);
        let ctx = new_irp_context();
        if ctx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let mdl = build_mdl(data as *mut c_void, length as u32);
        if mdl.is_null() {
            free_sync_irp(irp);
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let mut buf = WskBuf {
            mdl,
            offset: 0,
            length,
        };
        let state = addr_of_mut!(G_WSK);
        let status = send((*state).connection_socket, &mut buf, WSK_FLAG_NODELAY, irp);
        let final_status = finish_irp(ctx, irp, status);

        free_mdl(mdl);
        free_sync_irp(irp);
        free_irp_context(ctx);
        final_status
    }
}

pub unsafe fn socket_receive(buffer: *mut u8, length: usize) -> NtStatus {
    unsafe {
        let dispatch = connection_dispatch();
        if dispatch.is_null() {
            return STATUS_INVALID_DEVICE_STATE;
        }
        let receive = core::mem::transmute::<*mut c_void, FnWskReceive>((*dispatch).wsk_receive);
        let ctx = new_irp_context();
        if ctx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let mdl = build_mdl(buffer as *mut c_void, length as u32);
        if mdl.is_null() {
            free_sync_irp(irp);
            free_irp_context(ctx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let mut buf = WskBuf {
            mdl,
            offset: 0,
            length,
        };
        let state = addr_of_mut!(G_WSK);
        let status = receive((*state).connection_socket, &mut buf, WSK_FLAG_WAITALL, irp);
        let final_status = finish_irp(ctx, irp, status);

        free_mdl(mdl);
        free_sync_irp(irp);
        free_irp_context(ctx);
        final_status
    }
}

pub unsafe fn close_connection() {
    unsafe {
        let dispatch = connection_dispatch();
        let state = addr_of_mut!(G_WSK);
        if dispatch.is_null() || (*state).connection_socket.is_null() {
            return;
        }
        let close = core::mem::transmute::<*mut c_void, FnWskCloseSocket>(
            (*dispatch).basic.wsk_close_socket,
        );
        let ctx = new_irp_context();
        if ctx.is_null() {
            return;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return;
        }
        let status = close((*state).connection_socket, irp);
        let _ = finish_irp(ctx, irp, status);
        free_sync_irp(irp);
        free_irp_context(ctx);
        (*state).connection_socket = null_mut();
    }
}

pub unsafe fn close_listen_socket() {
    unsafe {
        let dispatch = listen_dispatch();
        let state = addr_of_mut!(G_WSK);
        if dispatch.is_null() || (*state).listen_socket.is_null() {
            return;
        }
        let close = core::mem::transmute::<*mut c_void, FnWskCloseSocket>(
            (*dispatch).basic.wsk_close_socket,
        );
        let ctx = new_irp_context();
        if ctx.is_null() {
            return;
        }
        let irp = allocate_sync_irp(ctx);
        if irp.is_null() {
            free_irp_context(ctx);
            return;
        }
        let status = close((*state).listen_socket, irp);
        let _ = finish_irp(ctx, irp, status);
        free_sync_irp(irp);
        free_irp_context(ctx);
        (*state).listen_socket = null_mut();
    }
}

pub unsafe fn derive_port() -> u16 {
    unsafe {
        let state = addr_of_mut!(G_WSK);
        let mut serial = [0i8; 128];
        let status =
            crate::helpers::get_boot_volume_serial(serial.as_mut_ptr(), serial.len() as u32);
        if status < 0 {
            return 0;
        }
        let serial_len = serial.iter().position(|&c| c == 0).unwrap_or(serial.len());

        let suffix = obfbytes!(b"UsugumoPort");
        let mut input = [0u8; 8 + 11];
        let mut slen = serial_len;
        if slen > 8 {
            slen = 8;
        }
        for (dst, src) in input.iter_mut().zip(serial.iter()).take(slen) {
            *dst = *src as u8;
        }
        input[slen..slen + suffix.len()].copy_from_slice(suffix);

        let mut digest = [0u8; 32];
        crate::sha256::sha256(input.as_ptr(), slen + suffix.len(), digest.as_mut_ptr());
        crate::util::zero_memory(serial.as_mut_ptr() as *mut u8, serial.len());

        let raw = ((digest[0] as u16) << 8) | digest[1] as u16;
        (*state).port = PORT_BASE + (raw % PORT_RANGE);
        (*state).port
    }
}

unsafe fn verify_wire_checksum(wire: &crate::protocol::Request, scratch: &mut [u8]) -> bool {
    let mut zeroed = *wire;
    zeroed.checksum = 0;
    let n = match zeroed.serialize(scratch) {
        Some(n) => n,
        None => return false,
    };
    crate::protocol::compute_checksum(&scratch[..n]) == wire.checksum
}

#[inline(never)]
unsafe fn handle_one_request(
    payload: *mut u8,
    payload_len: usize,
    reply: *mut u8,
    prefix: *mut u8,
) -> bool {
    unsafe {
        let text = core::slice::from_raw_parts(payload, payload_len);
        let wire = match crate::protocol::Request::parse(text) {
            Some(w) => w,
            None => return false,
        };
        if wire.version > crate::protocol::PROTOCOL_VERSION {
            return false;
        }
        let scratch = core::slice::from_raw_parts_mut(reply, crate::protocol::MAX_FRAME_SIZE);
        if !verify_wire_checksum(&wire, scratch) {
            return false;
        }

        let mut request = crate::protocol::request_from_wire(&wire);
        if crate::request_handler::request_handler(&mut request) == 0 {
            return false;
        }

        let reply_bytes = core::slice::from_raw_parts_mut(reply, crate::protocol::MAX_FRAME_SIZE);
        let mut outgoing = crate::protocol::request_to_wire(&request);
        outgoing.checksum = 0;
        let body_len = match outgoing.serialize(reply_bytes) {
            Some(n) => n,
            None => return false,
        };
        outgoing.checksum = crate::protocol::compute_checksum(&reply_bytes[..body_len]);
        let body_len = match outgoing.serialize(reply_bytes) {
            Some(n) => n,
            None => return false,
        };

        let prefix_out =
            core::slice::from_raw_parts_mut(prefix, crate::protocol::LENGTH_PREFIX_SIZE);
        if !crate::protocol::write_length_prefix(prefix_out, body_len) {
            return false;
        }
        socket_send(prefix, crate::protocol::LENGTH_PREFIX_SIZE) >= 0
            && socket_send(reply, body_len) >= 0
    }
}

unsafe extern "system" fn server_thread(_context: *mut c_void) {
    unsafe {
        let state = addr_of_mut!(G_WSK);
        let prefix = crate::util::kalloc(crate::protocol::LENGTH_PREFIX_SIZE) as *mut u8;
        if prefix.is_null() {
            set_event(addr_of_mut!((*state).exit_event));
            if let Some(f) = ps_terminate_thread_fn() {
                f(STATUS_INSUFFICIENT_RESOURCES);
            }
            return;
        }
        let payload = crate::util::kalloc(crate::protocol::MAX_FRAME_SIZE) as *mut u8;
        if payload.is_null() {
            crate::util::kfree(prefix as *mut c_void);
            set_event(addr_of_mut!((*state).exit_event));
            if let Some(f) = ps_terminate_thread_fn() {
                f(STATUS_INSUFFICIENT_RESOURCES);
            }
            return;
        }
        let reply = crate::util::kalloc(crate::protocol::MAX_FRAME_SIZE) as *mut u8;
        if reply.is_null() {
            crate::util::kfree(prefix as *mut c_void);
            crate::util::kfree(payload as *mut c_void);
            set_event(addr_of_mut!((*state).exit_event));
            if let Some(f) = ps_terminate_thread_fn() {
                f(STATUS_INSUFFICIENT_RESOURCES);
            }
            return;
        }
        crate::util::zero_memory(prefix, crate::protocol::LENGTH_PREFIX_SIZE);
        crate::util::zero_memory(payload, crate::protocol::MAX_FRAME_SIZE);
        crate::util::zero_memory(reply, crate::protocol::MAX_FRAME_SIZE);

        loop {
            if (*state).thread_should_stop {
                break;
            }
            if (*state).connection_socket.is_null() && accept_connection() < 0 {
                cpu_relax(1000);
                continue;
            }

            if socket_receive(prefix, crate::protocol::LENGTH_PREFIX_SIZE) < 0 {
                close_connection();
                continue;
            }
            let prefix_bytes =
                core::slice::from_raw_parts(prefix, crate::protocol::LENGTH_PREFIX_SIZE);
            let payload_len = match crate::protocol::read_length_prefix(prefix_bytes) {
                Some(n) => n,
                None => {
                    close_connection();
                    continue;
                }
            };
            if socket_receive(payload, payload_len) < 0 {
                crate::util::zero_memory(payload, payload_len);
                close_connection();
                continue;
            }

            if !handle_one_request(payload, payload_len, reply, prefix) {
                crate::util::zero_memory(payload, payload_len);
                close_connection();
                continue;
            }
            crate::util::zero_memory(payload, payload_len);
            crate::util::zero_memory(reply, crate::protocol::MAX_FRAME_SIZE);
        }

        close_connection();
        close_listen_socket();
        crate::util::kfree(prefix as *mut c_void);
        crate::util::kfree(payload as *mut c_void);
        crate::util::kfree(reply as *mut c_void);

        (*state).thread_exited = true;
        set_event(addr_of_mut!((*state).exit_event));

        if let Some(f) = ps_terminate_thread_fn() {
            f(STATUS_SUCCESS);
        }
    }
}

pub unsafe fn start_server() -> NtStatus {
    unsafe {
        let state = addr_of_mut!(G_WSK);

        let mut status = register_client();
        if status < 0 {
            return status;
        }

        status = capture_provider();
        if status < 0 {
            deregister_client();
            return status;
        }

        status = create_listen_socket();
        if status < 0 {
            release_provider();
            deregister_client();
            return status;
        }

        let port = derive_port();
        if port == 0 {
            close_listen_socket();
            release_provider();
            deregister_client();
            return STATUS_UNSUCCESSFUL;
        }

        status = bind_listen_socket(port);
        if status < 0 {
            close_listen_socket();
            release_provider();
            deregister_client();
            return status;
        }

        (*state).thread_should_stop = false;
        (*state).thread_exited = false;
        if !init_event(addr_of_mut!((*state).exit_event)) {
            close_listen_socket();
            release_provider();
            deregister_client();
            return STATUS_UNSUCCESSFUL;
        }
        reset_event(addr_of_mut!((*state).exit_event));

        let create_thread = match ps_create_thread_fn() {
            Some(f) => f,
            None => {
                close_listen_socket();
                release_provider();
                deregister_client();
                return STATUS_UNSUCCESSFUL;
            }
        };

        let mut handle = 0usize;
        status = create_thread(
            &mut handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            null_mut(),
            server_thread,
            null_mut(),
        );
        if status < 0 {
            close_listen_socket();
            release_provider();
            deregister_client();
            return status;
        }
        (*state).thread_handle = handle;

        STATUS_SUCCESS
    }
}

pub unsafe fn stop_server() {
    unsafe {
        let state = addr_of_mut!(G_WSK);
        (*state).thread_should_stop = true;

        if (*state).thread_handle != 0 {
            close_connection();
            if let Some(wait) = ke_wait_fn() {
                let mut timeout: i64 = -20_000_000;
                wait(
                    addr_of_mut!((*state).exit_event) as *mut c_void,
                    EXECUTIVE,
                    KERNEL_MODE_WAIT,
                    NON_ALERTABLE,
                    &mut timeout,
                );
            }
            if let Some(close) = zw_close_fn() {
                close((*state).thread_handle);
            }
            (*state).thread_handle = 0;
        }

        close_connection();
        close_listen_socket();
        release_provider();
        deregister_client();

        (*state).port = 0;
    }
}
