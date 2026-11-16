// Copyright (c) 2026 渟雲. All rights reserved.

use core::mem::{offset_of, size_of};

use crate::types::{IoStackLocation, Irp, Requests};

const _: () = assert!(size_of::<Requests>() == 192);

const _: () = assert!(size_of::<Irp>() == 0xD0);
const _: () = assert!(offset_of!(Irp, mdl_address) == 0x08);
const _: () = assert!(offset_of!(Irp, flags) == 0x10);
const _: () = assert!(offset_of!(Irp, associated_irp) == 0x18);
const _: () = assert!(offset_of!(Irp, thread_list_entry) == 0x20);
const _: () = assert!(offset_of!(Irp, io_status) == 0x30);
const _: () = assert!(offset_of!(Irp, _user_event) == 0x50);
const _: () = assert!(offset_of!(Irp, current_stack_location) == 0xB8);

const _: () = assert!(size_of::<IoStackLocation>() == 0x48);
const _: () = assert!(offset_of!(IoStackLocation, control) == 0x03);
const _: () = assert!(offset_of!(IoStackLocation, parameters) == 0x08);
const _: () = assert!(offset_of!(IoStackLocation, device_object) == 0x28);
const _: () = assert!(offset_of!(IoStackLocation, file_object) == 0x30);
const _: () = assert!(offset_of!(IoStackLocation, completion_routine) == 0x38);
const _: () = assert!(offset_of!(IoStackLocation, context) == 0x40);
