// Copyright (c) 2026 渟雲. All rights reserved.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[path = "../../src/consts.rs"]
pub mod consts;
#[path = "../../src/protocol.rs"]
pub mod protocol;

pub(crate) const SECURE_KEY: u64 = 0xBEEFDEADFEEDCAFE;
#[path = "../../src/sha256.rs"]
pub mod sha256;
#[path = "../../src/text.rs"]
pub mod text;
#[path = "../../src/types.rs"]
pub mod types;
#[path = "../../src/xxh32.rs"]
pub mod xxh32;

pub mod api;
pub use api::*;
mod backend;
mod helpers;
#[cfg(feature = "native")]
mod native;
mod scan;
#[cfg(feature = "driver")]
mod session;
#[cfg(feature = "driver")]
mod transport;
