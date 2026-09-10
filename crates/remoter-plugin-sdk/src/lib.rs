//! Guest-side helpers for writing Remoter plugins.
//!
//! **Licensed Apache-2.0 OR MIT, not GPL** — see `remoter-plugin-abi` and
//! ADR-0009. Plugin authors compile against this crate, so it must never pull
//! in copyleft code.
//!
//! The ABI is unstable until v1.2. This crate exists in v0.1 so that the
//! licence boundary is established from the first commit rather than
//! retrofitted, which ADR-0009 explains cannot be done later without unanimous
//! contributor consent.

#![no_std]
#![doc(html_no_source)]

pub use remoter_plugin_abi as abi;

/// The ABI version this SDK targets.
pub const fn abi_version() -> u32 {
    abi::ABI_VERSION
}
