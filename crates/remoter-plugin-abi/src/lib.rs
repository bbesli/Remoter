//! The Remoter plugin ABI: types and wire format shared by the host and by
//! WebAssembly plugins.
//!
//! **This crate is licensed Apache-2.0 OR MIT, not GPL.** Plugin authors
//! compile against it, and the licence exception in `LICENSE-EXCEPTION` rests
//! on their never incorporating copyleft code. Adding a GPL dependency here
//! breaks that silently — CI checks it, but do not rely on CI to catch what
//! you already know.
//!
//! The ABI is **unstable** until v1.2. It is versioned so that a host can
//! refuse a module it does not understand rather than guessing.

#![no_std]
#![doc(html_no_source)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// ABI version this crate defines. A host refuses a module declaring a version
/// it does not implement.
pub const ABI_VERSION: u32 = 1;

/// What kind of session a protocol produces. Drives which UI surface a tab
/// renders and which controls it offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Terminal,
    Framebuffer,
    FileTransfer,
}

/// Clipboard support a protocol adapter offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardSupport {
    None,
    Text,
    TextAndFiles,
}

/// What an adapter can do. The frontend asks rather than hardcoding, so a
/// plugin protocol gets the same treatment as a built-in one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub kind: SessionKind,
    pub resizable: bool,
    pub clipboard: ClipboardSupport,
    pub file_transfer: bool,
    pub audio: bool,
    pub printing: bool,
    pub multi_monitor: bool,
    pub recordable: bool,
}

/// A plugin's self-description, returned by `plugin_manifest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub abi: u32,
    pub license: String,
    pub protocols: Vec<String>,
}
