// Remoter — a modern, cross-platform remote connection manager.
// Copyright (C) 2026 The Remoter contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version. See the LICENSE file in the repository root.
//
// Additional permission under GNU GPL version 3 section 7 applies to
// WebAssembly plugins — see LICENSE-EXCEPTION.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tracing_subscriber::EnvFilter;

fn main() {
    apply_linux_rendering_workarounds();
    install_panic_hook();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("REMOTER_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Before any vault can be opened: the row recording an unlock is written by
    // the unlock itself, and it should name who unlocked.
    remoter_ipc::identify_process();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(remoter_ipc::AppState::new())
        .invoke_handler(remoter_ipc::handler())
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("could not start the application: {e}");
            std::process::exit(1);
        });
}

/// Works around a WebKitGTK crash on Wayland with proprietary GPU drivers.
///
/// WebKitGTK imports its rendered frames through DMA-BUF. On Wayland with the
/// NVIDIA driver that import fails, and the failure surfaces as a fatal Wayland
/// protocol error the moment the web view is realised — the window never
/// appears. Disabling that one path keeps accelerated compositing; it only
/// changes how the buffer reaches the compositor.
///
/// This is set here rather than left to the user because a connection manager
/// that exits silently on launch is indistinguishable from a broken install.
/// `REMOTER_KEEP_DMABUF=1` opts out, which is what you want when measuring the
/// framebuffer path (see docs/architecture/rendering.md) and need to know
/// whether the native renderer is actually in use.
#[cfg(target_os = "linux")]
fn apply_linux_rendering_workarounds() {
    // Only under Wayland: the X11 path does not use the DMA-BUF renderer, and
    // overriding a value the user set themselves would be rude.
    let on_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let already_set = std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some();
    let opted_out = std::env::var_os("REMOTER_KEEP_DMABUF").is_some();

    if on_wayland && !already_set && !opted_out {
        // SAFETY: `set_var` is unsafe because another thread reading the
        // environment concurrently would be a data race. This runs as the first
        // statement of `main`, before the Tokio runtime, before GTK
        // initialisation and before any thread is spawned, so this thread is
        // the only one in the process.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_rendering_workarounds() {}

/// Logs the panic **location**, never the payload.
///
/// A payload can contain a formatted value, and a formatted value can contain
/// a secret. See ADR-0011 and CLAUDE.md §0.2.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let where_ = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_owned());
        tracing::error!("panic at {where_} (payload withheld: it may contain a secret)");
    }));
}
