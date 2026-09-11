//! VNC sessions, over `vnc-rs`.
//!
//! Pure Rust on purpose: this code parses attacker-controlled bytes from a host
//! that may already be compromised, inside a process holding every credential
//! the user owns. See ADR-0003.
//!
//! # What lives here
//!
//! | Module | Owns |
//! |---|---|
//! | [`protocol`] | [`VncProtocol`] — the `Protocol` implementation the session pipeline calls |
//! | [`handshake`] | Watching RFC 6143 §7.1's version and security handshake go past, so a failure can be explained |
//! | [`security`] | The security-type registry, what VNC authentication actually is, and how exposed a clear-text session is |
//! | [`encoding`] | Which encodings to promise, and which this build must not promise |
//! | [`frame`] | The checked boundary between a decoded rectangle and [`remoter_proto::framebuffer`] |
//! | [`keymap`] | X11 keysyms, which are not scancodes |
//! | [`pointer`] | The button mask, and a wheel RFB has no field for |
//! | [`clipboard`] | Latin-1, and the two places it loses characters |
//! | [`session`] | The pull-based loop, and the way a session ends |
//! | [`error`] | `vnc-rs`'s failures, mapped onto the taxonomy |
//!
//! # The rules this crate is built around
//!
//! - **The transport is injected, never dialled** (ADR-0003). Nothing here
//!   opens a socket; `tests/no_dialling.rs` checks the source for it, and every
//!   session test runs over an in-memory pipe, which could not work otherwise.
//!   The consequence that matters is that **VNC through an SSH tunnel needs no
//!   code in this crate**: the chain is built before `connect` is called, and
//!   the only thing that changes here is that the clear-text warning stops
//!   being raised.
//! - **Pixels leave through the shared framebuffer format**, not a private one.
//!   [`remoter_proto::framebuffer`] defines the header, the dirty rectangles
//!   and the keyframe flag, and the interface renders RDP and VNC without
//!   knowing which it has. One supervisor, one event bus, one wire format.
//! - **Every wire-level detail cites RFC 6143.** The version handshake is
//!   §7.1.1, the security handshake §7.1.2, VNC authentication §7.2.2,
//!   `ServerInit` §7.3.2, `SetPixelFormat` §7.5.1, `SetEncodings` §7.5.2,
//!   `FramebufferUpdateRequest` §7.5.3, `KeyEvent` §7.5.4, `PointerEvent`
//!   §7.5.5, `ClientCutText` §7.5.6, `FramebufferUpdate` §7.6.1, `Bell` §7.6.3,
//!   `ServerCutText` §7.6.4, the encodings §7.7, and the Cursor and DesktopSize
//!   pseudo-encodings §7.8.1 and §7.8.2. Where something is **not** in the RFC
//!   — Tight, LastRect, `SetDesktopSize` — it is named as a registry entry or a
//!   community extension rather than given a section number it does not have.
//! - **A cancelled session frees its socket deterministically.** Dropping the
//!   client is what does it, which means every failure path gets it for free;
//!   see [`session`].
//! - **No secret is formatted.** The password is borrowed from the provider and
//!   moved straight into the connector, keysyms are redacted wherever they are
//!   logged, and no error carries a server-supplied string.
//!
//! # What this build does not do, and why
//!
//! Stated here rather than discovered later.
//!
//! **RRE (RFC 6143 §7.7.3) and Hextile (§7.7.4) are not negotiated.** `vnc-rs`
//! 0.5.3 has no decoder for either — the enum variants exist as commented-out
//! lines in its source. Promising an encoding whose decoder does not exist does
//! not lose a rectangle, it desynchronises the stream, because the library
//! folds every unrecognised encoding number onto `Raw` and would then read
//! `width * height * 4` bytes of a much shorter rectangle. Both are legacy
//! schemes superseded by ZRLE, and every server that speaks them also speaks
//! Raw. See [`encoding`].
//!
//! **VeNCrypt is not available.** `docs/security/transport-security.md` names
//! "VNC over TLS (`VeNCrypt`) … where the server supports it" as Remoter's
//! second position after tunnelling. `vnc-rs` implements security types 1 and 2
//! and refuses everything else, so a VeNCrypt-only server cannot be connected
//! to. The adapter says exactly that, naming what the server offered, rather
//! than reporting a generic handshake failure — see [`handshake`] — but the
//! capability itself is absent and the document is ahead of the code.
//!
//! **The desktop cannot be resized from this end.** RFC 6143 §7.8.2 is
//! server-to-client. See [`protocol::capabilities`].
//!
//! **Remote clipboard *content* is offered but not delivered.** RFC 6143 §7.6.4
//! text arrives, and the session raises
//! [`remoter_proto::SessionEvent::ClipboardOffer`] — but the session contract
//! has no event that carries clipboard content to the interface, so there is
//! nowhere to put the text. It is deliberately not retained while it cannot be
//! delivered: the most common thing on an administrator's clipboard is a
//! password, and holding one in memory for the life of a tab in exchange for
//! nothing is not a trade worth making.
//!
//! # Defects in `vnc-rs` 0.5.3
//!
//! Recorded because a reader of this crate needs to know where its guarantees
//! stop. None of them can be fixed from here; each is a candidate upstream
//! patch. What *is* done here is to keep a conforming server from ever putting
//! the library in these positions, and to make sure that when a hostile one
//! does, the blast radius is one tab (ADR-0011).
//!
//! 1. **`ServerMsg::read` reaches `unimplemented!()` on `SetColorMapEntries`**
//!    (RFC 6143 §7.6.2, server message type 1). A server can panic the
//!    library's decoding task by sending one byte. The adapter always sends
//!    `SetPixelFormat` with `true-colour-flag` set, so a conforming server has
//!    no reason to send it; a hostile one panics a task the library spawned,
//!    which ends the session and nothing else.
//! 2. **The ZRLE decoder indexes its palette without a bounds check.** An
//!    indexed-RLE tile whose index is past the palette panics. Same blast
//!    radius, same reason it cannot be prevented from here.
//! 3. **The ZRLE decoder's run lengths are unbounded.** A run length is a
//!    sequence of `0xff` bytes inside the zlib stream, so a few hundred
//!    kilobytes of compressed input can ask for billions of pixels. The
//!    allocation is not bounded by the tile size.
//! 4. **A rectangle's declared size is allocated before it is read.** A raw
//!    rectangle of 65535 by 65535 is a 17 GiB `Vec::with_capacity`, which
//!    aborts rather than unwinds — the one failure here that is *not* contained
//!    to a tab. It cannot be reached through a conforming server, because a
//!    rectangle that large cannot fit a framebuffer the client was told about;
//!    a hostile one can.
//! 5. **`AuthResult::from(u32)` transmutes.** RFC 6143 §7.2.2's
//!    `SecurityResult` is a `U32` and only 0 and 1 are defined; a server that
//!    sends 2 produces undefined behaviour in a two-variant enum.
//! 6. **`uninit_vec` sets a length over uninitialised memory** and reads into
//!    it. This crate is `#![forbid(unsafe_code)]`; its dependency is not.
//! 7. **`ServerCutText` is decoded as UTF-8.** RFC 6143 §7.6.4 is Latin-1, so
//!    every byte above `0x7f` becomes `U+FFFD`. See [`clipboard`].
//! 8. **`ClientCutText` is encoded as UTF-8.** Same section, same mistake in
//!    the other direction, and the reason [`clipboard::to_wire_text`]
//!    restricts to ASCII rather than to Latin-1.
//! 9. **The password `String` is dropped without being zeroized.** It is the
//!    one secret this crate has to hand over rather than lend.
//! 10. **A desktop resize does not move the update request.** `VncClient`
//!     builds every `FramebufferUpdateRequest` (RFC 6143 §7.5.3) from the size
//!     it read at `ServerInit` and never revises it when RFC 6143 §7.8.2
//!     changes the desktop, and `X11Event` offers no way to ask for a different
//!     rectangle. A desktop that *shrinks* is fine; one that **grows** leaves
//!     the new region unrequested and therefore unpainted. The adapter reports
//!     the new size and asks for a full refresh of what it can, which is all
//!     the library's surface allows. `wire_tests` pins the behaviour so that a
//!     fixed `vnc-rs` fails the assertion rather than passing silently.
//!
//! The `assert!(!security_types.is_empty())` in `VncState::try_start` that
//! `docs/development/verified-apis.md` warns about is, on inspection,
//! unreachable: `SecurityType::read` already returns an error for a zero count
//! in both handshake shapes. That note is corrected rather than repeated.

#![doc(html_no_source)]
#![forbid(unsafe_code)]

pub mod clipboard;
pub mod encoding;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod keymap;
pub mod pointer;
pub mod protocol;
pub mod security;
pub mod session;

#[cfg(any(test, feature = "integration-tests"))]
pub mod testing;

/// The adapter driven end to end against a scripted RFB server.
///
/// A `#[cfg(test)]` module rather than a file under `tests/`, because it needs
/// [`testing`] — which is compiled only for this crate's own tests, so that a
/// scripted server never ships in a release build.
#[cfg(test)]
mod wire_tests;

pub use clipboard::{Transcoded, to_wire_text};
pub use encoding::{CursorMode, EncodingPreference, RfbEncoding, encoding_list};
pub use error::{VNC_ID, map_vnc, vnc_protocol_id};
pub use frame::{Decoded, FrameTranslator};
pub use handshake::{HandshakeFacts, HandshakeObserver, ObservingTransport, RfbVersion};
pub use keymap::{EXTENDED, function_keysym, rfb_keysym};
pub use pointer::{WheelAccumulator, button_mask};
pub use protocol::{
    DEFAULT_HANDSHAKE_TIMEOUT, VNC_AUTH_PASSWORD_BYTES, VncProtocol, capabilities, schema,
};
pub use security::{Exposure, SecurityType, classify_exposure};
pub use session::{VncSession, run_vnc_session};

/// The port a VNC connection uses when nothing on the inheritance path set one:
/// display `:0`, which is 5900. Matches `remoter_core::ProtocolId::default_port`,
/// which is where the resolver actually reads it; repeated here so the adapter
/// can be read on its own.
pub const DEFAULT_PORT: u16 = 5900;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn the_identifier_validates_and_carries_the_well_known_port() {
        let id = vnc_protocol_id().unwrap();
        assert_eq!(id.as_str(), VNC_ID);
        // The resolver reads the default from `remoter-core`; if the two ever
        // disagree, a connection with no port set would dial somewhere else.
        assert_eq!(id.default_port(), Some(DEFAULT_PORT));
    }

    #[test]
    fn the_session_is_a_framebuffer_one_with_text_only_clipboard() {
        let caps = capabilities();
        assert_eq!(caps.kind, remoter_proto::SessionKind::Framebuffer);
        // There is no file clipboard in RFB to switch on.
        assert_eq!(caps.clipboard, remoter_proto::ClipboardSupport::Text);
        assert!(!caps.file_transfer);
        assert!(!caps.audio);
        assert!(!caps.multi_monitor);
    }

    #[test]
    fn the_adapter_can_be_built_and_reports_itself() {
        let protocol = VncProtocol::new().unwrap();
        assert_eq!(remoter_proto::Protocol::id(&protocol).as_str(), VNC_ID);
        assert_eq!(
            remoter_proto::Protocol::capabilities(&protocol),
            capabilities()
        );
        assert!(
            !remoter_proto::Protocol::settings_schema(&protocol)
                .fields()
                .is_empty()
        );
    }
}
