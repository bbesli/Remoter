//! VNC sessions, over `vnc-rs` — with the RFB handshake and the server message
//! stream owned here rather than by the library.
//!
//! Pure Rust on purpose: this code parses attacker-controlled bytes from a host
//! that may already be compromised, inside a process holding every credential
//! the user owns. See ADR-0003 and ADR-0013.
//!
//! # What lives here
//!
//! | Module | Owns |
//! |---|---|
//! | [`protocol`] | [`VncProtocol`] — the `Protocol` implementation the session pipeline calls |
//! | [`handshake`] | The vocabulary of RFC 6143 §7.1: versions, and what a server offered |
//! | [`negotiate`] | RFC 6143 §7.1.1 and §7.1.2 performed here: the version floor, and the security-type choice |
//! | [`gate`] | The `Transport` between the socket and `vnc-rs`: a replayed handshake, and a bounded server stream |
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
//! - **The client decides what it will accept, and says what it accepted**
//!   (ADR-0013). The RFB version is bracketed by a floor as well as a ceiling,
//!   the security type is selected here under a policy that refuses `None`
//!   whenever a credential is configured, and the type that was selected is
//!   reported rather than inferred. This is the trust model
//!   `remoter_proto::hostkey` sets for SSH, applied to a graphical protocol.
//! - **Nothing the far end sends sizes an allocation.** [`gate`] parses the
//!   server message stream (RFC 6143 §7.6) and checks every length before
//!   `vnc-rs` can act on it. The encodings this build promises are exactly the
//!   ones that makes possible; see [`encoding`].
//! - **Pixels leave through the shared framebuffer format**, not a private one.
//!   [`remoter_proto::framebuffer`] defines the header, the dirty rectangles
//!   and the keyframe flag, and the interface renders RDP and VNC without
//!   knowing which it has. One supervisor, one event bus, one wire format.
//! - **Every wire-level detail cites RFC 6143.** The version handshake is
//!   §7.1.1, the security handshake §7.1.2, `SecurityResult` §7.1.3, VNC
//!   authentication §7.2.2, `ServerInit` §7.3.2, `SetPixelFormat` §7.5.1,
//!   `SetEncodings` §7.5.2, `FramebufferUpdateRequest` §7.5.3, `KeyEvent`
//!   §7.5.4, `PointerEvent` §7.5.5, `ClientCutText` §7.5.6, `FramebufferUpdate`
//!   §7.6.1, `SetColourMapEntries` §7.6.2, `Bell` §7.6.3, `ServerCutText`
//!   §7.6.4, the encodings §7.7, and the Cursor and DesktopSize
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
//! **No compressed encoding is negotiated.** Tight, ZRLE (RFC 6143 §7.7.6) and
//! TRLE (§7.7.5) were withdrawn in ADR-0013, and RRE (§7.7.3) and Hextile
//! (§7.7.4) were never offered because `vnc-rs` has no decoder for them. The
//! reason for the first three is in [`encoding`] and is worth stating plainly
//! here too: nothing outside `vnc-rs` can bound what its compressed decoders
//! allocate, and an allocation failure aborts the process rather than unwinding
//! into one failed tab. A desktop over a slow link therefore sends raw pixels,
//! and CopyRect is the only saving left. That is a real cost, paid knowingly.
//!
//! **VeNCrypt is not available.** `docs/security/transport-security.md` names
//! "VNC over TLS (`VeNCrypt`) … where the server supports it" as Remoter's
//! second position after tunnelling. This build implements security types 1 and
//! 2 and refuses everything else, so a VeNCrypt-only server cannot be connected
//! to. The adapter says exactly that, naming what the server offered, rather
//! than reporting a generic handshake failure — see [`negotiate`] — but the
//! capability itself is absent and the document is ahead of the code.
//!
//! **The desktop cannot be resized from this end.** RFC 6143 §7.8.2 is
//! server-to-client. See [`protocol::capabilities`].
//!
//! **The clipboard is reported as unsupported, and paste still works.** RFC
//! 6143 §7.6.4 text arrives and raises
//! [`remoter_proto::SessionEvent::ClipboardOffer`], but the session contract
//! has no event that carries clipboard *content*, so
//! [`remoter_proto::ClipboardOp::Request`] cannot be answered. `ClipboardSupport`
//! has no one-direction value, so [`protocol::capabilities`] reports `None`
//! rather than promising a control that fails in the user's hand. The text is
//! also deliberately not retained while it cannot be delivered: the most common
//! thing on an administrator's clipboard is a password, and holding one in
//! memory for the life of a tab in exchange for nothing is not a trade worth
//! making.
//!
//! # Defects in `vnc-rs` 0.5.3
//!
//! Recorded because a reader of this crate needs to know where its guarantees
//! stop. None of them can be fixed *in* the library from here. What ADR-0013
//! changed is how many of them a server can still reach: [`gate`] stands
//! between the socket and the library and refuses the input that reaches most
//! of these, so they are listed with what now happens rather than as open
//! hazards.
//!
//! **Closed — the library can no longer be put in these positions.**
//!
//! 1. **`ServerMsg::read` reaches `unimplemented!()` on `SetColorMapEntries`**
//!    (RFC 6143 §7.6.2, server message type 1): a server could panic the
//!    library's decoding task with one byte. [`gate`] refuses message type 1
//!    outright — this build always asks for true colour (§7.5.1), so a
//!    conforming server has no reason to send one — and the session ends with a
//!    named protocol violation instead of a panic.
//! 2. **`AuthResult::from(u32)` transmutes.** RFC 6143 §7.2.2's
//!    `SecurityResult` is a `U32` and only 0 and 1 are defined; a server
//!    sending 2 produced **undefined behaviour** in a two-variant
//!    `#[repr(u32)]` enum, in the branch that decides whether authentication
//!    failed. [`gate`] reads that word itself, matches it on a plain `u32`, and
//!    hands the library a synthetic zero. The library now only ever sees `0`.
//! 3. **A rectangle's declared size is allocated before it is read.** A raw
//!    rectangle of 65535 by 65535 is a 17 GiB `Vec::with_capacity`, which
//!    **aborts** rather than unwinds. [`gate`] checks every rectangle against
//!    the framebuffer the server declared, and the framebuffer against
//!    [`gate::MAX_FRAMEBUFFER_PIXELS`], before the header reaches the library.
//! 4. **`ServerInit`'s name-length is a `U32` allocated before the name
//!    arrives** — `0xffff_ffff` is a 4 GiB `vec![0; n]`. Bounded by
//!    [`gate::MAX_DESKTOP_NAME_BYTES`]. *This vector was missing from the list
//!    this comment used to carry.*
//! 5. **`ServerCutText`'s length is a `U32` with the same shape** (§7.6.4).
//!    Bounded by [`gate::MAX_CLIPBOARD_BYTES`]. *Also missing from the old
//!    list.*
//! 6. **The Cursor pseudo-encoding's size is not bounded by the framebuffer**
//!    (§7.8.1) — its `x` and `y` are a hot spot, not a position — so it was a
//!    second route to the allocation in 3. Bounded by
//!    [`gate::MAX_CURSOR_DIMENSION`].
//! 7. **`From<u32> for VncEncoding` folds every unrecognised encoding number
//!    onto `Raw`**, so a rectangle in an unpromised encoding was read as
//!    `width * height * 4` raw bytes and desynchronised the stream. [`gate`]
//!    refuses a rectangle in an encoding this connection did not ask for.
//!
//! **Open — and the reason the compressed encodings are not negotiated.**
//!
//! 8. **The ZRLE decoder indexes its palette without a bounds check**, and
//!    **its run lengths are unbounded**: a run length is a sequence of `0xff`
//!    bytes *inside the zlib stream*, so a few kilobytes of compressed input
//!    can ask the decoder to grow a buffer to terabytes. The first is a panic
//!    in a task the library spawned — one failed tab, which ADR-0011 contains.
//!    The second is an allocation failure, which **aborts**. A parser in front
//!    of the library can bound the compressed length and cannot see inside it,
//!    so ADR-0013's answer is that ZRLE and TRLE are not promised at all. The
//!    same reasoning, plus a wire format no parser can frame without
//!    reimplementing it, withdraws Tight.
//! 9. **`uninit_vec` sets a length over uninitialised memory** and reads into
//!    it. This crate is `#![forbid(unsafe_code)]`; its dependency is not.
//! 10. **`ServerCutText` is decoded as UTF-8.** RFC 6143 §7.6.4 is Latin-1, so
//!     every byte above `0x7f` becomes `U+FFFD`. See [`clipboard`].
//! 11. **`ClientCutText` is encoded as UTF-8.** Same section, same mistake in
//!     the other direction, and the reason [`clipboard::to_wire_text`]
//!     restricts to ASCII rather than to Latin-1.
//! 12. **The password `String` is dropped without being zeroized.** It is the
//!     one secret this crate has to hand over rather than lend.
//! 13. **A desktop resize does not move the update request.** `VncClient`
//!     builds every `FramebufferUpdateRequest` (RFC 6143 §7.5.3) from the size
//!     it read at `ServerInit` and never revises it when RFC 6143 §7.8.2
//!     changes the desktop, and `X11Event` offers no way to ask for a different
//!     rectangle. A desktop that *shrinks* is fine; one that **grows** leaves
//!     the new region unrequested and therefore unpainted. The adapter reports
//!     the new size and asks for a full refresh of what it can, which is all
//!     the library's surface allows. `wire_tests` pins the behaviour so that a
//!     fixed `vnc-rs` fails the assertion rather than passing silently.
//!
//! # Containment, stated accurately
//!
//! This comment used to say that every one of the library's defects was
//! contained to a single tab. That was **not true**, and saying so is worse
//! than saying nothing: a panic in a spawned task unwinds and ends one session
//! (ADR-0011), but an allocation failure calls `handle_alloc_error`, which
//! **aborts the process** — every other session, and the unlocked vault, with
//! it. Items 3 to 7 above were aborts, not panics. They are closed now because
//! [`gate`] refuses their input, not because the library changed; item 8 is
//! still an abort and is closed only by not negotiating the encodings that
//! reach it.

#![doc(html_no_source)]
#![forbid(unsafe_code)]

pub mod clipboard;
pub mod encoding;
pub mod error;
pub mod frame;
pub mod gate;
pub mod handshake;
pub mod keymap;
pub mod negotiate;
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
pub use encoding::{CursorMode, EncodingPreference, RfbEncoding, WITHDRAWN, encoding_list};
pub use error::{VNC_ID, map_vnc, vnc_protocol_id};
pub use frame::{Decoded, FrameTranslator};
pub use gate::{GateFault, GateShared, GatedTransport};
pub use handshake::{HandshakeFacts, RfbVersion};
pub use keymap::{EXTENDED, function_keysym, rfb_keysym};
pub use negotiate::{Negotiated, negotiate, select_security};
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
    fn the_session_is_a_framebuffer_one_and_promises_no_clipboard_it_cannot_serve() {
        let caps = capabilities();
        assert_eq!(caps.kind, remoter_proto::SessionKind::Framebuffer);
        // `ClipboardOp::Request` cannot be answered — the session contract has
        // no event carrying clipboard content — so the capability must not say
        // the interface may ask.
        assert_eq!(caps.clipboard, remoter_proto::ClipboardSupport::None);
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
