//! RDP sessions, over IronRDP.
//!
//! Pure Rust on purpose: this code parses attacker-controlled bytes from a host
//! that may already be compromised, inside a process holding every credential
//! the user owns. See ADR-0003.
//!
//! # What lives here
//!
//! | Module | Owns |
//! |---|---|
//! | [`protocol`] | [`RdpProtocol`] — the `Protocol` implementation the session pipeline calls |
//! | [`connect`] | The connection sequence of MS-RDPBCGR §1.3.1.1, start to finish |
//! | [`credssp`] | Network Level Authentication: MS-CSSP, and the NTLM it runs on |
//! | [`cert`] | The server certificate as a host key problem: prompt, pin, and a changed one blocked |
//! | [`framed`] | Whole PDUs off an injected transport, and the TLS upgrade |
//! | [`session`] | [`RdpSession`]: the read loop, input, resize, clean disconnect |
//! | [`display`] | Decoded pixels into `remoter_proto::framebuffer`'s format |
//! | [`input`] | Keyboard and pointer into fast-path input |
//! | [`prompt`] | Asking the user something mid-handshake, and getting an answer back |
//! | [`error`] | RDP's failures, mapped onto the taxonomy |
//!
//! # The rules this crate is built around
//!
//! - **The transport is injected, never dialled** (ADR-0003). Nothing in this
//!   crate opens a socket, which is what makes RDP through two SSH bastions the
//!   same code path as RDP on the LAN.
//! - **The certificate is a trust decision, not a warning.** An unpinned one is
//!   a prompt; a *changed* one is a hard failure that can only be replaced by
//!   typing part of the offered fingerprint off the screen. Same model as the
//!   SSH host key, and the same types.
//! - **Pixels leave through the shared framebuffer format**, not a private one,
//!   so one presenter renders RDP and VNC without knowing which it has.
//! - **A cancelled session frees its sockets deterministically.** Nothing here
//!   spawns a task; the connection sequence is a future and the session is
//!   polled by exactly one loop, so cancelling either drops the stream and with
//!   it the transport.
//! - **No secret is formatted.** The password is borrowed inside a closure,
//!   lives in buffers that zero themselves, and every type that could hold one
//!   has a hand-written redacting `Debug`.
//!
//! # What this does, and what it does not
//!
//! Connect to a Windows host over TLS, with or without Network Level
//! Authentication; see the desktop, type, click, scroll, resize the remote
//! display, and disconnect cleanly. Not yet: the clipboard, drive redirection,
//! audio, printing, multiple monitors, or a Remote Desktop Gateway. Each of
//! those is a separate channel, and [`capabilities`] reports every one of them
//! as absent so the interface does not draw a control that does nothing.
//!
//! # Deviations from the specifications and the design documents, and why
//!
//! **The connection sequence is written here rather than delegated to
//! `ironrdp-connector`.** That crate is exactly this state machine and cannot
//! be added to this workspace: it pins `picky =7.0.0-rc.25` with default
//! features, which activate `aes-gcm =0.11.0-rc.4`, while `remoter-import`
//! depends on the released `aes-gcm 0.11`. Cargo carries one or the other, so
//! adding the feature fails every command in the repository rather than only
//! this crate. `Cargo.toml` records the resolver's own error and the three ways
//! out. What the connector is built on — `ironrdp-pdu`'s wire types — resolves
//! cleanly and is what [`connect`] uses, so no PDU below is hand-rolled.
//!
//! **CredSSP and NTLM are written here rather than delegated to `sspi`.** The
//! same class of blocker: `sspi` 0.21 pins `curve25519-dalek =5.0.0-rc.1` on
//! Apple targets while `russh` 0.63 requires the released `^5`, and cargo
//! resolves target-specific dependencies for every target in the graph.
//! [`credssp`] is MS-CSSP and MS-NLMP implemented against their
//! specifications, with known-answer tests against MS-NLMP §4.2.4's published
//! vectors.
//!
//! **Kerberos is not implemented.** Only NTLM. A domain that has disabled NTLM
//! entirely will not authenticate, and is told so rather than left to guess.
//! Kerberos needs a KDC, a realm and an SPN resolved through DNS, and it is a
//! second implementation of comparable size to the first.
//!
//! **The certificate check uses the Mozilla root store, not the platform's.**
//! `docs/security/transport-security.md` says "system trust store via
//! `rustls`". `webpki-roots` is already in the workspace tree and
//! `rustls-native-certs` is not, so a certificate issued by an enterprise CA
//! that the machine trusts reaches the pin prompt instead of validating
//! silently. That is stricter than the document promises rather than looser —
//! the user is asked instead of being trusted — and closing the gap is a
//! dependency decision for the maintainer under CLAUDE.md §8.
//!
//! **The clipboard is not implemented, and [`capabilities`] says so.** The
//! skeleton this crate replaced claimed `ClipboardSupport::Text`, and
//! `docs/features/protocols.md` expects it; MS-RDPECLIP is the channel that
//! would provide it. Claiming it before the channel exists puts a paste button
//! on the tab that silently discards, so the claim was withdrawn rather than
//! the button drawn.
//!
//! **`Protocol::connect` cannot know its session id.** A framebuffer message's
//! header carries one so a presenter can tell two tabs apart, and the trait has
//! no session id in its signature; the trait implementation therefore returns a
//! session numbered zero. [`RdpProtocol::connect_session`] takes the real one
//! and is what a caller that has it — `remoter-ipc` does — should use.
//! Widening the trait is the honest fix and is a change to `remoter-proto`.
//!
//! **The frame format cannot express "use the default pointer".** RDP has a
//! System Pointer Update that says exactly that (MS-RDPBCGR §2.2.9.1.1.4.3);
//! `remoter_proto::CursorUpdate` can carry a shape or say "no pointer at all"
//! and has no third thing to say. A session that switches from a custom cursor
//! back to the arrow keeps the custom one until the next shape change.
//!
//! # Where the wire formats are specified
//!
//! MS-RDPBCGR for the base protocol, MS-RDPEGDI for the drawing orders,
//! MS-RDPRFX for RemoteFX, MS-RDPEDYC for dynamic virtual channels, MS-RDPEDISP
//! for dynamic resize, MS-RDPELE for licensing, MS-CSSP for CredSSP and MS-NLMP
//! for NTLM. Every wire-level detail in this crate names the section it comes
//! from; a field whose meaning is not traceable to a section number is
//! invented, and CLAUDE.md §0.4 forbids inventing protocol behaviour.

#![doc(html_no_source)]
#![forbid(unsafe_code)]

pub mod cert;
pub mod connect;
pub mod credssp;
pub mod display;
pub mod error;
pub mod framed;
pub mod input;
pub mod layout;
pub mod prompt;
pub mod protocol;
pub mod session;

#[cfg(test)]
pub(crate) mod testing;

pub use cert::{CertificateChecker, DeferredVerifier, OfferedCertificate};
pub use connect::{
    Connected, ConnectionConfig, DEFAULT_TIMEOUT, DesktopSize, connect, static_channels,
    with_deadline,
};
pub use credssp::{CredsspClient, Step as CredsspStep};
pub use display::FrameEncoder;
pub use error::{DEFAULT_PORT, RDP_ID, rdp_protocol_id};
pub use framed::Framed;
pub use input::InputEncoder;
pub use layout::{
    DefaultLayout, FALLBACK_KEYBOARD_LAYOUT, KEYBOARD_LAYOUTS, KeyboardLayout, LayoutSource,
    default_layout, keyboard_layout_options,
};
pub use prompt::PromptChannel;
pub use protocol::{RdpProtocol, schema, settings_from, split_account};
pub use session::{RdpSession, capabilities, run_rdp_session};
