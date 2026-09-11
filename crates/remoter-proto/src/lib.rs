//! The protocol layer: one interface every session speaks through.
//!
//! See `docs/architecture/overview.md` and `docs/architecture/session-pipeline.md`.
//!
//! The organising decision, from ADR-0003: an adapter receives an
//! **already-connected transport** rather than dialling out itself. Jump host
//! chains, proxies and tunnels therefore work identically for every protocol,
//! including plugin-provided ones, and no adapter contains gateway logic.
//!
//! # What lives here
//!
//! | Module | Owns |
//! |---|---|
//! | [`transport`] | [`Transport`], [`TcpTransport`], [`HostPort`] |
//! | [`gateway`] | [`HopDialer`], chain validation, the walk that builds one transport out of several machines |
//! | [`protocol`] | [`Protocol`], [`Session`], [`SettingsSchema`] |
//! | [`credentials`] | [`CredentialProvider`] — secrets borrowed, never handed over |
//! | [`hostkey`] | [`TrustStore`], [`Fingerprint`], and what happens when a key changes |
//! | [`event`] | [`SessionEvent`], the bounded coalescing [`EventSink`] |
//! | [`framebuffer`] | The graphical vocabulary RDP and VNC share: rectangles, encodings, the frame format, [`FrameCoalescer`] |
//! | [`supervisor`] | [`SessionSupervisor`], one task per session, and the registry |
//! | [`error`] | [`ProtocolError`], the failure taxonomy |
//!
//! # What does not live here
//!
//! No protocol's wire format, and no dependency on `remoter-vault`. The vault
//! implements [`CredentialProvider`] and [`TrustStore`]; the SSH crate
//! implements [`HopDialer`] and [`Protocol`]. Dependencies point downward only.
//!
//! # Rules this crate is built around
//!
//! - **No secret is ever formatted.** Credentials are borrowed inside a
//!   closure; keystrokes, clipboard contents, prompt answers and terminal
//!   output all have hand-written redacting `Debug` implementations, because
//!   this is the layer where secrets are actually in flight.
//! - **Bounded channels only.** An unbounded channel is an unbounded memory
//!   leak waiting for a fast remote host.
//! - **A panicked session is destroyed, never resumed** (ADR-0011).
//! - **A leaked session is a correctness bug**: the process holds credentials.

#![doc(html_no_source)]

pub mod coalesce;
pub mod credentials;
pub mod error;
pub mod event;
pub mod framebuffer;
pub mod gateway;
pub mod hostkey;
pub mod protocol;
pub mod supervisor;
pub mod transport;

pub use coalesce::{DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_FRAME_BYTES, OutputCoalescer};
pub use credentials::{
    CredentialKind, CredentialProvider, CredentialProviderExt, KeyBorrow, KeyBorrowWith,
    NoCredentials,
};
pub use error::{
    AlgorithmKind, CertificateProblem, FailureReport, NextAction, ProtocolError, Stage,
};
pub use event::{
    CloseReason, DEFAULT_EVENT_CAPACITY, EventSink, ProgressUpdate, Prompt, PromptAnswer, PromptId,
    PromptKind, SessionEvent, SessionWarning, TrustedHostKey, event_channel,
};
pub use framebuffer::{
    COPY_RECT_PAYLOAD_BYTES, CursorUpdate, DEFAULT_MAX_PENDING_BYTES, FLAG_KEYFRAME,
    FRAME_HEADER_BYTES, FRAME_RECT_BYTES, FrameCoalescer, FrameEncoding, FrameMessage, FrameRect,
    FrameUpdate, MESSAGE_CURSOR, MESSAGE_FRAMEBUFFER, PixelFormat, Rect,
};
pub use gateway::{
    ChainBuilder, DEFAULT_HOP_TIMEOUT, EntryDialer, GatewayChainPlan, HopConfig, HopDialer,
    TcpDialer,
};
pub use hostkey::{
    ChangedHostKey, Fingerprint, HostKeyDecision, HostKeyOutcome, KnownKey, OfferedKey,
    TrustSource, TrustStore, UnknownHostKey, verify_host_key,
};
pub use protocol::{
    Capabilities, ClipboardData, ClipboardFormats, ClipboardOp, ClipboardPolicy, ClipboardSupport,
    DefaultOrigin, InputEvent, Modifiers, OptionLabel, PointerButtons, Protocol, Session,
    SessionKind, SettingField, SettingKind, SettingOption, SettingsSchema, connection_target,
};
pub use supervisor::{
    SessionCommand, SessionContext, SessionHandle, SessionId, SessionInfo, SessionSpec,
    SessionState, SessionSupervisor, SupervisorConfig, run_session,
};
pub use transport::{
    HostPort, SyncTransport, TcpTransport, Transport, TransportKind, TransportPeer,
};
