//! The `Protocol` trait: one interface every session speaks through.
//!
//! Built-in adapters and plugin adapters implement the same thing, which is
//! what makes a new protocol cheap and a plugin protocol first-class. The
//! normative sketch is in `docs/architecture/overview.md`; this is the
//! definition it points at.
//!
//! Two consequences are worth restating where the code lives:
//!
//! - **Transport is injected, not dialled.** [`Protocol::connect`] receives a
//!   `Box<dyn Transport>`, so jump host chains, SOCKS proxies and SSH tunnels
//!   work identically for RDP and for SSH (ADR-0003).
//! - **Capabilities drive the interface.** The frontend does not hardcode "RDP
//!   has a clipboard"; it asks the adapter.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use bytes::Bytes;
use remoter_core::{EffectiveConnection, ProtocolId, Resolved};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::credentials::CredentialProvider;
use crate::error::ProtocolError;
use crate::event::EventSink;
use crate::transport::{HostPort, Transport};

pub use remoter_plugin_abi::{Capabilities, ClipboardSupport, SessionKind};

/// A protocol adapter.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Stable identifier: `ssh`, `rdp`, `vnc`, `sftp`, or `vendor.myproto`.
    fn id(&self) -> ProtocolId;

    /// What this adapter can do. Drives which controls a tab shows.
    fn capabilities(&self) -> Capabilities;

    /// The schema for this adapter's settings. The interface renders its form
    /// from this, and an importer validates against it.
    fn settings_schema(&self) -> &SettingsSchema;

    /// Establishes a session over an already-connected stream.
    ///
    /// `transport` may be a plain socket or the far end of a three-hop chain;
    /// the adapter cannot tell and must not care. `creds` lends its secret for
    /// the duration of authentication and is not retained past it. `events` is
    /// bounded and coalescing. `cancel` fires when the tab is closed, and the
    /// adapter must release every socket, channel and buffer it holds before
    /// the returned future completes.
    ///
    /// # Errors
    ///
    /// Any [`ProtocolError`] from the Handshake or Authenticate stages.
    async fn connect(
        &self,
        transport: Box<dyn Transport>,
        config: &EffectiveConnection,
        creds: &dyn CredentialProvider,
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<Box<dyn Session>, ProtocolError>;
}

/// A live session.
///
/// `Send` but not `Sync`: a session lives in exactly one task, and commands
/// reach it over a channel rather than through a lock. That is deliberate —
/// ADR-0011 requires that a session task never hold a lock on shared state
/// across decoder code.
#[async_trait]
pub trait Session: Send {
    /// Tells the far end the display changed size.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Unsupported`] where the protocol cannot resize, or a
    /// transport failure.
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError>;

    /// Sends user input.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Unsupported`] for an input kind the protocol has no
    /// encoding for, or a transport failure.
    async fn input(&mut self, input: InputEvent) -> Result<(), ProtocolError>;

    /// Performs a clipboard operation.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Unsupported`] where the protocol or the policy does
    /// not allow it, or a transport failure.
    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError>;

    /// Sends the protocol's clean-disconnect message and releases everything.
    ///
    /// Takes `Box<Self>` so that the session is consumed: there is no session
    /// left to use afterwards, which is what makes "closing a tab releases
    /// every resource" checkable rather than hoped for.
    ///
    /// # Errors
    ///
    /// A transport failure while saying goodbye. The session is gone either
    /// way; the error is diagnostic.
    async fn disconnect(self: Box<Self>) -> Result<(), ProtocolError>;
}

/// Keyboard modifier state, as a bit set.
///
/// A newtype over `u8` rather than a `bitflags` dependency: five flags do not
/// justify a crate, and the constants below are the whole API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Modifiers(u8);

impl Modifiers {
    /// No modifier held.
    pub const NONE: Self = Self(0);
    /// Shift.
    pub const SHIFT: Self = Self(1 << 0);
    /// Control.
    pub const CONTROL: Self = Self(1 << 1);
    /// Alt, or Option.
    pub const ALT: Self = Self(1 << 2);
    /// Meta: Windows, Command, or Super.
    pub const META: Self = Self(1 << 3);
    /// AltGr, which is not Alt and matters on every non-US layout.
    pub const ALT_GRAPH: Self = Self(1 << 4);
    /// Caps Lock is latched. A *lock* state, not a held key: it is here
    /// because RDP synchronises lock states explicitly with a Client
    /// Synchronize Event (MS-RDPBCGR §2.2.8.1.1.3.1.1.5), and a session that
    /// never sends one types in the wrong case until the user notices and
    /// presses the key twice.
    pub const CAPS_LOCK: Self = Self(1 << 5);
    /// Num Lock is latched. Same reason as [`Modifiers::CAPS_LOCK`].
    pub const NUM_LOCK: Self = Self(1 << 6);
    /// Scroll Lock is latched. Same reason as [`Modifiers::CAPS_LOCK`].
    pub const SCROLL_LOCK: Self = Self(1 << 7);

    /// Combines two sets.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every modifier in `other` is held.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether nothing is held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Pointer button state, as a bit set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PointerButtons(u8);

impl PointerButtons {
    /// Nothing pressed.
    pub const NONE: Self = Self(0);
    /// The primary button.
    pub const LEFT: Self = Self(1 << 0);
    /// The secondary button.
    pub const RIGHT: Self = Self(1 << 1);
    /// The middle button.
    pub const MIDDLE: Self = Self(1 << 2);
    /// The first extra button — "back" on most mice. RDP carries it as
    /// `PTRXFLAGS_BUTTON1` in the extended pointer event
    /// (MS-RDPBCGR §2.2.8.1.1.3.1.1.4).
    ///
    /// RFC 6143 §7.5.5 has no equivalent: its eight `button-mask` bits are
    /// buttons 1 to 8, and buttons 4 to 7 are already the wheel. A VNC adapter
    /// therefore has to choose between the community extended-mask extension
    /// and dropping the event, and dropping it is a legitimate answer as long
    /// as it is written down rather than left to be inferred.
    pub const BACK: Self = Self(1 << 3);
    /// The second extra button — "forward" on most mice. RDP's
    /// `PTRXFLAGS_BUTTON2`; see [`PointerButtons::BACK`] for RFB.
    pub const FORWARD: Self = Self(1 << 4);

    /// Combines two sets.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every button in `other` is pressed.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Input travelling towards the remote machine.
///
/// `Debug` is hand-written and redacting. Keystrokes are not merely private,
/// they are frequently *credentials*: the bytes a user types at a `sudo`
/// prompt, into `passwd`, or at a Windows login screen all arrive here. A
/// derived `Debug` plus one `tracing::debug!` on the input path would put them
/// in a log file.
///
/// # A browser key event is neither a scancode nor a keysym
///
/// This is where keyboard-layout bugs live, so the contract is written out
/// rather than left to each adapter to rediscover.
///
/// A `KeyboardEvent` in the WebView carries three things worth having:
///
/// - **`code`** — the physical key, independent of layout. `"KeyA"` is the key
///   where `A` sits on a US keyboard, whatever the user's layout prints on it.
///   This is what maps to a **scancode**, and it is what RDP wants: the Client
///   Keyboard Event carries a PS/2 Set 1 make code (MS-RDPBCGR
///   §2.2.8.1.1.3.1.1.1) and the *server* applies the layout.
/// - **`key`** — the character the layout produced, `"a"` or `"ä"` or
///   `"Dead"`. This is what maps to an **X11 keysym**, and it is what VNC
///   wants: `KeyEvent` carries a keysym (RFC 6143 §7.5.4) and the layout has
///   already been applied by the client.
/// - **`keyCode`** — a deprecated number that is neither. It varies by browser
///   and by layout, it is not a scancode despite the name, and any adapter
///   that treats it as one produces a session that types correctly on a US
///   keyboard and wrongly on a Turkish, German or AZERTY one. It is named here
///   only so that nobody reaches for it.
///
/// The two protocols therefore want different things from the same keypress,
/// and neither can be derived from the other without the layout — which lives
/// in the browser, not in Rust. So [`InputEvent::Key`] carries **both**, and
/// each adapter takes the one it needs. `scancode` is always present because a
/// physical key was always pressed; `keysym` is optional because a key such as
/// a dead key or a bare modifier produces no character at all.
#[derive(Clone, PartialEq, Eq)]
pub enum InputEvent {
    /// Bytes for a terminal, already encoded by the frontend — an escape
    /// sequence, a paste, an IME commit. Terminal input is a byte stream, and
    /// re-deriving it from key events in Rust would be a second, divergent
    /// implementation of what xterm.js already does correctly.
    Bytes(Bytes),
    /// A key transition, for framebuffer protocols. See the type
    /// documentation for why both a scancode and a keysym are carried.
    Key {
        /// The physical key, as a PS/2 Set 1 make code, with the `E0` prefix
        /// represented as bit 8 (`0x100`). Right Control is therefore `0x11d`
        /// and Left Control is `0x1d`, which is exactly the "extended
        /// scancode" convention MS-RDPBCGR §2.2.8.1.1.3.1.1.1 encodes as
        /// `KBDFLAGS_EXTENDED` beside an 8-bit `keyCode`.
        scancode: u32,
        /// The X11 keysym the user's layout produced, where it produced one.
        /// Latin-1 characters are their own code point; everything else uses
        /// the `0x01000000 + code point` form. `None` for a key that produced
        /// no character — a bare modifier, or a dead key mid-composition.
        keysym: Option<u32>,
        /// Modifiers held, and lock states latched, at the time.
        modifiers: Modifiers,
        /// Whether the key went down (`true`) or up.
        pressed: bool,
    },
    /// Pointer movement, buttons and wheel.
    Pointer {
        /// X, in remote display coordinates — remote pixels, after the tab's
        /// zoom and the device pixel ratio have been divided out. Scaling in
        /// the frontend and not here is deliberate: only the frontend knows
        /// what it drew.
        x: u16,
        /// Y, in remote display coordinates.
        y: u16,
        /// Which buttons are down. A full state, not a transition, because
        /// that is what both protocols put on the wire.
        buttons: PointerButtons,
        /// Vertical wheel delta; positive is away from the user, and one
        /// notch is 120, matching RDP's `rotationUnits`
        /// (MS-RDPBCGR §2.2.8.1.1.3.1.1.3) and the `WHEEL_DELTA` every mouse
        /// driver reports. RFB has no delta at all — a notch is a press and
        /// release of button 4 or 5 (RFC 6143 §7.5.5) — so the VNC adapter
        /// divides, and carrying the finer number here is what lets it.
        wheel: i16,
        /// Horizontal wheel delta; positive is to the right. Same units.
        /// Separate from `wheel` because a tilt wheel is a different axis, not
        /// a different sign, and RDP encodes it with its own flag.
        wheel_x: i16,
    },
}

impl fmt::Debug for InputEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => write!(f, "Bytes(<redacted, {} bytes>)", bytes.len()),
            Self::Key {
                scancode,
                keysym,
                modifiers,
                pressed,
            } => {
                // A scancode is a physical position, not a character, so it
                // reveals which key was struck but not which glyph a layout
                // maps it to. It is still input: shown only as a number.
                //
                // The keysym is not shown at all, not even as a number: it
                // *is* the character. Printing it would put the password
                // typed at a Windows login screen into a log one code point
                // per line.
                write!(
                    f,
                    "Key {{ scancode: {scancode}, keysym: {}, modifiers: {:#04x}, pressed: {pressed} }}",
                    if keysym.is_some() {
                        "<redacted>"
                    } else {
                        "None"
                    },
                    modifiers.bits()
                )
            }
            Self::Pointer {
                x,
                y,
                buttons,
                wheel,
                wheel_x,
            } => write!(
                f,
                "Pointer {{ x: {x}, y: {y}, buttons: {:#04x}, wheel: {wheel}, wheel_x: {wheel_x} }}",
                buttons.bits()
            ),
        }
    }
}

/// Which clipboard formats are on offer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClipboardFormats {
    /// Plain text is available.
    pub text: bool,
    /// One or more files are available.
    pub files: bool,
}

/// Clipboard content moving in either direction.
///
/// `Debug` is redacting for the same reason [`InputEvent`]'s is: the single
/// most common thing on a system administrator's clipboard is a password they
/// just copied out of a password manager.
#[derive(Clone, PartialEq, Eq)]
pub enum ClipboardData {
    /// Plain text.
    Text(String),
    /// File names. Transferring the contents is a separate, explicit step.
    Files(Vec<String>),
}

impl fmt::Debug for ClipboardData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => write!(f, "Text(<redacted, {} chars>)", text.chars().count()),
            Self::Files(files) => write!(f, "Files(<{} paths>)", files.len()),
        }
    }
}

/// A clipboard operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOp {
    /// Offer the local clipboard to the remote machine.
    Offer(ClipboardData),
    /// Ask the remote machine for what it offered.
    Request {
        /// Whether files are wanted rather than text.
        files: bool,
    },
    /// Withdraw a previous offer.
    Clear,
    /// Copy the files the remote put on its clipboard into a local folder.
    ///
    /// The user chose the folder. Nothing already in it is overwritten: a name
    /// that is taken gets a number, and a file arrives under a temporary name
    /// until its last byte is written.
    SaveFiles {
        /// The folder, as an absolute local path.
        directory: String,
    },
    /// Stop a [`ClipboardOp::SaveFiles`] in progress.
    CancelSave,
}

/// One entry of a file list the remote copied.
///
/// Described, not transferred: the bytes move only on
/// [`ClipboardOp::SaveFiles`]. `Debug` is redacting like [`ClipboardData`]'s —
/// a file name is not a secret, but it is the user's, and a log is the wrong
/// place for a list of what they copied.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteFile {
    /// Where it sits in what was copied: relative, `/`-separated, and already
    /// stripped of anything that would climb out of the folder it is saved
    /// into. The remote chose it, so it is untrusted text.
    pub path: String,
    /// Its size in bytes, when the remote said.
    pub size: Option<u64>,
    /// Whether it is a folder.
    pub directory: bool,
}

impl fmt::Debug for RemoteFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteFile")
            .field(
                "path",
                &format_args!("<redacted, {} chars>", self.path.chars().count()),
            )
            .field("size", &self.size)
            .field("directory", &self.directory)
            .finish()
    }
}

/// Files moving across a session's clipboard, as the adapter reports them.
#[derive(Clone, PartialEq, Eq)]
pub enum ClipboardFiles {
    /// The remote copied files. Nothing has moved yet.
    Offered {
        /// The first entries, in the remote's order — enough to say what was
        /// copied without carrying a hundred thousand names to the interface.
        files: Vec<RemoteFile>,
        /// How many entries there are in all, folders included.
        total_entries: u32,
        /// How many bytes the files declare in all.
        total_bytes: u64,
    },
    /// The remote's clipboard no longer holds files.
    Withdrawn,
    /// A save is under way.
    Saving {
        /// Bytes written so far.
        done_bytes: u64,
        /// Bytes in the whole save, as the remote declared them.
        total_bytes: u64,
        /// Files finished so far.
        done_files: u32,
        /// Files in the whole save, folders not counted.
        total_files: u32,
    },
    /// One file of a save reached the local folder whole.
    Saved {
        /// Its path in what was copied. Untrusted.
        remote: String,
        /// Where it was written.
        local: String,
        /// Its size.
        bytes: u64,
    },
    /// The whole save finished.
    Finished {
        /// The folder it was saved into.
        directory: String,
        /// How many files arrived.
        files: u32,
        /// How many bytes.
        bytes: u64,
    },
    /// The save stopped short.
    Failed {
        /// A catalogue key saying why.
        reason: String,
    },
    /// The user stopped the save.
    Cancelled,
    /// Something on the remote machine pasted a local file and has now read
    /// the whole of it.
    Sent {
        /// The local file.
        local: String,
        /// Its size.
        bytes: u64,
    },
}

impl fmt::Debug for ClipboardFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offered {
                total_entries,
                total_bytes,
                ..
            } => write!(f, "Offered(<{total_entries} entries, {total_bytes} bytes>)"),
            Self::Withdrawn => f.write_str("Withdrawn"),
            Self::Saving {
                done_bytes,
                total_bytes,
                done_files,
                total_files,
            } => write!(
                f,
                "Saving {{ {done_bytes}/{total_bytes} bytes, {done_files}/{total_files} files }}"
            ),
            Self::Saved { bytes, .. } => write!(f, "Saved(<redacted>, {bytes} bytes)"),
            Self::Finished { files, bytes, .. } => {
                write!(f, "Finished({files} files, {bytes} bytes)")
            }
            Self::Failed { reason } => write!(f, "Failed({reason})"),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Sent { bytes, .. } => write!(f, "Sent(<redacted>, {bytes} bytes)"),
        }
    }
}

/// What clipboard traffic is allowed.
///
/// Defaults follow `docs/security/transport-security.md`: text moves both ways
/// because the user constantly needs it, and **files do not**, because a
/// compromised host should not be able to drop files into the local clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClipboardPolicy {
    /// Local text may be pasted into the session.
    pub text_to_remote: bool,
    /// Remote text may reach the local clipboard.
    pub text_from_remote: bool,
    /// Files may cross in either direction.
    pub files: bool,
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        Self {
            text_to_remote: true,
            text_from_remote: true,
            files: false,
        }
    }
}

impl ClipboardPolicy {
    /// Whether `op` is permitted.
    #[must_use]
    pub const fn permits(&self, op: &ClipboardOp) -> bool {
        match op {
            ClipboardOp::Offer(ClipboardData::Text(_)) => self.text_to_remote,
            ClipboardOp::Offer(ClipboardData::Files(_)) => self.files,
            ClipboardOp::Request { files: true } => self.files,
            ClipboardOp::Request { files: false } => self.text_from_remote,
            ClipboardOp::SaveFiles { .. } => self.files,
            ClipboardOp::Clear | ClipboardOp::CancelSave => true,
        }
    }
}

/// What a settings field holds.
///
/// There is deliberately no `Secret` kind. Protocol settings are an open map
/// carried through import, export and inheritance; a password put in one would
/// travel with all three. Secrets are credentials, and credentials are the
/// vault's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SettingKind {
    /// Free text.
    Text {
        /// Maximum length, in characters.
        max_len: usize,
    },
    /// A whole number within a range.
    Integer {
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// `true` or `false`.
    Boolean,
    /// One of a fixed set of values.
    Choice {
        /// The permitted values, as stored. Their labels live in the message
        /// catalogue, not here.
        options: Vec<String>,
    },
}

/// What to call one offered value on screen.
///
/// Two cases, because a settings value is named in two genuinely different
/// ways and collapsing them costs one of them. `0x0000041F` is "Turkish Q",
/// which is prose and belongs to a translator; `3.8` is an RFB version, which
/// is a wire token and belongs to nobody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OptionLabel {
    /// A message catalogue key, like [`SettingField::label`]. Translated.
    Message {
        /// The key — `settings.keyboardLayout.turkishF`, say.
        key: String,
    },
    /// Text shown exactly as it stands: a wire token, a version number, a
    /// proper name. Never translated, and never a sentence.
    Verbatim {
        /// The text.
        text: String,
    },
}

/// One value a setting offers by name.
///
/// **A named set is not a closed one.** [`SettingKind`] decides what is
/// *valid*; this decides what is worth *offering*. An integer field with a
/// hundred named values still accepts the hundred-and-first — which is the
/// whole point for a keyboard layout, where Microsoft publishes hundreds of
/// identifiers and no list anybody would want to scroll holds them all. Use
/// [`SettingField::options_are_closed`] to tell the two apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingOption {
    /// The value as stored — exactly the string that travels through the
    /// settings map, not a rendering of it.
    pub value: String,
    /// What to call it.
    pub label: OptionLabel,
}

impl SettingOption {
    /// An option whose name comes from the message catalogue.
    #[must_use]
    pub fn message(value: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: OptionLabel::Message { key: key.into() },
        }
    }

    /// An option whose name is shown as it stands.
    #[must_use]
    pub fn verbatim(value: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: OptionLabel::Verbatim { text: text.into() },
        }
    }
}

/// Where a field's default value came from.
///
/// A default that was read off this machine is a different statement from one
/// the adapter chose, and a default that is a *guess* is a third. The interface
/// needs all three: telling a user their keyboard layout was guessed is the
/// difference between "the wrong characters appear and I cannot think why" and
/// "the client said it could not tell, and there is the field to fix it".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultOrigin {
    /// The adapter's own constant. The ordinary case.
    #[default]
    Fixed,
    /// Read from the machine this build is running on.
    Detected,
    /// Detection was attempted and failed; the value is a stand-in. **Say so
    /// on screen** — a silent guess is the failure this variant exists to
    /// prevent.
    Guessed,
}

/// One settings field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingField {
    /// The key it is stored under.
    pub key: String,
    /// The message catalogue key for its label. Not English: every
    /// user-visible string goes through `t()`.
    pub label: String,
    /// What it holds.
    pub kind: SettingKind,
    /// The value used when nothing on the inheritance path set one.
    pub default: Option<String>,
    /// Whether a value must be present.
    pub required: bool,
    /// The values worth offering by name. Empty where there are none.
    ///
    /// Advisory unless [`Self::options_are_closed`]: see [`SettingOption`].
    #[serde(default)]
    pub options: Vec<SettingOption>,
    /// Where [`Self::default`] came from.
    #[serde(default)]
    pub default_origin: DefaultOrigin,
}

impl SettingField {
    /// A field with no default and no requirement.
    #[must_use]
    pub fn new(key: impl Into<String>, label: impl Into<String>, kind: SettingKind) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            kind,
            default: None,
            required: false,
            options: Vec::new(),
            default_origin: DefaultOrigin::Fixed,
        }
    }

    /// The same field, with a default the adapter chose.
    #[must_use]
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self.default_origin = DefaultOrigin::Fixed;
        self
    }

    /// The same field, with a default read off this machine.
    #[must_use]
    pub fn with_detected_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self.default_origin = DefaultOrigin::Detected;
        self
    }

    /// The same field, with a default that is a stand-in for something this
    /// build could not determine. The interface must say so; see
    /// [`DefaultOrigin::Guessed`].
    #[must_use]
    pub fn with_guessed_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self.default_origin = DefaultOrigin::Guessed;
        self
    }

    /// The same field, offering these values by name.
    #[must_use]
    pub fn with_options(mut self, options: Vec<SettingOption>) -> Self {
        self.options = options;
        self
    }

    /// Whether [`Self::options`] is the whole of what this field will accept.
    ///
    /// True only for [`SettingKind::Choice`], which is the one kind that
    /// refuses a value outside its list. Everything else keeps the escape
    /// hatch: the named values are a convenience over a larger space.
    #[must_use]
    pub const fn options_are_closed(&self) -> bool {
        matches!(self.kind, SettingKind::Choice { .. })
    }

    /// The same field, required.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Checks one value against this field.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`], which names the key and never the
    /// value — a settings map is exactly where a mistyped password ends up.
    pub fn validate(&self, value: &str) -> Result<(), ProtocolError> {
        let invalid = |expected: &'static str| ProtocolError::SettingInvalid {
            key: self.key.clone(),
            expected,
        };
        match &self.kind {
            SettingKind::Text { max_len } => {
                if value.chars().count() > *max_len {
                    return Err(invalid("shorter text"));
                }
            }
            SettingKind::Integer { min, max } => {
                let parsed: i64 = value.parse().map_err(|_| invalid("a whole number"))?;
                if parsed < *min || parsed > *max {
                    return Err(invalid("a number within the permitted range"));
                }
            }
            SettingKind::Boolean => {
                if !matches!(value, "true" | "false") {
                    return Err(invalid("`true` or `false`"));
                }
            }
            SettingKind::Choice { options } => {
                if !options.iter().any(|option| option == value) {
                    return Err(invalid("one of the offered values"));
                }
            }
        }
        Ok(())
    }
}

/// An adapter's settings schema.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsSchema {
    fields: Vec<SettingField>,
}

impl SettingsSchema {
    /// A schema over `fields`.
    #[must_use]
    pub fn new(fields: Vec<SettingField>) -> Self {
        Self { fields }
    }

    /// A schema with no settings.
    #[must_use]
    pub const fn empty() -> Self {
        Self { fields: Vec::new() }
    }

    /// The fields, in the order the form should show them.
    #[must_use]
    pub fn fields(&self) -> &[SettingField] {
        &self.fields
    }

    /// The field stored under `key`.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&SettingField> {
        self.fields.iter().find(|field| field.key == key)
    }

    /// Checks a resolved settings map.
    ///
    /// Keys the schema does not know are **not** an error. `remoter-core`
    /// preserves unknown keys verbatim so that opening a vault in an older
    /// build does not silently discard a newer protocol's settings; rejecting
    /// them here would undo that. Use [`unknown_keys`](Self::unknown_keys) to
    /// surface them as a warning.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingRequired`] or [`ProtocolError::SettingInvalid`].
    pub fn validate(
        &self,
        settings: &BTreeMap<String, Resolved<String>>,
    ) -> Result<(), ProtocolError> {
        for field in &self.fields {
            match settings.get(&field.key) {
                Some(resolved) => field.validate(&resolved.value)?,
                None if field.required && field.default.is_none() => {
                    return Err(ProtocolError::SettingRequired {
                        key: field.key.clone(),
                    });
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Keys present in `settings` that this schema does not define.
    #[must_use]
    pub fn unknown_keys<'a>(
        &self,
        settings: &'a BTreeMap<String, Resolved<String>>,
    ) -> Vec<&'a str> {
        settings
            .keys()
            .filter(|key| self.field(key).is_none())
            .map(String::as_str)
            .collect()
    }

    /// The effective string value of `key`: what the connection set, or the
    /// schema's default.
    #[must_use]
    pub fn string<'a>(
        &'a self,
        settings: &'a BTreeMap<String, Resolved<String>>,
        key: &str,
    ) -> Option<&'a str> {
        settings
            .get(key)
            .map(|r| r.value.as_str())
            .or_else(|| self.field(key).and_then(|field| field.default.as_deref()))
    }

    /// The effective integer value of `key`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] if the stored value is not a number.
    pub fn integer(
        &self,
        settings: &BTreeMap<String, Resolved<String>>,
        key: &str,
    ) -> Result<Option<i64>, ProtocolError> {
        let Some(value) = self.string(settings, key) else {
            return Ok(None);
        };
        value
            .parse()
            .map(Some)
            .map_err(|_| ProtocolError::SettingInvalid {
                key: key.to_owned(),
                expected: "a whole number",
            })
    }

    /// The effective boolean value of `key`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] if the stored value is not `true` or
    /// `false`.
    pub fn boolean(
        &self,
        settings: &BTreeMap<String, Resolved<String>>,
        key: &str,
    ) -> Result<Option<bool>, ProtocolError> {
        match self.string(settings, key) {
            None => Ok(None),
            Some("true") => Ok(Some(true)),
            Some("false") => Ok(Some(false)),
            Some(_) => Err(ProtocolError::SettingInvalid {
                key: key.to_owned(),
                expected: "`true` or `false`",
            }),
        }
    }
}

/// The address a resolved connection points at.
///
/// The port comes from the connection, or from the protocol's well-known
/// default when nothing on the inheritance path set one. A plugin protocol with
/// no known default must set a port, and is told so rather than guessed at.
///
/// # Errors
///
/// [`ProtocolError::NoAddress`] if the connection has no host,
/// [`ProtocolError::InvalidPort`] if no port could be determined, and
/// [`ProtocolError::InvalidHost`] if the stored host is not a valid address.
pub fn connection_target(config: &EffectiveConnection) -> Result<HostPort, ProtocolError> {
    if config.host.trim().is_empty() {
        return Err(ProtocolError::NoAddress);
    }
    let port = config
        .port
        .value
        .or_else(|| config.protocol.default_port())
        .ok_or(ProtocolError::InvalidPort)?;
    HostPort::new(config.host.clone(), port)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;
    use remoter_core::{GatewayChain, NodeId, Provenance, ReconnectPolicy, RecordingPolicy};

    fn schema() -> SettingsSchema {
        SettingsSchema::new(vec![
            SettingField::new(
                "terminal",
                "settings.ssh.terminal",
                SettingKind::Text { max_len: 32 },
            )
            .with_default("xterm-256color"),
            SettingField::new(
                "keepalive",
                "settings.ssh.keepalive",
                SettingKind::Integer { min: 0, max: 3600 },
            ),
            SettingField::new(
                "compression",
                "settings.ssh.compression",
                SettingKind::Boolean,
            ),
            SettingField::new(
                "bandwidth",
                "settings.rdp.bandwidth",
                SettingKind::Choice {
                    options: vec!["lan".to_owned(), "broadband".to_owned()],
                },
            ),
            SettingField::new("required-one", "settings.required", SettingKind::Boolean).required(),
        ])
    }

    fn settings(pairs: &[(&str, &str)]) -> BTreeMap<String, Resolved<String>> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_owned(),
                    Resolved::new((*v).to_owned(), Provenance::DefaultAtRoot),
                )
            })
            .collect()
    }

    #[test]
    fn a_valid_settings_map_passes() {
        let map = settings(&[
            ("terminal", "xterm"),
            ("keepalive", "30"),
            ("compression", "false"),
            ("bandwidth", "lan"),
            ("required-one", "true"),
        ]);
        schema().validate(&map).unwrap();
    }

    #[test]
    fn a_missing_required_setting_is_named() {
        let map = settings(&[("terminal", "xterm")]);
        let Err(ProtocolError::SettingRequired { key }) = schema().validate(&map) else {
            panic!("a required setting with no default must be demanded");
        };
        assert_eq!(key, "required-one");
    }

    #[test]
    fn an_invalid_setting_names_the_key_but_never_the_value() {
        // The value is withheld on purpose: a settings map is exactly where a
        // mistyped password ends up.
        let map = settings(&[("keepalive", "hunter2"), ("required-one", "true")]);
        let error = schema().validate(&map).expect_err("not a number");
        let rendered = error.to_string();
        assert!(rendered.contains("keepalive"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn a_number_outside_its_range_is_refused() {
        let map = settings(&[("keepalive", "99999"), ("required-one", "true")]);
        assert!(matches!(
            schema().validate(&map),
            Err(ProtocolError::SettingInvalid { .. })
        ));
    }

    #[test]
    fn a_value_outside_the_offered_choices_is_refused() {
        let map = settings(&[("bandwidth", "carrier-pigeon"), ("required-one", "true")]);
        let error = schema().validate(&map).expect_err("not an offered choice");
        assert!(!error.to_string().contains("carrier-pigeon"));
    }

    #[test]
    fn unknown_keys_are_preserved_rather_than_rejected() {
        // Opening a vault in an older build must not silently discard a newer
        // protocol's settings.
        let map = settings(&[("from-the-future", "1"), ("required-one", "true")]);
        schema().validate(&map).unwrap();
        assert_eq!(schema().unknown_keys(&map), vec!["from-the-future"]);
    }

    #[test]
    fn a_default_applies_when_nothing_on_the_path_set_a_value() {
        let schema = schema();
        let map = settings(&[]);
        assert_eq!(schema.string(&map, "terminal"), Some("xterm-256color"));

        let map = settings(&[("terminal", "vt100")]);
        assert_eq!(schema.string(&map, "terminal"), Some("vt100"));
        assert_eq!(schema.string(&map, "nothing-here"), None);
    }

    #[test]
    fn typed_accessors_report_a_bad_value_by_key() {
        let schema = schema();
        let map = settings(&[("keepalive", "30"), ("compression", "true")]);
        assert_eq!(schema.integer(&map, "keepalive").unwrap(), Some(30));
        assert_eq!(schema.boolean(&map, "compression").unwrap(), Some(true));

        let bad = settings(&[("compression", "yes please")]);
        let error = schema.boolean(&bad, "compression").expect_err("not a bool");
        assert!(!error.to_string().contains("yes please"));
    }

    #[test]
    fn a_named_value_outside_a_choice_is_still_refused() {
        // The escape hatch is the *kind*'s, not the option list's. A `Choice`
        // is closed and says so; anything else keeps accepting values the list
        // does not name, which is what makes a hundred named keyboard layouts
        // a convenience rather than a cage.
        let closed = SettingField::new(
            "bandwidth",
            "settings.rdp.bandwidth",
            SettingKind::Choice {
                options: vec!["lan".to_owned()],
            },
        );
        assert!(closed.options_are_closed());
        assert!(closed.validate("broadband").is_err());

        let open = SettingField::new(
            "keyboard_layout",
            "settings.rdp.keyboard_layout",
            SettingKind::Integer { min: 0, max: 9999 },
        )
        .with_options(vec![SettingOption::message("1055", "layout.turkishQ")]);
        assert!(!open.options_are_closed());
        // Named, and validated because it is in range.
        open.validate("1055").unwrap();
        // Not named, and accepted anyway: there are hundreds of identifiers
        // and the list is not all of them.
        open.validate("1031").unwrap();
        // Still bounded by the kind.
        assert!(open.validate("100000").is_err());
    }

    #[test]
    fn a_default_says_where_it_came_from() {
        // A guessed default and a chosen one are different statements, and the
        // interface has to be able to tell the user which it is looking at.
        let field = SettingField::new("k", "settings.k", SettingKind::Text { max_len: 8 });
        assert_eq!(field.default_origin, DefaultOrigin::Fixed);
        assert_eq!(
            field.clone().with_default("a").default_origin,
            DefaultOrigin::Fixed
        );
        assert_eq!(
            field.clone().with_detected_default("b").default_origin,
            DefaultOrigin::Detected
        );
        let guessed = field.with_guessed_default("c");
        assert_eq!(guessed.default_origin, DefaultOrigin::Guessed);
        assert_eq!(guessed.default.as_deref(), Some("c"));
    }

    #[test]
    fn an_option_is_named_either_by_the_catalogue_or_verbatim() {
        // `0x0409` is "US English", which a translator owns. `3.8` is an RFB
        // version, which nobody owns. One type, two honest answers.
        assert_eq!(
            SettingOption::message("1055", "settings.keyboardLayout.turkishQ").label,
            OptionLabel::Message {
                key: "settings.keyboardLayout.turkishQ".to_owned()
            }
        );
        assert_eq!(
            SettingOption::verbatim("3.8", "3.8").label,
            OptionLabel::Verbatim {
                text: "3.8".to_owned()
            }
        );
    }

    #[test]
    fn a_schema_stored_before_options_existed_still_reads() {
        // `SettingsSchema` is serialisable, and a plugin manifest or a cached
        // copy written by an older build carries neither `options` nor
        // `defaultOrigin`. Both default rather than failing the parse.
        let json = r#"{"fields":[{"key":"terminal","label":"settings.ssh.terminal",
            "kind":{"type":"text","max_len":32},"default":"xterm","required":false}]}"#;
        let schema: SettingsSchema = serde_json::from_str(json).unwrap();
        let field = schema.field("terminal").unwrap();
        assert!(field.options.is_empty());
        assert_eq!(field.default_origin, DefaultOrigin::Fixed);
    }

    #[test]
    fn the_clipboard_defaults_match_the_security_document() {
        // Text both ways, files never — a compromised host must not be able to
        // drop files into the local clipboard.
        let policy = ClipboardPolicy::default();
        assert!(policy.text_to_remote);
        assert!(policy.text_from_remote);
        assert!(!policy.files);

        assert!(policy.permits(&ClipboardOp::Offer(ClipboardData::Text("x".to_owned()))));
        assert!(policy.permits(&ClipboardOp::Request { files: false }));
        assert!(
            !policy.permits(&ClipboardOp::Offer(ClipboardData::Files(vec![
                "/etc/passwd".to_owned()
            ])))
        );
        assert!(!policy.permits(&ClipboardOp::Request { files: true }));
        assert!(!policy.permits(&ClipboardOp::SaveFiles {
            directory: "/tmp".to_owned()
        }));
        assert!(policy.permits(&ClipboardOp::Clear));
        assert!(policy.permits(&ClipboardOp::CancelSave));
    }

    #[test]
    fn input_never_debug_prints_the_keystrokes() {
        // The bytes a user types at a `sudo` prompt arrive as `InputEvent`.
        let typed = InputEvent::Bytes(Bytes::from_static(b"hunter2\n"));
        let rendered = format!("{typed:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted, 8 bytes>"), "{rendered}");

        // A keysym *is* the character the user typed, so it is redacted even
        // though it is only a number: `0x68` in a log is `h`, and the rest of
        // the password follows it one event at a time.
        let key = InputEvent::Key {
            scancode: 0x23,
            keysym: Some(0x68),
            modifiers: Modifiers::SHIFT,
            pressed: true,
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("scancode: 35"), "{rendered}");
        assert!(rendered.contains("keysym: <redacted>"), "{rendered}");
        assert!(!rendered.contains("104"), "{rendered}");

        let modifier_only = InputEvent::Key {
            scancode: 0x2a,
            keysym: None,
            modifiers: Modifiers::NONE,
            pressed: true,
        };
        assert!(format!("{modifier_only:?}").contains("keysym: None"));
    }

    #[test]
    fn a_lock_state_has_a_modifier_bit_of_its_own() {
        // RDP synchronises lock states explicitly; a session that cannot
        // express "Caps Lock is latched" types in the wrong case until the
        // user notices.
        let held = Modifiers::SHIFT.with(Modifiers::CAPS_LOCK);
        assert!(held.contains(Modifiers::CAPS_LOCK));
        assert!(!held.contains(Modifiers::NUM_LOCK));
        assert_eq!(
            Modifiers::CAPS_LOCK
                .with(Modifiers::NUM_LOCK)
                .with(Modifiers::SCROLL_LOCK)
                .bits(),
            0b1110_0000
        );
    }

    #[test]
    fn the_extra_pointer_buttons_are_distinct_from_the_first_three() {
        let pressed = PointerButtons::BACK.with(PointerButtons::FORWARD);
        assert!(pressed.contains(PointerButtons::BACK));
        assert!(pressed.contains(PointerButtons::FORWARD));
        assert!(!pressed.contains(PointerButtons::LEFT));
        assert!(!pressed.contains(PointerButtons::MIDDLE));
    }

    #[test]
    fn the_two_wheel_axes_are_separate_fields_not_a_sign() {
        // A tilt wheel is a different axis; RDP gives it its own flag, and
        // folding it into the vertical delta loses the distinction.
        let tilt = InputEvent::Pointer {
            x: 10,
            y: 20,
            buttons: PointerButtons::NONE,
            wheel: 0,
            wheel_x: -120,
        };
        let rendered = format!("{tilt:?}");
        assert!(rendered.contains("wheel: 0"), "{rendered}");
        assert!(rendered.contains("wheel_x: -120"), "{rendered}");
    }

    #[test]
    fn clipboard_content_never_debug_prints_itself() {
        let copied = ClipboardData::Text("s3cr3t-from-the-password-manager".to_owned());
        let rendered = format!("{copied:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("<redacted, 32 chars>"), "{rendered}");

        // The operation wrapper inherits the redaction rather than undoing it.
        let op = ClipboardOp::Offer(copied);
        assert!(!format!("{op:?}").contains("s3cr3t"));
    }

    #[test]
    fn modifiers_and_buttons_combine_and_test() {
        let held = Modifiers::CONTROL.with(Modifiers::ALT);
        assert!(held.contains(Modifiers::CONTROL));
        assert!(held.contains(Modifiers::ALT));
        assert!(!held.contains(Modifiers::SHIFT));
        assert!(Modifiers::NONE.is_empty());

        let pressed = PointerButtons::LEFT.with(PointerButtons::MIDDLE);
        assert!(pressed.contains(PointerButtons::LEFT));
        assert!(!pressed.contains(PointerButtons::RIGHT));
    }

    /// An `EffectiveConnection` built by hand. `Tree::effective_connection`
    /// is the real producer, but it validates the host on insert, and the
    /// point of two of these tests is what happens when it did not.
    fn effective(host: &str, port: Option<u16>, protocol: &str) -> EffectiveConnection {
        fn root<T>(value: T) -> Resolved<T> {
            Resolved::new(value, Provenance::DefaultAtRoot)
        }
        EffectiveConnection {
            node: NodeId::new(),
            name: "target".to_owned(),
            protocol: ProtocolId::new(protocol).unwrap(),
            host: host.to_owned(),
            port: root(port),
            credential: root(None),
            username: root(None),
            credential_attached: false,
            gateway: root(GatewayChain::direct()),
            connect_timeout_ms: root(None),
            keepalive_secs: root(None),
            settings: BTreeMap::new(),
            on_connect: root(Vec::new()),
            on_disconnect: root(Vec::new()),
            recording: root(RecordingPolicy::Never),
            auto_reconnect: root(ReconnectPolicy::Never),
            icon: root(None),
            colour: root(None),
        }
    }

    #[test]
    fn a_target_falls_back_to_the_protocol_default_port() {
        let target = connection_target(&effective("db-01.internal", None, "ssh")).unwrap();
        assert_eq!(target.to_string(), "db-01.internal:22");

        let target = connection_target(&effective("db-01.internal", Some(2222), "ssh")).unwrap();
        assert_eq!(target.port(), 2222);
    }

    #[test]
    fn a_connection_with_no_address_says_so() {
        assert!(matches!(
            connection_target(&effective("   ", None, "ssh")),
            Err(ProtocolError::NoAddress)
        ));
    }

    #[test]
    fn a_protocol_with_no_known_default_port_must_supply_one() {
        // A plugin protocol is told to set a port rather than guessed at.
        assert!(matches!(
            connection_target(&effective("host.example.com", None, "vendor.myproto")),
            Err(ProtocolError::InvalidPort)
        ));
    }

    #[test]
    fn the_capability_type_is_shared_with_the_plugin_abi() {
        // A plugin protocol gets the same treatment as a built-in one; that is
        // only true if it is literally the same type.
        let caps = Capabilities {
            kind: SessionKind::Terminal,
            resizable: true,
            clipboard: ClipboardSupport::Text,
            file_transfer: false,
            audio: false,
            printing: false,
            multi_monitor: false,
            recordable: true,
        };
        let _: remoter_plugin_abi::Capabilities = caps;
        let _ = NodeId::new();
    }
}
