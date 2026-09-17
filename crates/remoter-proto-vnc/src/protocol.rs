//! The adapter: `Protocol` for VNC.
//!
//! Everything else in this crate is machinery; this is the part the session
//! pipeline calls. It receives an already-connected transport (ADR-0003), runs
//! the RFB handshake **itself** (ADR-0013), hands what is left to `vnc-rs`
//! behind [`crate::gate`], waits for the server to say how big its framebuffer
//! is, and hands back a [`remoter_proto::Session`].
//!
//! # The transport is injected, and this file is the proof
//!
//! There is no `connect`, no `lookup_host` and no socket anywhere below. The
//! `Box<dyn Transport>` that arrives may be a plain TCP connection or the far
//! end of a three-hop SSH chain, and nothing here can tell the difference or
//! needs to. That is what makes "secure this with SSH" — the one-click action
//! `docs/security/transport-security.md` calls the recommended configuration
//! for VNC — cost this crate exactly zero lines: the tunnel is built before
//! `connect` is called, and the only thing that changes here is that
//! [`crate::security::transport_protects_the_session`] stops raising the
//! clear-text warning.
//!
//! # The client decides what it will accept, and says what it accepted
//!
//! The trust model `remoter_proto::hostkey` sets for SSH, applied to RFB. The
//! version is bracketed by a floor as well as a ceiling; the security type is
//! **selected here**, under a policy that refuses `None` whenever a credential
//! is configured; and the type that was selected is reported to the user rather
//! than inferred from what the server offered. `vnc-rs` did none of those
//! things — see [`crate::negotiate`] for what that cost.
//!
//! # The one place a secret is handed over rather than borrowed
//!
//! `vnc-rs` takes the password as an owned `String`
//! (`docs/development/verified-apis.md`), so the borrow that
//! [`remoter_proto::CredentialProviderExt::with_password`] provides has to end
//! in an allocation the library owns. Two things follow, and both are honoured
//! below: the `String` is built as late as possible and moved straight into the
//! connector, and it is never logged, never cloned and never put in a struct
//! that outlives the handshake. What this crate **cannot** do is zeroize it —
//! the library drops it without doing so, which is a defect recorded in
//! `lib.rs` rather than papered over here.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use remoter_core::{EffectiveConnection, ProtocolId};
use remoter_proto::{
    Capabilities, ClipboardPolicy, CredentialProvider, CredentialProviderExt, EventSink, HostPort,
    ProtocolError, Session, SessionEvent, SessionWarning, SettingField, SettingKind,
    SettingsSchema, SyncTransport, Transport, connection_target,
};
use tokio_util::sync::CancellationToken;
use vnc::{PixelFormat, VncClient, VncConnector, VncError, VncEvent, VncVersion};

use crate::encoding::{
    CursorMode, EncodingPreference, RfbEncoding, encoding_list, library_encodings,
};
use crate::error::{map_vnc, unsupported, vnc_protocol_id};
use crate::gate::{GateShared, GatedTransport, refine_with_gate};
use crate::handshake::RfbVersion;
use crate::negotiate::{Negotiated, negotiate};
use crate::security::{Exposure, SecurityType, classify_exposure, transport_protects_the_session};
use crate::session::{MAX_PREFACE_EVENTS, VncSession};

/// Whether the server may keep other viewers connected (RFC 6143 §7.3.1).
pub const SETTING_SHARED: &str = "shared";
/// Whether input is suppressed locally.
pub const SETTING_VIEW_ONLY: &str = "view_only";
/// Which encoding to put at the head of `SetEncodings` (RFC 6143 §7.5.2).
pub const SETTING_ENCODING: &str = "encoding";
/// Whether to draw the pointer locally (RFC 6143 §7.8.1).
pub const SETTING_CURSOR: &str = "cursor";
/// The highest RFB version to offer (RFC 6143 §7.1.1).
pub const SETTING_RFB_VERSION: &str = "rfb_version";
/// The lowest RFB version to accept (RFC 6143 §7.1.1).
pub const SETTING_RFB_VERSION_MIN: &str = "rfb_version_min";

/// The catalogue key for a password VNC authentication will truncate.
pub const WARNING_PASSWORD_TRUNCATED: &str = "vnc.password_truncated";
/// The catalogue key for a session that authenticated with nothing at all.
pub const WARNING_NO_AUTHENTICATION: &str = "vnc.security.none";
/// The catalogue key for a session that negotiated below RFB 3.8.
pub const WARNING_LEGACY_RFB_VERSION: &str = "vnc.version.legacy";
/// The algorithm name reported for VNC authentication's DES challenge.
pub const WEAK_ALGORITHM_VNC_AUTH: &str = "VNC-Auth-DES";

/// How many bytes of a password VNC authentication actually uses.
///
/// RFC 6143 §7.2.2: the key is made from the first eight bytes and the rest is
/// discarded. A user with a 40-character passphrase has an 8-character one, and
/// is told so.
pub const VNC_AUTH_PASSWORD_BYTES: usize = 8;

/// How long the handshake has, when the connection sets no timeout of its own.
///
/// The 30 seconds `docs/architecture/session-pipeline.md` promises. It covers
/// the version handshake, the security handshake and `ServerInit` together,
/// because from the user's side those are one wait.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// What a VNC session can do.
///
/// # `resizable` is `false`, and that is a correction
///
/// RFC 6143 §7.8.2's DesktopSize pseudo-encoding is server-to-client only: it
/// reports that the desktop changed size and offers no way to ask for a change.
/// The client-initiated direction needs the `SetDesktopSize` client message
/// (type 251) and the ExtendedDesktopSize pseudo-encoding (`-308`), which are
/// **community extensions outside RFC 6143** and which `vnc-rs` 0.5 does not
/// implement.
///
/// `docs/architecture/rendering.md` lists "VNC `SetDesktopSize`" under smart
/// resize. That remains the right target; it is not what this build can do, and
/// advertising a capability whose control does nothing is worse than scaling
/// the tab. The document needs amending, and this comment is the flag.
///
/// # `clipboard` is `None`, and that is the same correction again
///
/// It used to be `Text`. RFB carries text in both directions on the wire
/// (§7.5.6 out, §7.6.4 in), so `Text` looked right — but
/// [`crate::session::VncSession::clipboard`] answers
/// [`remoter_proto::ClipboardOp::Request`] with `Unsupported`, because the
/// session contract has no event that can carry clipboard *content* back to the
/// interface. So the capability promised a control the session then refused,
/// and the interface drew it: a clipboard button that cannot work.
///
/// `ClipboardSupport` has three values — `None`, `Text`, `TextAndFiles` — and
/// no way to say "one direction". Of the two available answers, `None` is the
/// true one: a capability is a promise, and half a promise kept is a control
/// that fails in the user's hand. Pasting *into* the session still works for a
/// caller that sends `ClipboardOp::Offer`; what is withdrawn is the claim that
/// the interface may offer both.
///
/// `SessionEvent::ClipboardContent` now exists — the RDP adapter delivers remote
/// text through it — so the reading half is no longer blocked on the contract.
/// What keeps this `None` is the other half. The interface offers the local
/// clipboard whenever a graphical tab takes the keyboard, which RDP can afford
/// because MS-RDPECLIP announces formats and moves the text only on paste. RFB
/// has no such step: `ClientCutText` *is* the text, so the same offer here would
/// send whatever the user last copied — a password, often — to the server every
/// time they clicked into the tab. Turning this on needs the interface to offer
/// VNC only on a paste chord, and that is a decision to make on its own.
#[must_use]
pub const fn capabilities() -> Capabilities {
    Capabilities {
        kind: remoter_proto::SessionKind::Framebuffer,
        resizable: false,
        clipboard: remoter_proto::ClipboardSupport::None,
        file_transfer: false,
        audio: false,
        printing: false,
        multi_monitor: false,
        recordable: true,
    }
}

/// The settings this adapter understands.
///
/// Every one of them is wired to something on the wire. There is deliberately
/// no entry for Tight's compression and quality levels: Tight is not negotiated
/// at all (ADR-0013), so a setting for it would be a form field that changes
/// nothing.
#[must_use]
pub fn schema() -> SettingsSchema {
    SettingsSchema::new(vec![
        SettingField::new(SETTING_SHARED, "settings.vnc.shared", SettingKind::Boolean)
            // Shared by default: disconnecting whoever else is on the console
            // is a surprising thing for opening a tab to do.
            .with_default("true"),
        SettingField::new(
            SETTING_VIEW_ONLY,
            "settings.vnc.view_only",
            SettingKind::Boolean,
        )
        .with_default("false"),
        SettingField::new(
            SETTING_ENCODING,
            "settings.vnc.encoding",
            SettingKind::Choice {
                options: vec![
                    EncodingPreference::Auto.as_setting().to_owned(),
                    EncodingPreference::Raw.as_setting().to_owned(),
                ],
            },
        )
        .with_default(EncodingPreference::Auto.as_setting()),
        SettingField::new(
            SETTING_CURSOR,
            "settings.vnc.cursor",
            SettingKind::Choice {
                options: vec![
                    CursorMode::Local.as_setting().to_owned(),
                    CursorMode::Remote.as_setting().to_owned(),
                ],
            },
        )
        .with_default(CursorMode::Local.as_setting()),
        SettingField::new(
            SETTING_RFB_VERSION,
            "settings.vnc.rfb_version",
            SettingKind::Choice {
                options: vec!["3.8".to_owned(), "3.7".to_owned(), "3.3".to_owned()],
            },
        )
        // 3.8 unless a server needs otherwise: it is the version RFC 6143
        // documents, and the only one that always sends a `SecurityResult`
        // after a `None` handshake — which means a failure is reported rather
        // than appearing as a stream that stops.
        .with_default("3.8"),
        SettingField::new(
            SETTING_RFB_VERSION_MIN,
            "settings.vnc.rfb_version_min",
            SettingKind::Choice {
                options: vec!["3.8".to_owned(), "3.7".to_owned(), "3.3".to_owned()],
            },
        )
        // The floor, and it defaults to the same value as the ceiling on
        // purpose. RFC 6143 §7.1.1 negotiation is `min(ours, theirs)`, which on
        // its own is a ceiling with no floor — so the *server* decides how low
        // the conversation goes, and 3.3 is the shape in which the server also
        // decides the security type. A connection to a genuinely old server is
        // a decision the user makes here, once, rather than one any peer can
        // make for them on every connection.
        .with_default("3.8"),
    ])
}

/// The VNC adapter.
pub struct VncProtocol {
    id: ProtocolId,
    schema: SettingsSchema,
    clipboard: ClipboardPolicy,
}

impl VncProtocol {
    /// An adapter with the default clipboard policy.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Internal`] if `"vnc"` stops being a valid protocol
    /// identifier, which would be a defect in `remoter-core`.
    pub fn new() -> Result<Self, ProtocolError> {
        Ok(Self {
            id: vnc_protocol_id()?,
            schema: schema(),
            clipboard: ClipboardPolicy::default(),
        })
    }

    /// The same adapter with a different clipboard policy.
    #[must_use]
    pub const fn with_clipboard_policy(mut self, clipboard: ClipboardPolicy) -> Self {
        self.clipboard = clipboard;
        self
    }

    fn boolean_or(
        &self,
        settings: &BTreeMap<String, remoter_core::Resolved<String>>,
        key: &str,
        fallback: bool,
    ) -> Result<bool, ProtocolError> {
        Ok(self.schema.boolean(settings, key)?.unwrap_or(fallback))
    }
}

impl std::fmt::Debug for VncProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncProtocol")
            .field("clipboard", &self.clipboard)
            .finish()
    }
}

/// Everything the connect path resolved out of the connection's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VncSettings {
    shared: bool,
    view_only: bool,
    encoding: EncodingPreference,
    cursor: CursorMode,
    /// The highest RFB version this connection will speak.
    version_max: RfbVersion,
    /// The lowest it will accept. Never above `version_max`.
    version_min: RfbVersion,
    handshake_timeout: Duration,
}

#[async_trait]
impl remoter_proto::Protocol for VncProtocol {
    fn id(&self) -> ProtocolId {
        self.id.clone()
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    fn settings_schema(&self) -> &SettingsSchema {
        &self.schema
    }

    async fn connect(
        &self,
        transport: Box<dyn Transport>,
        config: &EffectiveConnection,
        creds: &dyn CredentialProvider,
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<Box<dyn Session>, ProtocolError> {
        Ok(Box::new(
            self.connect_session(transport, config, creds, events, cancel)
                .await?,
        ))
    }
}

impl VncProtocol {
    /// The same connection, typed.
    ///
    /// [`remoter_proto::Protocol::connect`] has to return `Box<dyn Session>`,
    /// and a boxed trait object cannot be handed to [`crate::run_vnc_session`]
    /// — which is the loop a VNC tab actually needs, because
    /// `remoter_proto::run_session` waits only on commands and cancellation and
    /// would never send the framebuffer update requests RFC 6143 §7.5.3
    /// requires. So the concrete constructor is public and `connect` is the
    /// thin wrapper over it, exactly as the SSH adapter does.
    ///
    /// # Errors
    ///
    /// Any [`ProtocolError`] from the Handshake or Authenticate stages.
    pub async fn connect_session(
        &self,
        transport: Box<dyn Transport>,
        config: &EffectiveConnection,
        creds: &dyn CredentialProvider,
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<VncSession, ProtocolError> {
        self.schema.validate(&config.settings)?;
        for key in self.schema.unknown_keys(&config.settings) {
            // Not an error: `remoter-core` keeps unknown keys so that opening a
            // vault in an older build does not discard a newer setting.
            tracing::debug!(setting = key, "a VNC setting this build does not know");
        }

        let target = connection_target(config)?;
        let settings = self.settings(config)?;

        // Said before a single pixel arrives, and before the password is even
        // read. A warning that follows the desktop onto the screen is one the
        // user has already stopped being able to act on.
        warn_about_clear_text(&events, transport.peer().kind, &target).await;

        // The password is read here and moved straight into the connector. It
        // is not stored, not cloned and not logged; its *length* is used for
        // one warning and then forgotten.
        let password = borrow_password(creds)?;
        if let Some(password) = &password
            && password.len() > VNC_AUTH_PASSWORD_BYTES
        {
            // RFC 6143 §7.2.2 discards everything past the eighth byte. A user
            // with a long passphrase is entitled to know it is not being used.
            let _ = events
                .send(SessionEvent::Warning(SessionWarning::Other {
                    detail: WARNING_PASSWORD_TRUNCATED.to_owned(),
                }))
                .await;
        }

        // RFC 6143 §7.1, performed here. Until this returns, `vnc-rs` has not
        // been constructed and has seen nothing.
        let mut transport = transport;
        let negotiated = run_negotiation(
            &mut transport,
            &settings,
            password.is_some(),
            &target,
            &cancel,
        )
        .await?;

        // Said before the desktop appears, and said from what was *selected*
        // rather than from what was offered.
        warn_about_security(&events, &negotiated).await;

        let encodings = encoding_list(settings.encoding, settings.cursor);
        let (gate, shared) = GatedTransport::new(transport, &negotiated, &encodings);
        let client = start(
            gate, &encodings, password, &settings, &target, &cancel, &shared,
        )
        .await?;

        // From here the client owns two spawned tasks and the socket. Every
        // path below either builds a session that owns the client or returns —
        // and returning drops the client, whose destructor stops both tasks and
        // releases the socket. That is why there is no guard type here.
        let (width, height, preface) =
            await_server_init(&client, &settings, &cancel, &shared).await?;

        let mut session = VncSession::new(
            client,
            events.clone(),
            target,
            width,
            height,
            self.clipboard,
            settings.view_only,
            Arc::clone(&shared),
            negotiated.security,
        );
        for event in preface {
            session.queue_preface(event);
        }
        // The interface needs the size before the first rectangle: a presenter
        // that allocates its surface from the first frame would allocate it
        // from a dirty rectangle.
        events.send(SessionEvent::Resized { width, height }).await?;

        Ok(session)
    }

    fn settings(&self, config: &EffectiveConnection) -> Result<VncSettings, ProtocolError> {
        let settings = &config.settings;
        let encoding = self
            .schema
            .string(settings, SETTING_ENCODING)
            .and_then(EncodingPreference::from_setting)
            .unwrap_or_default();
        let cursor = self
            .schema
            .string(settings, SETTING_CURSOR)
            .and_then(CursorMode::from_setting)
            .unwrap_or_default();
        let version_max = self
            .schema
            .string(settings, SETTING_RFB_VERSION)
            .and_then(RfbVersion::from_setting)
            .unwrap_or(RfbVersion::Rfb38);
        // The floor, and the one setting that must not be read through the
        // schema's default.
        //
        // `SettingsSchema::string` falls back to the schema's default, which is
        // 3.8 — and that default arrived *after* connections were already
        // stored. Every existing connection whose ceiling had been lowered to
        // reach an old server would therefore have been given a floor above its
        // own ceiling, and would have failed with `SettingInvalid` instead of
        // connecting. A security floor is right; introducing one by breaking a
        // stored configuration is not.
        //
        // So a connection that never stated a floor gets the default brought no
        // higher than the ceiling it did state. One pinned to 3.3 speaks exactly
        // 3.3: stricter than the floorless `min(ours, theirs)` this replaced,
        // because the server can no longer move the conversation down, and it
        // still connects. It is not silent either — `warn_about_security` puts
        // the legacy-version line on screen for anything below 3.8.
        let version_min = match stored_version(settings, SETTING_RFB_VERSION_MIN) {
            Some(floor) => floor,
            None => RfbVersion::Rfb38.min(version_max),
        };
        if version_min > version_max {
            // Both were stated, and they contradict each other. A floor above
            // the ceiling admits no version at all, and silently swapping them
            // would turn a typo into a downgrade — so it is refused, and the
            // refusal says which two values disagree and what to do about it
            // rather than leaving the user to guess.
            return Err(ProtocolError::SettingInvalid {
                key: SETTING_RFB_VERSION_MIN.to_owned(),
                expected: "an RFB version no higher than `rfb_version`: a floor above the ceiling \
                           admits no version at all, so either raise `rfb_version` or lower \
                           `rfb_version_min` to it",
            });
        }
        Ok(VncSettings {
            shared: self.boolean_or(settings, SETTING_SHARED, true)?,
            view_only: self.boolean_or(settings, SETTING_VIEW_ONLY, false)?,
            encoding,
            cursor,
            version_max,
            version_min,
            handshake_timeout: config
                .connect_timeout_ms
                .value
                .filter(|ms| *ms > 0)
                .map_or(DEFAULT_HANDSHAKE_TIMEOUT, |ms| {
                    Duration::from_millis(u64::from(ms))
                }),
        })
    }
}

/// The RFB version this connection *stored* under `key`, if it stored one.
///
/// Deliberately not [`SettingsSchema::string`], which falls back to the schema's
/// default: the difference between "the user chose 3.8" and "this connection was
/// created before the setting existed" is exactly what decides whether a stored
/// configuration keeps working. See [`VncProtocol::settings`].
fn stored_version(
    settings: &BTreeMap<String, remoter_core::Resolved<String>>,
    key: &str,
) -> Option<RfbVersion> {
    settings
        .get(key)
        .and_then(|resolved| RfbVersion::from_setting(&resolved.value))
}

/// Reads the password out of the provider, if there is one.
///
/// The borrow ends inside this function; what comes out is the allocation
/// `vnc-rs` demands and nothing else.
///
/// A password that is not valid UTF-8 is refused rather than mangled.
/// `String::from_utf8_lossy` would replace the offending bytes and produce a
/// password that is *almost* the stored one, and the user would see "wrong
/// password" for a credential their password manager holds correctly.
fn borrow_password(creds: &dyn CredentialProvider) -> Result<Option<String>, ProtocolError> {
    let borrowed = creds.with_password(&mut |bytes| {
        std::str::from_utf8(bytes)
            .ok()
            .map(std::borrow::ToOwned::to_owned)
    });
    match borrowed {
        None => Ok(None),
        Some(None) => Err(unsupported("a password that is not valid UTF-8 text")),
        Some(Some(password)) => Ok(Some(password)),
    }
}

/// Runs RFC 6143 §7.1 under the deadline and the cancellation token.
///
/// Cancelling drops the future, and the transport is still owned by the caller,
/// so a tab closed mid-handshake releases its socket at the moment it is closed
/// rather than at the moment the server gives up.
async fn run_negotiation(
    transport: &mut Box<dyn Transport>,
    settings: &VncSettings,
    has_credential: bool,
    target: &HostPort,
    cancel: &CancellationToken,
) -> Result<Negotiated, ProtocolError> {
    let handshake = negotiate(
        transport,
        settings.version_min,
        settings.version_max,
        has_credential,
    );
    let outcome = tokio::select! {
        () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
        outcome = tokio::time::timeout(settings.handshake_timeout, handshake) => outcome,
    };
    match outcome {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::ConnectTimeout {
            target: target.clone(),
            timeout_ms: u64::try_from(settings.handshake_timeout.as_millis()).unwrap_or(u64::MAX),
        }),
    }
}

/// Hands the gated stream to `vnc-rs` and lets it finish the connection.
///
/// What is left for the library at this point is `ClientInit`, `ServerInit`,
/// `SetPixelFormat`, `SetEncodings` and the first update request — plus the DES
/// exchange, if the security handshake selected VNC authentication, which the
/// gate passes through because the library's DES is not public.
async fn start(
    transport: GatedTransport,
    encodings: &[RfbEncoding],
    password: Option<String>,
    settings: &VncSettings,
    target: &HostPort,
    cancel: &CancellationToken,
    shared: &GateShared,
) -> Result<VncClient, ProtocolError> {
    // `SyncTransport` adds the `Sync` the connector's bound demands, through an
    // uncontended mutex rather than a pump task. A `tokio::io::duplex` bridge
    // would copy every framebuffer byte *and* add a task that has to be
    // cancelled with the session — and a task that is nearly always cancelled
    // is how one leaked per connection attempt once already.
    let stream = SyncTransport::new(Box::new(transport));

    let mut connector = VncConnector::new(stream)
        // The future is only polled if VNC authentication was selected, so a
        // `None` session never sees the password at all.
        .set_auth_method(async move {
            match password {
                Some(password) => Ok(password),
                None => Err(VncError::NoPassword),
            }
        })
        // Always 3.8, whatever the real wire is speaking: the gate serves the
        // library a synthetic 3.8 handshake so that the library's own floorless
        // negotiation has nowhere to go. See `crate::gate`.
        .set_version(VncVersion::RFB38)
        .allow_shared(settings.shared)
        // Always set, and not only for the pixel layout it asks for
        // (RFC 6143 §7.5.1). Leaving it unset makes the library adopt the
        // server's format, and two of its decoders reach `unreachable!()` on a
        // format whose colour masks are not one of four expected values — so
        // the server would be choosing whether this process panics. It is also
        // what makes `crate::gate::BYTES_PER_PIXEL` a constant rather than a
        // number the far end picks.
        .set_pixel_format(PixelFormat::bgra());
    for encoding in library_encodings(encodings) {
        connector = connector.add_encoding(encoding);
    }

    let state = connector
        .build()
        .map_err(|error| map_vnc(&error, "build the RFB connection"))?;

    let started = tokio::select! {
        () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
        outcome = tokio::time::timeout(settings.handshake_timeout, state.try_start()) => outcome,
    };

    let state = match started {
        Ok(Ok(state)) => state,
        // Everything the library can fail on from here is either an I/O error
        // or something the gate refused on its behalf, and the gate's reason is
        // always the better one: the library flattens a refused security result
        // and a refused rectangle into the same opaque error.
        Ok(Err(error)) => {
            return Err(refine_with_gate(
                shared,
                map_vnc(&error, "complete the RFB connection"),
            ));
        }
        Err(_elapsed) => {
            // The taxonomy's "`host` did not respond within N ms". The socket
            // was open — the server simply never finished the handshake — and
            // naming the host is what lets the user check the right machine.
            return Err(ProtocolError::ConnectTimeout {
                target: target.clone(),
                timeout_ms: u64::try_from(settings.handshake_timeout.as_millis())
                    .unwrap_or(u64::MAX),
            });
        }
    };

    state
        .finish()
        .map_err(|error| refine_with_gate(shared, map_vnc(&error, "finish the RFB connection")))
}

/// Waits for the framebuffer size, keeping anything else it finds on the way.
///
/// `vnc-rs` emits `SetResolution` from `ServerInit` (RFC 6143 §7.3.2) before it
/// hands the client back, so in practice this returns on the first event. It is
/// written as a drain anyway because "in practice" is doing a lot of work in
/// that sentence, and a server that emitted something else first would
/// otherwise leave the session with a surface of zero and every rectangle
/// failing its bounds check.
async fn await_server_init(
    client: &VncClient,
    settings: &VncSettings,
    cancel: &CancellationToken,
    shared: &GateShared,
) -> Result<(u16, u16, Vec<VncEvent>), ProtocolError> {
    let mut preface = Vec::new();
    let deadline = tokio::time::timeout(settings.handshake_timeout, async {
        loop {
            let event = client.recv_event().await.map_err(|error| {
                refine_with_gate(
                    shared,
                    map_vnc(&error, "read the RFB server initialisation"),
                )
            })?;
            match event {
                VncEvent::SetResolution(screen) if screen.width > 0 && screen.height > 0 => {
                    return Ok((screen.width, screen.height, std::mem::take(&mut preface)));
                }
                VncEvent::Error(_) => {
                    return Err(refine_with_gate(
                        shared,
                        crate::error::classify_decoder_failure(),
                    ));
                }
                other => {
                    if preface.len() < MAX_PREFACE_EVENTS {
                        preface.push(other);
                    }
                }
            }
        }
    });

    tokio::select! {
        () = cancel.cancelled() => Err(ProtocolError::Cancelled),
        outcome = deadline => match outcome {
            Ok(result) => result,
            Err(_elapsed) => Err(crate::error::handshake_failed(
                "the server did not report its framebuffer size in time",
            )),
        },
    }
}

/// Raises the clear-text warning, unless the transport already protects the
/// session.
///
/// The exposure decides how loud it is:
/// `docs/security/transport-security.md` asks for a *blocking* warning on a
/// routable address and nothing so dramatic on loopback, and one red banner for
/// every connection is a banner users learn to dismiss.
async fn warn_about_clear_text(
    events: &EventSink,
    kind: remoter_proto::TransportKind,
    target: &HostPort,
) {
    if transport_protects_the_session(kind) {
        return;
    }
    let exposure = classify_exposure(target);
    if exposure == Exposure::Loopback {
        // A local forward — the recommended configuration — and a VNC server on
        // this machine both land here. Neither is exposed, and warning about
        // them is what teaches a user to ignore the warning that matters.
        return;
    }
    let _ = events
        .send(SessionEvent::Warning(
            SessionWarning::UnencryptedTransport {
                detail: exposure.warning_key().to_owned(),
            },
        ))
        .await;
}

/// Names the security type the handshake actually used, and the version it used
/// it in.
///
/// The old version of this function read the *offered* list and reproduced
/// `vnc-rs`'s preference to guess what had been chosen. That guess was the
/// visible half of the CRITICAL defect: the library preferred `None` whenever a
/// server offered it, so a session that silently skipped authentication was
/// described by the same code path that described one which had not. The choice
/// is now made here, so it is reported rather than inferred.
async fn warn_about_security(events: &EventSink, negotiated: &Negotiated) {
    if negotiated.is_unauthenticated() {
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: WARNING_NO_AUTHENTICATION.to_owned(),
            }))
            .await;
    } else if negotiated.security == SecurityType::VNC_AUTH {
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::WeakAlgorithm {
                algorithm: WEAK_ALGORITHM_VNC_AUTH.to_owned(),
            }))
            .await;
    }
    if negotiated.version < RfbVersion::Rfb38 {
        // Reaching here at all means the floor was lowered deliberately, and a
        // session that is not using the version the RFC documents is worth one
        // line on screen rather than nothing.
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: WARNING_LEGACY_RFB_VERSION.to_owned(),
            }))
            .await;
    }
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
    use crate::handshake::HandshakeFacts;
    use remoter_proto::{CredentialKind, KeyBorrow, event_channel};

    struct Password(&'static [u8]);

    impl CredentialProvider for Password {
        fn username(&self) -> Option<&str> {
            None
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::Password
        }
        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            f(self.0);
            true
        }
        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    struct Nothing;

    impl CredentialProvider for Nothing {
        fn username(&self) -> Option<&str> {
            None
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::None
        }
        fn borrow_password(&self, _f: &mut dyn FnMut(&[u8])) -> bool {
            false
        }
        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    /// A resolved connection carrying exactly `settings` and nothing else.
    fn connection(settings: &[(&str, &str)]) -> EffectiveConnection {
        fn root<T>(value: T) -> remoter_core::Resolved<T> {
            remoter_core::Resolved::new(value, remoter_core::Provenance::DefaultAtRoot)
        }
        EffectiveConnection {
            node: remoter_core::NodeId::new(),
            name: "desktop".to_owned(),
            protocol: ProtocolId::new("vnc").unwrap(),
            host: "127.0.0.1".to_owned(),
            port: root(Some(5900)),
            credential: root(None),
            username: root(None),
            credential_attached: false,
            gateway: root(remoter_core::GatewayChain::direct()),
            connect_timeout_ms: root(Some(5_000)),
            keepalive_secs: root(None),
            settings: settings
                .iter()
                .map(|(key, value)| ((*key).to_owned(), root((*value).to_owned())))
                .collect::<BTreeMap<_, _>>(),
            on_connect: root(Vec::new()),
            on_disconnect: root(Vec::new()),
            recording: root(remoter_core::RecordingPolicy::Never),
            auto_reconnect: root(remoter_core::ReconnectPolicy::Never),
            icon: root(None),
            colour: root(None),
        }
    }

    fn settled(version: RfbVersion, security: SecurityType) -> Negotiated {
        Negotiated {
            version,
            security,
            facts: HandshakeFacts {
                negotiated_version: Some(version),
                selected_security: Some(security),
                ..HandshakeFacts::default()
            },
        }
    }

    #[test]
    fn the_capability_set_matches_what_this_build_can_actually_do() {
        let caps = capabilities();
        assert_eq!(caps.kind, remoter_proto::SessionKind::Framebuffer);
        // RFC 6143 §7.8.2 is server-to-client only, and neither
        // `SetDesktopSize` nor ExtendedDesktopSize is implemented here.
        // Advertising a control that cannot work is worse than scaling.
        assert!(!caps.resizable);
        // And the same rule applied to the clipboard: the session refuses
        // `ClipboardOp::Request`, so promising `Text` drew a control that
        // failed in the user's hand.
        assert_eq!(caps.clipboard, remoter_proto::ClipboardSupport::None);
        assert!(!caps.file_transfer, "there is no file clipboard in RFB");
        assert!(!caps.audio);
        assert!(!caps.multi_monitor);
        assert!(caps.recordable);
    }

    #[test]
    fn every_setting_in_the_schema_has_a_valid_default() {
        let schema = schema();
        for field in schema.fields() {
            let default = field
                .default
                .as_deref()
                .unwrap_or_else(|| panic!("{} has no default", field.key));
            field
                .validate(default)
                .unwrap_or_else(|error| panic!("{}: {error}", field.key));
        }
        // And an empty settings map validates, which is what a connection
        // created before this adapter existed looks like.
        schema.validate(&BTreeMap::new()).unwrap();
    }

    #[test]
    fn the_version_floor_defaults_to_the_version_the_rfc_documents() {
        // The defect this pins: negotiation used to be `min(ours, theirs)` with
        // nothing underneath it, so any server could move the conversation to
        // 3.3 — the shape in which the *server* picks the security type.
        let schema = schema();
        let floor = schema
            .field(SETTING_RFB_VERSION_MIN)
            .expect("the floor is a setting");
        assert_eq!(floor.default.as_deref(), Some("3.8"));
    }

    #[test]
    fn a_connection_stored_before_the_floor_existed_still_connects() {
        // The defect: `rfb_version_min` defaults to 3.8, and reading it through
        // the schema gave that default to every connection that predates the
        // setting. One whose ceiling had been lowered to 3.3 to reach an old
        // server was then handed a floor above its own ceiling and failed with
        // `SettingInvalid` — a connection that worked yesterday, refused today,
        // with an error about a setting the user never touched.
        let protocol = VncProtocol::new().unwrap();
        let settings = protocol
            .settings(&connection(&[(SETTING_RFB_VERSION, "3.3")]))
            .expect("a connection that lowered its ceiling still connects");
        assert_eq!(settings.version_max, RfbVersion::Rfb33);
        assert_eq!(
            settings.version_min,
            RfbVersion::Rfb33,
            "an unstated floor follows the ceiling the user did state"
        );
    }

    #[test]
    fn the_floor_is_still_38_for_a_connection_that_lowered_nothing() {
        // The other half: the accommodation above must not become a way for the
        // floor to slip. With no ceiling stated, the default ceiling is 3.8 and
        // so is the floor, which is what keeps a server from moving the
        // conversation to 3.3 — the shape in which the *server* picks the
        // security type.
        let protocol = VncProtocol::new().unwrap();
        let settings = protocol.settings(&connection(&[])).unwrap();
        assert_eq!(settings.version_min, RfbVersion::Rfb38);
        assert_eq!(settings.version_max, RfbVersion::Rfb38);

        // And a floor the connection states for itself is still its own.
        let stated = protocol
            .settings(&connection(&[(SETTING_RFB_VERSION_MIN, "3.7")]))
            .unwrap();
        assert_eq!(stated.version_min, RfbVersion::Rfb37);
    }

    #[test]
    fn a_stated_floor_above_a_stated_ceiling_is_refused_and_the_error_says_why() {
        // Two values that contradict each other, both chosen deliberately.
        // Refused rather than reconciled — silently swapping them would turn a
        // typo into a downgrade — and the refusal has to be actionable, because
        // the user is the only one who can resolve it.
        let protocol = VncProtocol::new().unwrap();
        let error = protocol
            .settings(&connection(&[
                (SETTING_RFB_VERSION, "3.3"),
                (SETTING_RFB_VERSION_MIN, "3.8"),
            ]))
            .expect_err("a floor above the ceiling admits no version at all");
        let ProtocolError::SettingInvalid { key, expected } = error else {
            panic!("the contradiction is a setting error");
        };
        assert_eq!(key, SETTING_RFB_VERSION_MIN);
        assert!(
            expected.contains(SETTING_RFB_VERSION) && expected.contains(SETTING_RFB_VERSION_MIN),
            "the message names both settings: {expected}"
        );
        assert!(
            expected.contains("raise") || expected.contains("lower"),
            "and says what to do about it: {expected}"
        );
    }

    #[test]
    fn the_encoding_and_cursor_choices_are_exactly_what_the_parsers_accept() {
        // A choice the form offers but the parser rejects would silently fall
        // back to the default, which is a setting that appears to do nothing.
        let schema = schema();
        for (key, parse) in [
            (
                SETTING_ENCODING,
                (|value: &str| EncodingPreference::from_setting(value).is_some())
                    as fn(&str) -> bool,
            ),
            (SETTING_CURSOR, |value| {
                CursorMode::from_setting(value).is_some()
            }),
            (SETTING_RFB_VERSION, |value| {
                RfbVersion::from_setting(value).is_some()
            }),
            (SETTING_RFB_VERSION_MIN, |value| {
                RfbVersion::from_setting(value).is_some()
            }),
        ] {
            let SettingKind::Choice { options } =
                &schema.field(key).expect("the field exists").kind
            else {
                panic!("{key} is a choice");
            };
            for option in options {
                assert!(parse(option), "{key} = {option}");
            }
        }
    }

    #[test]
    fn a_password_is_read_once_and_nothing_keeps_it() {
        let password = borrow_password(&Password(b"hunter2")).unwrap();
        assert_eq!(password.as_deref(), Some("hunter2"));
        assert_eq!(borrow_password(&Nothing).unwrap(), None);
    }

    #[test]
    fn a_password_that_is_not_text_is_refused_rather_than_mangled() {
        // `from_utf8_lossy` would produce a password that is *almost* the
        // stored one, and the user would see "wrong password" for a credential
        // their password manager holds correctly.
        let error = borrow_password(&Password(&[0xff, 0xfe])).expect_err("not UTF-8");
        assert!(matches!(error, ProtocolError::Unsupported { .. }));
        assert!(
            !format!("{error:?}").contains("255"),
            "and the bytes are not in the message"
        );
    }

    #[tokio::test]
    async fn a_tunnelled_session_raises_no_clear_text_warning() {
        // This is ADR-0003's payoff: the adapter cannot tell a tunnel from a
        // socket, so "secure this with SSH" costs this crate nothing but the
        // absence of a warning.
        let (events, mut rx) = event_channel(8);
        let target = HostPort::new("203.0.113.7", 5900).unwrap();
        warn_about_clear_text(&events, remoter_proto::TransportKind::SshChannel, &target).await;
        drop(events);
        assert!(rx.recv().await.is_none(), "nothing to warn about");
    }

    #[tokio::test]
    async fn a_routable_target_over_plain_tcp_raises_the_blocking_warning() {
        let (events, mut rx) = event_channel(8);
        let target = HostPort::new("203.0.113.7", 5900).unwrap();
        warn_about_clear_text(&events, remoter_proto::TransportKind::Tcp, &target).await;
        let Some(SessionEvent::Warning(SessionWarning::UnencryptedTransport { detail })) =
            rx.recv().await
        else {
            panic!("a clear-text session to the open internet is warned about");
        };
        assert_eq!(detail, Exposure::Routable.warning_key());
    }

    #[tokio::test]
    async fn loopback_is_quiet_because_it_is_the_recommended_configuration() {
        let (events, mut rx) = event_channel(8);
        let target = HostPort::new("127.0.0.1", 5901).unwrap();
        warn_about_clear_text(&events, remoter_proto::TransportKind::Tcp, &target).await;
        drop(events);
        assert!(
            rx.recv().await.is_none(),
            "a local forward must not train the user to dismiss warnings"
        );
    }

    #[tokio::test]
    async fn vnc_authentication_is_reported_as_the_weak_algorithm_it_is() {
        let (events, mut rx) = event_channel(8);
        warn_about_security(&events, &settled(RfbVersion::Rfb38, SecurityType::VNC_AUTH)).await;
        let Some(SessionEvent::Warning(SessionWarning::WeakAlgorithm { algorithm })) =
            rx.recv().await
        else {
            panic!("a DES challenge with an eight-byte key is a weak algorithm");
        };
        assert_eq!(algorithm, WEAK_ALGORITHM_VNC_AUTH);
    }

    #[tokio::test]
    async fn a_session_that_authenticated_with_nothing_says_so() {
        let (events, mut rx) = event_channel(8);
        warn_about_security(&events, &settled(RfbVersion::Rfb38, SecurityType::NONE)).await;
        let Some(SessionEvent::Warning(SessionWarning::Other { detail })) = rx.recv().await else {
            panic!("a desktop anybody who can reach the port can open is worth saying");
        };
        assert_eq!(detail, WARNING_NO_AUTHENTICATION);
    }

    #[tokio::test]
    async fn the_warning_follows_what_was_selected_not_what_was_offered() {
        // The visible half of the CRITICAL defect. A server offering both used
        // to produce the `None` warning, because that is what `vnc-rs` would
        // have picked; with the selection made here, a session that really did
        // authenticate is described as one that did.
        let (events, mut rx) = event_channel(8);
        let mut negotiated = settled(RfbVersion::Rfb38, SecurityType::VNC_AUTH);
        negotiated.facts.offered_security = vec![SecurityType::NONE, SecurityType::VNC_AUTH];
        warn_about_security(&events, &negotiated).await;
        drop(events);

        let mut details = Vec::new();
        while let Some(event) = rx.recv().await {
            if let SessionEvent::Warning(SessionWarning::Other { detail }) = event {
                details.push(detail);
            }
        }
        assert!(
            !details.contains(&WARNING_NO_AUTHENTICATION.to_owned()),
            "{details:?}"
        );
    }

    #[tokio::test]
    async fn a_legacy_version_is_worth_a_line_on_screen() {
        let (events, mut rx) = event_channel(8);
        warn_about_security(&events, &settled(RfbVersion::Rfb33, SecurityType::NONE)).await;
        drop(events);

        let mut details = Vec::new();
        while let Some(event) = rx.recv().await {
            if let SessionEvent::Warning(SessionWarning::Other { detail }) = event {
                details.push(detail);
            }
        }
        assert!(
            details.contains(&WARNING_LEGACY_RFB_VERSION.to_owned()),
            "{details:?}"
        );
    }
}
