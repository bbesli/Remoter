//! The adapter: `Protocol` for VNC.
//!
//! Everything else in this crate is machinery; this is the part the session
//! pipeline calls. It receives an already-connected transport (ADR-0003),
//! watches the RFB handshake go past, authenticates, waits for the server to
//! say how big its framebuffer is, and hands back a
//! [`remoter_proto::Session`].
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
use parking_lot::Mutex;
use remoter_core::{EffectiveConnection, ProtocolId};
use remoter_proto::{
    Capabilities, ClipboardPolicy, CredentialProvider, CredentialProviderExt, EventSink, HostPort,
    ProtocolError, Session, SessionEvent, SessionWarning, SettingField, SettingKind,
    SettingsSchema, SyncTransport, Transport, connection_target,
};
use tokio_util::sync::CancellationToken;
use vnc::{PixelFormat, VncClient, VncConnector, VncError, VncEvent, VncVersion};

use crate::encoding::{CursorMode, EncodingPreference, encoding_list, library_encodings};
use crate::error::{handshake_failed, map_vnc, unsupported, vnc_protocol_id};
use crate::handshake::{HandshakeObserver, ObservingTransport, RfbVersion};
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

/// The catalogue key for a password VNC authentication will truncate.
pub const WARNING_PASSWORD_TRUNCATED: &str = "vnc.password_truncated";
/// The catalogue key for a session that authenticated with nothing at all.
pub const WARNING_NO_AUTHENTICATION: &str = "vnc.security.none";
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
/// `clipboard` is `Text`: RFC 6143 §7.5.6 and §7.6.4 carry text and nothing
/// else. There is no file clipboard in RFB to switch on.
#[must_use]
pub const fn capabilities() -> Capabilities {
    Capabilities {
        kind: remoter_proto::SessionKind::Framebuffer,
        resizable: false,
        clipboard: remoter_proto::ClipboardSupport::Text,
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
/// no entry for Tight's compression and quality levels: those are pseudo-
/// encodings (`-247`..`-256` and `-32`..`-23`) and `vnc-rs`'s encoding type is
/// a closed enum with no way to express them, so a setting for them would be a
/// form field that changes nothing.
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
                    EncodingPreference::Tight.as_setting().to_owned(),
                    EncodingPreference::Zrle.as_setting().to_owned(),
                    EncodingPreference::Trle.as_setting().to_owned(),
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
    version: RfbVersion,
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

        let (observing, observer) = ObservingTransport::new(transport, settings.version);
        let client = start(observing, &observer, password, &settings, &target, &cancel).await?;

        // From here the client owns two spawned tasks and the socket. Every
        // path below either builds a session that owns the client or returns —
        // and returning drops the client, whose destructor stops both tasks and
        // releases the socket. That is why there is no guard type here.
        warn_about_weak_security(&events, &observer).await;

        let (width, height, preface) = await_server_init(&client, &settings, &cancel).await?;

        let mut session = VncSession::new(
            client,
            events.clone(),
            target,
            width,
            height,
            self.clipboard,
            settings.view_only,
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
        let version = match self.schema.string(settings, SETTING_RFB_VERSION) {
            Some("3.3") => RfbVersion::Rfb33,
            Some("3.7") => RfbVersion::Rfb37,
            _ => RfbVersion::Rfb38,
        };
        Ok(VncSettings {
            shared: self.boolean_or(settings, SETTING_SHARED, true)?,
            view_only: self.boolean_or(settings, SETTING_VIEW_ONLY, false)?,
            encoding,
            cursor,
            version,
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

/// Runs the RFB handshake, under the deadline and the cancellation token.
///
/// Cancelling drops the connector, and the connector owns the transport — so a
/// tab closed mid-handshake releases its socket at the moment it is closed
/// rather than at the moment the server gives up. That is the defect this
/// arrangement exists to avoid: one leaked task and one leaked socket per
/// cancelled connection attempt.
async fn start(
    transport: ObservingTransport,
    observer: &Arc<Mutex<HandshakeObserver>>,
    password: Option<String>,
    settings: &VncSettings,
    target: &HostPort,
    cancel: &CancellationToken,
) -> Result<VncClient, ProtocolError> {
    let encodings = library_encodings(&encoding_list(settings.encoding, settings.cursor));
    let version = match settings.version {
        RfbVersion::Rfb33 => VncVersion::RFB33,
        RfbVersion::Rfb37 => VncVersion::RFB37,
        RfbVersion::Rfb38 => VncVersion::RFB38,
    };

    // `SyncTransport` adds the `Sync` the connector's bound demands, through an
    // uncontended mutex rather than a pump task. A `tokio::io::duplex` bridge
    // would copy every framebuffer byte *and* add a task that has to be
    // cancelled with the session — and a task that is nearly always cancelled
    // is how one leaked per connection attempt once already.
    let stream = SyncTransport::new(Box::new(transport));

    let mut connector = VncConnector::new(stream)
        // The future is only polled if the server asks for VNC authentication,
        // so a `None` server never sees the password at all.
        .set_auth_method(async move {
            match password {
                Some(password) => Ok(password),
                None => Err(VncError::NoPassword),
            }
        })
        .set_version(version)
        .allow_shared(settings.shared)
        // Always set, and not only for the pixel layout it asks for
        // (RFC 6143 §7.5.1). Leaving it unset makes the library adopt the
        // server's format, and two of its decoders reach `unreachable!()` on a
        // format whose colour masks are not one of four expected values — so
        // the server would be choosing whether this process panics.
        .set_pixel_format(PixelFormat::bgra());
    for encoding in encodings {
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
        Ok(Err(error)) => return Err(refine(error, observer)),
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
        .map_err(|error| map_vnc(&error, "finish the RFB connection"))
}

/// Turns a library handshake failure into something the user can act on.
///
/// The observer watched the security-type list go past (RFC 6143 §7.1.2), so
/// "the handshake failed" can become "this server offers VeNCrypt and Apple
/// Remote Desktop, and this build implements neither" — without ever quoting
/// the server's own words back at the user.
fn refine(error: VncError, observer: &Arc<Mutex<HandshakeObserver>>) -> ProtocolError {
    let facts = observer.lock().facts().clone();
    if facts.security_is_unusable() {
        return ProtocolError::AuthMethodUnavailable {
            // RFB has no account name and no key: a password is the only thing
            // a client can present, so "the server does not accept password
            // authentication" is the true sentence when it offers only
            // VeNCrypt.
            attempted: remoter_proto::CredentialKind::Password,
            offered: facts.offered_names(),
        };
    }
    if facts.refused_outright {
        return handshake_failed(
            "the server refused the connection before offering a security type",
        );
    }
    map_vnc(&error, "complete the RFB handshake")
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
) -> Result<(u16, u16, Vec<VncEvent>), ProtocolError> {
    let mut preface = Vec::new();
    let deadline = tokio::time::timeout(settings.handshake_timeout, async {
        loop {
            let event = client
                .recv_event()
                .await
                .map_err(|error| map_vnc(&error, "read the RFB server initialisation"))?;
            match event {
                VncEvent::SetResolution(screen) if screen.width > 0 && screen.height > 0 => {
                    return Ok((screen.width, screen.height, std::mem::take(&mut preface)));
                }
                VncEvent::Error(_) => {
                    return Err(crate::error::classify_decoder_failure());
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
            Err(_elapsed) => Err(handshake_failed(
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

/// Names the security type the handshake actually used.
///
/// `vnc-rs` prefers `None` where the server offers it and VNC authentication
/// otherwise, so the choice can be read off the observed list rather than
/// guessed. Both outcomes are worth telling the user about: one is a desktop
/// anybody who can reach the port can open, and the other is a DES challenge
/// with an eight-byte key.
async fn warn_about_weak_security(events: &EventSink, observer: &Arc<Mutex<HandshakeObserver>>) {
    let offered = observer.lock().facts().offered_security.clone();
    if offered.contains(&SecurityType::NONE) {
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: WARNING_NO_AUTHENTICATION.to_owned(),
            }))
            .await;
    } else if offered.contains(&SecurityType::VNC_AUTH) {
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::WeakAlgorithm {
                algorithm: WEAK_ALGORITHM_VNC_AUTH.to_owned(),
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

    #[test]
    fn the_capability_set_matches_what_this_build_can_actually_do() {
        let caps = capabilities();
        assert_eq!(caps.kind, remoter_proto::SessionKind::Framebuffer);
        // RFC 6143 §7.8.2 is server-to-client only, and neither
        // `SetDesktopSize` nor ExtendedDesktopSize is implemented here.
        // Advertising a control that cannot work is worse than scaling.
        assert!(!caps.resizable);
        assert_eq!(caps.clipboard, remoter_proto::ClipboardSupport::Text);
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
    fn the_encoding_and_cursor_choices_are_exactly_what_the_parsers_accept() {
        // A choice the form offers but the parser rejects would silently fall
        // back to the default, which is a setting that appears to do nothing.
        let schema = schema();
        let SettingKind::Choice { options } = &schema
            .field(SETTING_ENCODING)
            .expect("the encoding field exists")
            .kind
        else {
            panic!("the encoding setting is a choice");
        };
        for option in options {
            assert!(
                EncodingPreference::from_setting(option).is_some(),
                "{option}"
            );
        }

        let SettingKind::Choice { options } = &schema
            .field(SETTING_CURSOR)
            .expect("the cursor field exists")
            .kind
        else {
            panic!("the cursor setting is a choice");
        };
        for option in options {
            assert!(CursorMode::from_setting(option).is_some(), "{option}");
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
        let observer = Arc::new(Mutex::new(HandshakeObserver::new(RfbVersion::Rfb38)));
        observer.lock().observe(b"RFB 003.008\n\x01\x02");
        warn_about_weak_security(&events, &observer).await;
        let Some(SessionEvent::Warning(SessionWarning::WeakAlgorithm { algorithm })) =
            rx.recv().await
        else {
            panic!("a DES challenge with an eight-byte key is a weak algorithm");
        };
        assert_eq!(algorithm, WEAK_ALGORITHM_VNC_AUTH);
    }

    #[tokio::test]
    async fn a_server_with_no_authentication_at_all_says_so() {
        let (events, mut rx) = event_channel(8);
        let observer = Arc::new(Mutex::new(HandshakeObserver::new(RfbVersion::Rfb38)));
        observer.lock().observe(b"RFB 003.008\n\x01\x01");
        warn_about_weak_security(&events, &observer).await;
        let Some(SessionEvent::Warning(SessionWarning::Other { detail })) = rx.recv().await else {
            panic!("a desktop anybody who can reach the port can open is worth saying");
        };
        assert_eq!(detail, WARNING_NO_AUTHENTICATION);
    }

    #[test]
    fn a_server_offering_nothing_we_implement_names_what_it_offered() {
        let observer = Arc::new(Mutex::new(HandshakeObserver::new(RfbVersion::Rfb38)));
        // VeNCrypt and Apple Remote Desktop: the two a user is most likely to
        // meet, and neither is implemented here.
        observer.lock().observe(b"RFB 003.008\n\x02\x13\x1e");
        let error = refine(
            VncError::General("Security type apart from Vnc Auth has not been implemented".into()),
            &observer,
        );
        let ProtocolError::AuthMethodUnavailable { offered, .. } = error else {
            panic!("this is an authentication failure, not a mystery");
        };
        assert_eq!(
            offered,
            vec!["VeNCrypt".to_owned(), "Apple Remote Desktop".to_owned()]
        );
    }

    #[test]
    fn a_server_that_refused_outright_is_not_blamed_on_authentication() {
        let observer = Arc::new(Mutex::new(HandshakeObserver::new(RfbVersion::Rfb38)));
        observer
            .lock()
            .observe(b"RFB 003.008\n\x00\x00\x00\x00\x08too many");
        let error = refine(VncError::General("too many".into()), &observer);
        assert_eq!(error.stage(), remoter_proto::Stage::Handshake);
        assert!(!error.to_string().contains("too many"));
    }
}
