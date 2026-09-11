//! The adapter: `Protocol` for RDP.
//!
//! Everything below this line is machinery; this is the part the session
//! pipeline calls. It receives an already-connected transport (ADR-0003), runs
//! the connection sequence, and hands back a [`remoter_proto::Session`].
//!
//! **The settings schema is the interface's form.**
//! `docs/features/protocols.md` lists what an RDP connection can be configured
//! with; each entry below is one of those, with the type and range that make
//! the form render itself. There is deliberately no secret among them: a
//! settings map travels through import, export and inheritance, and a password
//! put in one would travel with all three.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use remoter_core::{EffectiveConnection, NodeId, ProtocolId, Provenance, Resolved};
use remoter_proto::{
    Capabilities, CredentialProvider, EventSink, HostPort, ProtocolError, Session, SessionId,
    SettingField, SettingKind, SettingsSchema, Transport, TrustStore, connection_target,
};
use tokio_util::sync::CancellationToken;

use crate::cert::CertificateChecker;
use crate::connect::{ConnectionConfig, DEFAULT_TIMEOUT, DesktopSize, connect, static_channels};
use crate::error::rdp_protocol_id;
use crate::prompt::PromptChannel;
use crate::session::{RdpSession, capabilities};

/// The account's Windows domain. Empty for a local account.
pub const SETTING_DOMAIN: &str = "domain";
/// The Windows keyboard layout identifier, as a decimal number.
pub const SETTING_KEYBOARD_LAYOUT: &str = "keyboard_layout";
/// Whether to require Network Level Authentication.
pub const SETTING_NLA: &str = "network_level_authentication";
/// The desktop width to request, in pixels.
pub const SETTING_WIDTH: &str = "desktop_width";
/// The desktop height to request, in pixels.
pub const SETTING_HEIGHT: &str = "desktop_height";
/// A program to run instead of the shell.
pub const SETTING_ALTERNATE_SHELL: &str = "alternate_shell";
/// That program's working directory.
pub const SETTING_WORK_DIR: &str = "work_dir";
/// The client name this machine reports to the server.
pub const SETTING_WORKSTATION: &str = "workstation";

/// The catalogue key surfaced when Network Level Authentication is turned off.
pub const WARNING_NLA_DISABLED: &str = "rdp.network_level_authentication_disabled";

/// US English — `0x0409`. The layout a connection gets when nothing on the
/// inheritance path chose one.
pub const DEFAULT_KEYBOARD_LAYOUT: u32 = 0x0000_0409;

/// The RDP adapter.
pub struct RdpProtocol {
    id: ProtocolId,
    schema: SettingsSchema,
    trust: Arc<dyn TrustStore>,
    prompts: Option<Arc<PromptChannel>>,
}

impl RdpProtocol {
    /// An adapter checking certificates against `trust`.
    ///
    /// Without a prompt channel the adapter cannot ask anything, so an unpinned
    /// certificate is refused rather than accepted and a missing password
    /// fails. That is the right behaviour for a scripted connect; an
    /// interactive one should use [`with_prompts`](Self::with_prompts).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Internal`] if `"rdp"` stops being a valid protocol
    /// identifier, which would be a defect in `remoter-core`.
    pub fn new(trust: Arc<dyn TrustStore>) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: rdp_protocol_id()?,
            schema: schema(),
            trust,
            prompts: None,
        })
    }

    /// The same adapter, able to ask the user.
    ///
    /// The caller owns the other end: it forwards every
    /// [`remoter_proto::SessionCommand::Prompt`] it receives into the sender
    /// that [`PromptChannel::new`] handed back.
    #[must_use]
    pub fn with_prompts(mut self, prompts: Arc<PromptChannel>) -> Self {
        self.prompts = Some(prompts);
        self
    }

    /// Establishes a session, with the identity the presenter will demultiplex
    /// frames by.
    ///
    /// This is the entry point a caller that knows its `SessionId` should use —
    /// `remoter-ipc` does, because the supervisor hands it one before the
    /// session body runs. [`remoter_proto::Protocol::connect`] cannot: the
    /// trait has no session id in its signature, and a framebuffer message's
    /// header carries one so that two tabs do not quietly become one.
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
        session: SessionId,
    ) -> Result<RdpSession, ProtocolError> {
        self.schema.validate(&config.settings)?;
        for key in self.schema.unknown_keys(&config.settings) {
            // Not an error: `remoter-core` keeps unknown keys so that opening
            // a vault in an older build does not discard a newer setting.
            tracing::debug!(setting = key, "an RDP setting this build does not know");
        }

        let target = connection_target(config)?;
        let connection = self.connection_config(config, creds, &target)?;

        if !connection.network_level_authentication {
            // Stated where the user will see it, every time. Without NLA the
            // credentials go to whatever answered the port, which is the whole
            // reason `docs/security/transport-security.md` says it should stay
            // on.
            let _ = events
                .send(remoter_proto::SessionEvent::Warning(
                    remoter_proto::SessionWarning::Other {
                        detail: WARNING_NLA_DISABLED.to_owned(),
                    },
                ))
                .await;
        }

        let certificates = CertificateChecker::new(
            target.clone(),
            Arc::clone(&self.trust),
            events.clone(),
            self.prompts.clone(),
        );

        let connected = connect(
            transport,
            &connection,
            creds,
            &certificates,
            static_channels(),
            &events,
            self.prompts.clone(),
            &cancel,
        )
        .await?;

        Ok(RdpSession::attach(connected, events, session, target))
    }

    /// Turns a resolved connection into the sequence's configuration.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] for a setting outside its range, or
    /// [`ProtocolError::CredentialRequired`] when no account name resolved —
    /// RDP has no anonymous login, and the account name lives with the
    /// credential rather than with the connection.
    fn connection_config(
        &self,
        config: &EffectiveConnection,
        creds: &dyn CredentialProvider,
        target: &HostPort,
    ) -> Result<ConnectionConfig, ProtocolError> {
        let Some(account) = creds
            .username()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            return Err(ProtocolError::CredentialRequired {
                target: target.clone(),
            });
        };
        let (username, embedded_domain) = split_account(account);

        let mut connection = ConnectionConfig::new(target.clone(), username);
        // Precedence: the domain the user typed into the account name beats
        // the setting, because it is the more specific statement and because
        // `CORP\ada` with a `domain` setting of `OTHER` is a user contradicting
        // themselves in one field.
        connection.domain = embedded_domain
            .or_else(|| creds.domain().map(str::trim).map(ToOwned::to_owned))
            .filter(|domain| !domain.is_empty())
            .or_else(|| {
                self.string(config, SETTING_DOMAIN)
                    .map(str::trim)
                    .filter(|domain| !domain.is_empty())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        if let Some(workstation) = self
            .string(config, SETTING_WORKSTATION)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            connection.workstation = workstation.to_owned();
        }

        connection.desktop = DesktopSize {
            width: self.dimension(config, SETTING_WIDTH, DesktopSize::default().width)?,
            height: self.dimension(config, SETTING_HEIGHT, DesktopSize::default().height)?,
        };

        connection.keyboard_layout = self
            .schema
            .integer(&config.settings, SETTING_KEYBOARD_LAYOUT)?
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(DEFAULT_KEYBOARD_LAYOUT);

        connection.network_level_authentication = self
            .schema
            .boolean(&config.settings, SETTING_NLA)?
            .unwrap_or(true);

        connection.alternate_shell = self
            .string(config, SETTING_ALTERNATE_SHELL)
            .unwrap_or_default()
            .to_owned();
        connection.work_dir = self
            .string(config, SETTING_WORK_DIR)
            .unwrap_or_default()
            .to_owned();

        connection.timeout = config
            .connect_timeout_ms
            .value
            .filter(|ms| *ms > 0)
            .map_or(DEFAULT_TIMEOUT, |ms| Duration::from_millis(u64::from(ms)));

        Ok(connection)
    }

    fn string<'a>(&'a self, config: &'a EffectiveConnection, key: &str) -> Option<&'a str> {
        self.schema.string(&config.settings, key)
    }

    fn dimension(
        &self,
        config: &EffectiveConnection,
        key: &str,
        fallback: u16,
    ) -> Result<u16, ProtocolError> {
        Ok(self
            .schema
            .integer(&config.settings, key)?
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(fallback))
    }
}

impl core::fmt::Debug for RdpProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpProtocol")
            .field("can_prompt", &self.prompts.is_some())
            .finish()
    }
}

#[async_trait]
impl remoter_proto::Protocol for RdpProtocol {
    fn id(&self) -> ProtocolId {
        self.id.clone()
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    fn settings_schema(&self) -> &SettingsSchema {
        &self.schema
    }

    /// Establishes a session over an already-connected stream.
    ///
    /// The returned session carries session id zero, because the trait has no
    /// session id to give it. That is only correct for a caller with exactly
    /// one framebuffer session open: a framebuffer message's header carries the
    /// id so a presenter can tell two tabs apart, and two zeros are one tab.
    /// A caller that knows its id — `remoter-ipc` does — should use
    /// [`RdpProtocol::connect_session`]. Widening the trait is the real fix and
    /// is a change to `remoter-proto`.
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
    ) -> Result<Box<dyn Session>, ProtocolError> {
        let session = self
            .connect_session(
                transport,
                config,
                creds,
                events,
                cancel,
                SessionId::from_raw(0),
            )
            .await?;
        Ok(Box::new(session))
    }
}

/// Splits `DOMAIN\user` or `user@domain` into an account and a domain.
///
/// Both forms are what a Windows user actually types, and getting either wrong
/// produces an authentication failure the user cannot explain — the password is
/// right and the account is not the one being tried.
///
/// The two forms are not symmetric, and that is Windows' doing rather than a
/// choice here:
///
/// - `DOMAIN\user` is the NetBIOS form. The domain is separated out, because
///   NTLM hashes the *user* name and the domain separately (MS-NLMP §3.3.2)
///   and a `NTOWFv2` computed over `DOMAIN\user` matches nothing.
/// - `user@domain` is a User Principal Name. It stays whole, with an empty
///   domain, because that is how Windows resolves it: the UPN *is* the account
///   identifier and splitting it produces a different, usually non-existent
///   account.
#[must_use]
pub fn split_account(account: &str) -> (String, Option<String>) {
    let account = account.trim();
    if let Some((domain, user)) = account.split_once('\\') {
        let user = user.trim();
        let domain = domain.trim();
        if !user.is_empty() {
            return (
                user.to_owned(),
                (!domain.is_empty()).then(|| domain.to_owned()),
            );
        }
    }
    (account.to_owned(), None)
}

/// The settings this adapter understands.
#[must_use]
pub fn schema() -> SettingsSchema {
    SettingsSchema::new(vec![
        SettingField::new(
            SETTING_DOMAIN,
            "settings.rdp.domain",
            // A NetBIOS domain name is at most 15 characters; a DNS one can be
            // longer, and both are accepted here.
            SettingKind::Text { max_len: 255 },
        ),
        SettingField::new(
            SETTING_WORKSTATION,
            "settings.rdp.workstation",
            SettingKind::Text { max_len: 63 },
        )
        .with_default("REMOTER"),
        SettingField::new(
            SETTING_NLA,
            "settings.rdp.network_level_authentication",
            SettingKind::Boolean,
        )
        // On, and it stays on unless the user turns it off: without CredSSP
        // the credentials go to whatever answered the port.
        .with_default("true"),
        SettingField::new(
            SETTING_WIDTH,
            "settings.rdp.desktop_width",
            // MS-RDPEDISP §2.2.2.2.1's own bounds. Outside them the server
            // rejects a resize rather than clamping it, so the form should
            // refuse the value before the connection does.
            SettingKind::Integer {
                min: 200,
                max: 8192,
            },
        )
        .with_default(DesktopSize::default().width.to_string()),
        SettingField::new(
            SETTING_HEIGHT,
            "settings.rdp.desktop_height",
            SettingKind::Integer {
                min: 200,
                max: 8192,
            },
        )
        .with_default(DesktopSize::default().height.to_string()),
        SettingField::new(
            SETTING_KEYBOARD_LAYOUT,
            "settings.rdp.keyboard_layout",
            // A Windows locale identifier. The server applies the layout to
            // the scancodes this client sends, so a wrong value here types the
            // wrong characters and nothing in the adapter can tell.
            SettingKind::Integer {
                min: 0,
                max: 0xffff_ffff,
            },
        )
        .with_default(DEFAULT_KEYBOARD_LAYOUT.to_string()),
        SettingField::new(
            SETTING_ALTERNATE_SHELL,
            "settings.rdp.alternate_shell",
            SettingKind::Text { max_len: 512 },
        ),
        SettingField::new(
            SETTING_WORK_DIR,
            "settings.rdp.work_dir",
            SettingKind::Text { max_len: 512 },
        ),
    ])
}

/// A settings map with the given entries, attributed to `node`.
///
/// For an importer building a connection, and for tests. Every value is
/// recorded as the node's own, which is what an imported setting is.
#[must_use]
pub fn settings_from<I, K, V>(node: NodeId, entries: I) -> BTreeMap<String, Resolved<String>>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    entries
        .into_iter()
        .map(|(key, value)| {
            (
                key.into(),
                Resolved {
                    value: value.into(),
                    provenance: Provenance::Own(node),
                },
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;
    use remoter_proto::{CredentialKind, KeyBorrow, KnownKey};

    struct NoTrust;
    impl TrustStore for NoTrust {
        fn lookup(&self, _host: &HostPort, _algorithm: &str) -> Option<KnownKey> {
            None
        }
        fn remember(&self, _host: &HostPort, _key: &KnownKey) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    struct Account(&'static str);
    impl CredentialProvider for Account {
        fn username(&self) -> Option<&str> {
            (!self.0.is_empty()).then_some(self.0)
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::Password
        }
        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            f(b"hunter2");
            true
        }
        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    fn adapter() -> RdpProtocol {
        RdpProtocol::new(Arc::new(NoTrust)).unwrap()
    }

    fn effective(settings: BTreeMap<String, Resolved<String>>) -> EffectiveConnection {
        fn root<T>(value: T) -> Resolved<T> {
            Resolved::new(value, Provenance::DefaultAtRoot)
        }
        EffectiveConnection {
            node: NodeId::new(),
            name: "ts-01".to_owned(),
            protocol: rdp_protocol_id().unwrap(),
            host: "ts-01.corp.example".to_owned(),
            port: root(None),
            credential: root(None),
            username: root(None),
            credential_attached: false,
            gateway: root(remoter_core::GatewayChain::direct()),
            connect_timeout_ms: root(None),
            keepalive_secs: root(None),
            settings,
            on_connect: root(Vec::new()),
            on_disconnect: root(Vec::new()),
            recording: root(remoter_core::RecordingPolicy::Never),
            auto_reconnect: root(remoter_core::ReconnectPolicy::Never),
            icon: root(None),
            colour: root(None),
        }
    }

    fn target() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    #[test]
    fn the_schema_has_no_secret_in_it() {
        // A settings map travels through import, export and inheritance. A
        // password in one would travel with all three, which is why
        // `SettingKind` has no `Secret` variant — asserted here so that a
        // future field cannot smuggle one in as free text.
        for field in schema().fields() {
            let key = field.key.to_lowercase();
            for forbidden in [
                "password",
                "passphrase",
                "secret",
                "key_data",
                "token",
                "pin",
            ] {
                assert!(
                    !key.contains(forbidden),
                    "{} looks like a credential field",
                    field.key
                );
            }
        }
    }

    #[test]
    fn network_level_authentication_is_on_unless_it_is_turned_off() {
        // Without CredSSP the credentials go to whatever answered the port.
        let schema = schema();
        let empty = BTreeMap::new();
        assert_eq!(schema.boolean(&empty, SETTING_NLA).unwrap(), Some(true));

        let off = settings_from(NodeId::new(), [(SETTING_NLA, "false")]);
        assert_eq!(schema.boolean(&off, SETTING_NLA).unwrap(), Some(false));
    }

    #[test]
    fn the_desktop_bounds_are_the_ones_the_specification_permits() {
        // MS-RDPEDISP §2.2.2.2.1. Outside them the server rejects a resize
        // rather than clamping it, so the form refuses first.
        let schema = schema();
        for bad in ["0", "100", "9000", "-1"] {
            let settings = settings_from(NodeId::new(), [(SETTING_WIDTH, bad)]);
            assert!(schema.validate(&settings).is_err(), "{bad} was accepted");
        }
        let good = settings_from(
            NodeId::new(),
            [(SETTING_WIDTH, "1920"), (SETTING_HEIGHT, "1080")],
        );
        schema.validate(&good).unwrap();
    }

    #[test]
    fn a_setting_error_names_the_key_and_never_the_value() {
        let error = schema()
            .validate(&settings_from(NodeId::new(), [(SETTING_WIDTH, "hunter2")]))
            .unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(rendered.contains(SETTING_WIDTH));
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn an_unknown_setting_is_kept_rather_than_rejected() {
        // Opening a vault in an older build must not discard a newer
        // protocol's settings.
        let schema = schema();
        let settings = settings_from(NodeId::new(), [("gateway_hostname", "rdgw.corp")]);
        schema.validate(&settings).unwrap();
        assert_eq!(schema.unknown_keys(&settings), vec!["gateway_hostname"]);
    }

    #[test]
    fn a_netbios_account_name_is_split_and_a_principal_name_is_not() {
        // NTLM hashes the user and the domain separately (MS-NLMP §3.3.2), so
        // `NTOWFv2` over `CORP\ada` matches nothing. A UPN is the opposite: it
        // *is* the account identifier and splitting it produces a different,
        // usually non-existent account.
        assert_eq!(
            split_account("CORP\\ada"),
            ("ada".to_owned(), Some("CORP".to_owned()))
        );
        assert_eq!(
            split_account("  CORP \\ ada  "),
            ("ada".to_owned(), Some("CORP".to_owned()))
        );
        assert_eq!(
            split_account("ada@corp.example"),
            ("ada@corp.example".to_owned(), None)
        );
        assert_eq!(split_account("ada"), ("ada".to_owned(), None));
        // A leading backslash with no domain is the account, not an empty
        // domain and an empty account.
        assert_eq!(split_account("\\ada"), ("ada".to_owned(), None));
        assert_eq!(split_account("CORP\\"), ("CORP\\".to_owned(), None));
    }

    #[test]
    fn the_domain_in_the_account_name_beats_the_setting() {
        // A user who typed `CORP\ada` into the account field and left an old
        // `domain` setting behind has contradicted themselves; the more
        // specific statement wins.
        let adapter = adapter();
        let config = effective(settings_from(NodeId::new(), [(SETTING_DOMAIN, "OTHER")]));
        let connection = adapter
            .connection_config(&config, &Account("CORP\\ada"), &target())
            .unwrap();
        assert_eq!(connection.username, "ada");
        assert_eq!(connection.domain, "CORP");

        // With no domain in the account name, the setting is used.
        let connection = adapter
            .connection_config(&config, &Account("ada"), &target())
            .unwrap();
        assert_eq!(connection.domain, "OTHER");
    }

    #[test]
    fn a_connection_with_no_account_name_says_so() {
        // RDP has no anonymous login, and the account name lives with the
        // credential rather than with the connection.
        let adapter = adapter();
        let error = adapter
            .connection_config(&effective(BTreeMap::new()), &Account(""), &target())
            .unwrap_err();
        assert!(matches!(error, ProtocolError::CredentialRequired { .. }));
    }

    #[test]
    fn an_unconfigured_connection_gets_the_documented_defaults() {
        let adapter = adapter();
        let connection = adapter
            .connection_config(&effective(BTreeMap::new()), &Account("ada"), &target())
            .unwrap();
        assert_eq!(connection.desktop, DesktopSize::default());
        assert_eq!(connection.keyboard_layout, DEFAULT_KEYBOARD_LAYOUT);
        assert!(connection.network_level_authentication);
        assert_eq!(connection.workstation, "REMOTER");
        assert_eq!(connection.timeout, DEFAULT_TIMEOUT);
        assert_eq!(
            connection.service_principal_name(),
            "TERMSRV/ts-01.corp.example"
        );
    }

    #[test]
    fn the_settings_reach_the_connection_configuration() {
        let adapter = adapter();
        let config = effective(settings_from(
            NodeId::new(),
            [
                (SETTING_WIDTH, "1920"),
                (SETTING_HEIGHT, "1080"),
                // German, 0x0407.
                (SETTING_KEYBOARD_LAYOUT, "1031"),
                (SETTING_NLA, "false"),
                (SETTING_WORKSTATION, "LAPTOP-7"),
                (SETTING_ALTERNATE_SHELL, "cmd.exe"),
                (SETTING_WORK_DIR, "C:\\Windows"),
            ],
        ));
        let connection = adapter
            .connection_config(&config, &Account("ada"), &target())
            .unwrap();

        assert_eq!(
            connection.desktop,
            DesktopSize {
                width: 1920,
                height: 1080
            }
        );
        assert_eq!(connection.keyboard_layout, 0x0407);
        assert!(!connection.network_level_authentication);
        assert_eq!(connection.workstation, "LAPTOP-7");
        assert_eq!(connection.alternate_shell, "cmd.exe");
        assert_eq!(connection.work_dir, "C:\\Windows");
    }

    #[test]
    fn a_blank_setting_falls_back_rather_than_producing_an_empty_value() {
        // An empty workstation name is reported to the server as an empty
        // string, which some hosts log as an anonymous connection.
        let adapter = adapter();
        let config = effective(settings_from(NodeId::new(), [(SETTING_WORKSTATION, "   ")]));
        let connection = adapter
            .connection_config(&config, &Account("ada"), &target())
            .unwrap();
        assert_eq!(connection.workstation, "REMOTER");
    }

    #[test]
    fn the_adapter_reports_the_documented_identity_and_capabilities() {
        use remoter_proto::Protocol as _;
        let protocol = adapter();
        assert_eq!(protocol.id().as_str(), "rdp");
        assert_eq!(protocol.capabilities(), capabilities());
        assert_eq!(
            protocol.settings_schema().fields().len(),
            schema().fields().len()
        );
        assert_eq!(format!("{protocol:?}"), "RdpProtocol { can_prompt: false }");
    }
}
