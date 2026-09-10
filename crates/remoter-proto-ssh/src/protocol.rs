//! The adapter: `Protocol` for SSH.
//!
//! Everything above this line is machinery; this is the part the session
//! pipeline calls. It receives an already-connected transport (ADR-0003),
//! negotiates, authenticates, opens a PTY and a shell, and hands back a
//! [`remoter_proto::Session`].
//!
//! **The settings schema is the interface's form.** `docs/features/protocols.md`
//! lists what an SSH connection can be configured with; each entry below is one
//! of those, with the type and range that make the form render itself. There is
//! deliberately no secret among them: a settings map travels through import,
//! export and inheritance, and a password put in one would travel with all
//! three.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use remoter_core::{EffectiveConnection, NodeId, ProtocolId, Provenance, Resolved};
use remoter_proto::{
    Capabilities, CredentialProvider, EventSink, ProtocolError, Session, SessionEvent,
    SessionWarning, SettingField, SettingKind, SettingsSchema, Transport, TrustStore,
    connection_target,
};
use tokio_util::sync::CancellationToken;

use crate::algorithms::AlgorithmPolicy;
use crate::connection::{
    DEFAULT_HANDSHAKE_TIMEOUT, SshConnection, SshConnectionConfig, with_deadline,
};
use crate::error::ssh_protocol_id;
use crate::prompt::PromptChannel;
use crate::session::{
    DEFAULT_COLUMNS, DEFAULT_ROWS, DEFAULT_TERM, SshSession, TerminalSettings, capabilities,
};

/// The `TERM` value sent in `pty-req`.
pub const SETTING_TERMINAL_TYPE: &str = "terminal_type";
/// Initial window width, in columns.
pub const SETTING_COLUMNS: &str = "columns";
/// Initial window height, in rows.
pub const SETTING_ROWS: &str = "rows";
/// Whether to negotiate compression.
pub const SETTING_COMPRESSION: &str = "compression";
/// A command written to the shell once it starts.
pub const SETTING_INITIAL_COMMAND: &str = "initial_command";
/// A one-shot command run instead of a shell (RFC 4254 §6.5).
pub const SETTING_EXEC_COMMAND: &str = "exec_command";
/// Environment variables to request, one `NAME=value` per line.
pub const SETTING_ENVIRONMENT: &str = "environment";
/// Whether the platform agent may be used to authenticate.
pub const SETTING_AGENT_AUTH: &str = "agent_auth";
/// Which agent identity to use, by comment substring.
pub const SETTING_AGENT_IDENTITY: &str = "agent_identity";
/// Whether the remote may use this machine's agent.
pub const SETTING_AGENT_FORWARDING: &str = "agent_forwarding";

/// The catalogue key surfaced when agent forwarding is on.
pub const WARNING_AGENT_FORWARDING: &str = "ssh.agent_forwarding_enabled";

/// The SSH adapter.
pub struct SshProtocol {
    id: ProtocolId,
    schema: SettingsSchema,
    trust: Arc<dyn TrustStore>,
    prompts: Option<Arc<PromptChannel>>,
}

impl SshProtocol {
    /// An adapter checking host keys against `trust`.
    ///
    /// Without a prompt channel the adapter cannot ask anything, so an unknown
    /// host key is refused rather than accepted and an encrypted key with no
    /// stored passphrase fails. That is the right behaviour for a scripted
    /// connect; an interactive one should use
    /// [`with_prompts`](Self::with_prompts).
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Internal`] if `"ssh"` stops being a valid protocol
    /// identifier, which would be a defect in `remoter-core`.
    pub fn new(trust: Arc<dyn TrustStore>) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: ssh_protocol_id()?,
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
}

impl std::fmt::Debug for SshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshProtocol")
            .field("can_prompt", &self.prompts.is_some())
            .finish()
    }
}

#[async_trait]
impl remoter_proto::Protocol for SshProtocol {
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
        self.schema.validate(&config.settings)?;
        for key in self.schema.unknown_keys(&config.settings) {
            // Not an error: `remoter-core` keeps unknown keys so that opening
            // a vault in an older build does not discard a newer setting.
            tracing::debug!(setting = key, "an SSH setting this build does not know");
        }

        let target = connection_target(config)?;
        let Some(username) = creds.username().map(str::trim).filter(|u| !u.is_empty()) else {
            // SSH has no anonymous login, and the account name lives with the
            // credential rather than with the connection.
            return Err(ProtocolError::CredentialRequired { target });
        };

        let agent_forwarding = self.boolean(config, SETTING_AGENT_FORWARDING)?;
        let mut connection = SshConnectionConfig::new(target.clone(), username);
        connection.algorithms = AlgorithmPolicy {
            compression: self.boolean(config, SETTING_COMPRESSION)?,
        };
        connection.allow_agent = self.boolean_or(config, SETTING_AGENT_AUTH, true)?;
        connection.agent_filter = self
            .string(config, SETTING_AGENT_IDENTITY)
            .map(str::trim)
            .filter(|filter| !filter.is_empty())
            .map(ToOwned::to_owned);
        connection.agent_forwarding = agent_forwarding;
        connection.keepalive = config
            .keepalive_secs
            .value
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        connection.handshake_timeout = config
            .connect_timeout_ms
            .value
            .filter(|ms| *ms > 0)
            .map_or(DEFAULT_HANDSHAKE_TIMEOUT, |ms| {
                Duration::from_millis(u64::from(ms))
            });

        if agent_forwarding {
            // Stated where the user will see it, every time. A compromised
            // remote host with a forwarded agent can impersonate them
            // everywhere that key opens.
            let _ = events
                .send(SessionEvent::Warning(SessionWarning::Other {
                    detail: WARNING_AGENT_FORWARDING.to_owned(),
                }))
                .await;
        }

        let established = SshConnection::establish(
            transport,
            &connection,
            creds,
            Arc::clone(&self.trust),
            events.clone(),
            self.prompts.clone(),
            &cancel,
        )
        .await?;
        let established = Arc::new(established);

        let terminal = self.terminal_settings(config, agent_forwarding)?;
        // Everything after authentication — the channel open, `pty-req`,
        // `shell`/`exec` — is still the far end answering, and a server that
        // authenticates and then stops answering would otherwise hold the tab
        // open with no deadline and no way for the user to cancel out of it.
        // Same budget, same token as the handshake.
        let session = open_session_within(
            &cancel,
            connection.handshake_timeout,
            &target,
            self.prompts.as_deref(),
            async {
                match self.string(config, SETTING_EXEC_COMMAND) {
                    Some(command) if !command.trim().is_empty() => {
                        SshSession::open_exec(established, command, &terminal, events).await
                    }
                    _ => SshSession::open_shell(established, &terminal, events).await,
                }
            },
        )
        .await?;

        Ok(Box::new(session))
    }
}

/// Opens the shell or the `exec` under the handshake's deadline and token.
///
/// A thin wrapper so that the post-authentication phase is bounded by exactly
/// the same rules as the phases before it — including the suspension of the
/// clock while a question is on screen, which matters here because a server
/// may still raise one.
async fn open_session_within<F>(
    cancel: &CancellationToken,
    timeout: Duration,
    target: &remoter_proto::HostPort,
    prompts: Option<&PromptChannel>,
    open: F,
) -> Result<SshSession, ProtocolError>
where
    F: Future<Output = Result<SshSession, ProtocolError>>,
{
    with_deadline(cancel, timeout, target, prompts, open).await?
}

impl SshProtocol {
    fn string<'a>(&'a self, config: &'a EffectiveConnection, key: &str) -> Option<&'a str> {
        self.schema.string(&config.settings, key)
    }

    fn boolean(&self, config: &EffectiveConnection, key: &str) -> Result<bool, ProtocolError> {
        Ok(self.schema.boolean(&config.settings, key)?.unwrap_or(false))
    }

    fn boolean_or(
        &self,
        config: &EffectiveConnection,
        key: &str,
        fallback: bool,
    ) -> Result<bool, ProtocolError> {
        Ok(self
            .schema
            .boolean(&config.settings, key)?
            .unwrap_or(fallback))
    }

    fn terminal_settings(
        &self,
        config: &EffectiveConnection,
        agent_forwarding: bool,
    ) -> Result<TerminalSettings, ProtocolError> {
        let dimension = |key: &str, fallback: u16| -> Result<u16, ProtocolError> {
            Ok(self
                .schema
                .integer(&config.settings, key)?
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
                .unwrap_or(fallback))
        };

        Ok(TerminalSettings {
            term: self
                .string(config, SETTING_TERMINAL_TYPE)
                .filter(|term| !term.trim().is_empty())
                .unwrap_or(DEFAULT_TERM)
                .to_owned(),
            columns: dimension(SETTING_COLUMNS, DEFAULT_COLUMNS)?,
            rows: dimension(SETTING_ROWS, DEFAULT_ROWS)?,
            environment: parse_environment(self.string(config, SETTING_ENVIRONMENT)),
            initial_command: self
                .string(config, SETTING_INITIAL_COMMAND)
                .filter(|command| !command.trim().is_empty())
                .map(ToOwned::to_owned),
            clipboard: remoter_proto::ClipboardPolicy::default(),
            agent_forwarding,
        })
    }
}

/// The settings this adapter understands.
#[must_use]
pub fn schema() -> SettingsSchema {
    SettingsSchema::new(vec![
        SettingField::new(
            SETTING_TERMINAL_TYPE,
            "settings.ssh.terminal_type",
            SettingKind::Text { max_len: 64 },
        )
        .with_default(DEFAULT_TERM),
        SettingField::new(
            SETTING_COLUMNS,
            "settings.ssh.columns",
            // A terminal narrower than one column cannot render, and one wider
            // than the SSH window size field allows cannot be requested.
            SettingKind::Integer { min: 1, max: 4096 },
        )
        .with_default(DEFAULT_COLUMNS.to_string()),
        SettingField::new(
            SETTING_ROWS,
            "settings.ssh.rows",
            SettingKind::Integer { min: 1, max: 4096 },
        )
        .with_default(DEFAULT_ROWS.to_string()),
        SettingField::new(
            SETTING_COMPRESSION,
            "settings.ssh.compression",
            SettingKind::Boolean,
        )
        .with_default("false"),
        SettingField::new(
            SETTING_INITIAL_COMMAND,
            "settings.ssh.initial_command",
            SettingKind::Text { max_len: 1024 },
        ),
        SettingField::new(
            SETTING_EXEC_COMMAND,
            "settings.ssh.exec_command",
            SettingKind::Text { max_len: 4096 },
        ),
        SettingField::new(
            SETTING_ENVIRONMENT,
            "settings.ssh.environment",
            SettingKind::Text { max_len: 4096 },
        ),
        SettingField::new(
            SETTING_AGENT_AUTH,
            "settings.ssh.agent_auth",
            SettingKind::Boolean,
        )
        // On: the agent is the method where the private key never enters this
        // process, so it is the one to try first wherever it exists.
        .with_default("true"),
        SettingField::new(
            SETTING_AGENT_IDENTITY,
            "settings.ssh.agent_identity",
            SettingKind::Text { max_len: 256 },
        ),
        SettingField::new(
            SETTING_AGENT_FORWARDING,
            "settings.ssh.agent_forwarding",
            SettingKind::Boolean,
        )
        // Off, and it stays off: a compromised remote host with a forwarded
        // agent can impersonate the user everywhere that key opens.
        .with_default("false"),
    ])
}

/// Parses `NAME=value` lines into environment requests.
///
/// Blank lines and lines without a `=` are skipped rather than rejected: this
/// field is free text a user types, and refusing a whole connection over a
/// stray line would be a poor trade. A name containing a `=` cannot be
/// expressed and is not accepted by any server anyway.
#[must_use]
pub fn parse_environment(value: Option<&str>) -> Vec<(String, String)> {
    let Some(value) = value else {
        return Vec::new();
    };
    value
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
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

    #[test]
    fn the_schema_has_no_secret_in_it() {
        // A settings map travels through import, export and inheritance. A
        // password in one would travel with all three, which is why
        // `SettingKind` has no `Secret` variant — asserted here so that a
        // future field cannot smuggle one in as free text.
        for field in schema().fields() {
            let key = field.key.to_lowercase();
            for forbidden in ["password", "passphrase", "secret", "key_data", "token"] {
                assert!(
                    !key.contains(forbidden),
                    "{} looks like a credential field",
                    field.key
                );
            }
        }
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let schema = schema();
        let empty = BTreeMap::new();

        assert_eq!(
            schema.string(&empty, SETTING_TERMINAL_TYPE),
            Some("xterm-256color")
        );
        assert_eq!(schema.integer(&empty, SETTING_COLUMNS).unwrap(), Some(80));
        assert_eq!(schema.integer(&empty, SETTING_ROWS).unwrap(), Some(24));
        assert_eq!(
            schema.boolean(&empty, SETTING_COMPRESSION).unwrap(),
            Some(false)
        );
        // The two that carry a security decision.
        assert_eq!(
            schema.boolean(&empty, SETTING_AGENT_AUTH).unwrap(),
            Some(true)
        );
        assert_eq!(
            schema.boolean(&empty, SETTING_AGENT_FORWARDING).unwrap(),
            Some(false),
            "agent forwarding must default to off"
        );
    }

    #[test]
    fn every_field_the_form_shows_validates_its_own_input() {
        let schema = schema();

        let bad_columns = settings_from(NodeId::new(), [(SETTING_COLUMNS, "0")]);
        assert!(schema.validate(&bad_columns).is_err());

        let huge_columns = settings_from(NodeId::new(), [(SETTING_COLUMNS, "100000")]);
        assert!(schema.validate(&huge_columns).is_err());

        let bad_boolean = settings_from(NodeId::new(), [(SETTING_AGENT_FORWARDING, "yes")]);
        assert!(schema.validate(&bad_boolean).is_err());

        let good = settings_from(
            NodeId::new(),
            [
                (SETTING_COLUMNS, "200"),
                (SETTING_ROWS, "50"),
                (SETTING_AGENT_FORWARDING, "true"),
                (SETTING_TERMINAL_TYPE, "screen-256color"),
            ],
        );
        schema.validate(&good).unwrap();
    }

    #[test]
    fn a_setting_error_names_the_key_and_never_the_value() {
        // A settings map is exactly where a mistyped password ends up.
        let schema = schema();
        let settings = settings_from(NodeId::new(), [(SETTING_COLUMNS, "hunter2")]);
        let error = schema.validate(&settings).unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(rendered.contains(SETTING_COLUMNS));
        assert!(!rendered.contains("hunter2"), "rendered: {rendered}");
    }

    #[test]
    fn an_unknown_setting_is_kept_rather_than_rejected() {
        // Opening a vault in an older build must not discard a newer
        // protocol's settings.
        let schema = schema();
        let settings = settings_from(NodeId::new(), [("x11_forwarding", "true")]);
        schema.validate(&settings).unwrap();
        assert_eq!(schema.unknown_keys(&settings), vec!["x11_forwarding"]);
    }

    #[test]
    fn environment_lines_are_parsed_forgivingly() {
        assert_eq!(
            parse_environment(Some("LANG=en_GB.UTF-8\nEDITOR=vim")),
            vec![
                ("LANG".to_owned(), "en_GB.UTF-8".to_owned()),
                ("EDITOR".to_owned(), "vim".to_owned()),
            ]
        );
        // A value may contain `=`; only the first one separates.
        assert_eq!(
            parse_environment(Some("OPTS=a=b")),
            vec![("OPTS".to_owned(), "a=b".to_owned())]
        );
        // Blank and malformed lines are skipped rather than failing the
        // connection.
        assert_eq!(
            parse_environment(Some("\n  \nnonsense\n=novalue")),
            Vec::new()
        );
        assert_eq!(parse_environment(None), Vec::new());
    }

    /// An `EffectiveConnection` carrying `settings`. Built by hand because the
    /// real producer, `Tree::effective_connection`, needs a whole vault.
    fn effective(settings: BTreeMap<String, Resolved<String>>) -> EffectiveConnection {
        fn root<T>(value: T) -> Resolved<T> {
            Resolved::new(value, Provenance::DefaultAtRoot)
        }
        EffectiveConnection {
            node: NodeId::new(),
            name: "db-01".to_owned(),
            protocol: ssh_protocol_id().unwrap(),
            host: "db-01.internal".to_owned(),
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

    fn adapter() -> SshProtocol {
        struct NoTrust;
        impl TrustStore for NoTrust {
            fn lookup(
                &self,
                _host: &remoter_proto::HostPort,
                _algorithm: &str,
            ) -> Option<remoter_proto::KnownKey> {
                None
            }
            fn remember(
                &self,
                _host: &remoter_proto::HostPort,
                _key: &remoter_proto::KnownKey,
            ) -> Result<(), ProtocolError> {
                Ok(())
            }
        }
        SshProtocol::new(Arc::new(NoTrust)).unwrap()
    }

    #[test]
    fn the_terminal_is_configured_from_the_settings() {
        let adapter = adapter();
        let config = effective(settings_from(
            NodeId::new(),
            [
                (SETTING_TERMINAL_TYPE, "screen-256color"),
                (SETTING_COLUMNS, "200"),
                (SETTING_ROWS, "60"),
                (SETTING_INITIAL_COMMAND, "tmux attach"),
                (SETTING_ENVIRONMENT, "LANG=en_GB.UTF-8"),
            ],
        ));

        let terminal = adapter.terminal_settings(&config, false).unwrap();
        assert_eq!(terminal.term, "screen-256color");
        assert_eq!(terminal.columns, 200);
        assert_eq!(terminal.rows, 60);
        assert_eq!(terminal.initial_command.as_deref(), Some("tmux attach"));
        assert_eq!(
            terminal.environment,
            vec![("LANG".to_owned(), "en_GB.UTF-8".to_owned())]
        );
        assert!(!terminal.agent_forwarding);
    }

    #[test]
    fn an_unconfigured_terminal_gets_the_defaults() {
        let adapter = adapter();
        let terminal = adapter
            .terminal_settings(&effective(BTreeMap::new()), false)
            .unwrap();
        assert_eq!(terminal.term, DEFAULT_TERM);
        assert_eq!(terminal.columns, DEFAULT_COLUMNS);
        assert_eq!(terminal.rows, DEFAULT_ROWS);
        assert!(terminal.initial_command.is_none());
    }

    #[test]
    fn a_blank_setting_falls_back_rather_than_producing_an_empty_terminal() {
        // An empty `TERM` would make the remote's `terminfo` lookup fail and
        // every full-screen program refuse to draw.
        let adapter = adapter();
        let config = effective(settings_from(
            NodeId::new(),
            [
                (SETTING_TERMINAL_TYPE, "   "),
                (SETTING_INITIAL_COMMAND, "  "),
            ],
        ));
        let terminal = adapter.terminal_settings(&config, false).unwrap();
        assert_eq!(terminal.term, DEFAULT_TERM);
        assert!(terminal.initial_command.is_none());
    }

    #[test]
    fn agent_forwarding_reaches_the_channel_only_when_it_is_asked_for() {
        let adapter = adapter();
        assert!(
            !adapter
                .boolean(&effective(BTreeMap::new()), SETTING_AGENT_FORWARDING)
                .unwrap()
        );
        let on = effective(settings_from(
            NodeId::new(),
            [(SETTING_AGENT_FORWARDING, "true")],
        ));
        assert!(adapter.boolean(&on, SETTING_AGENT_FORWARDING).unwrap());
        assert!(
            adapter
                .terminal_settings(&on, true)
                .unwrap()
                .agent_forwarding
        );
    }

    #[test]
    fn agent_authentication_is_on_unless_it_is_turned_off() {
        // The agent is the method where the private key never enters this
        // process, so it is the default.
        let adapter = adapter();
        assert!(
            adapter
                .boolean_or(&effective(BTreeMap::new()), SETTING_AGENT_AUTH, true)
                .unwrap()
        );
        let off = effective(settings_from(
            NodeId::new(),
            [(SETTING_AGENT_AUTH, "false")],
        ));
        assert!(!adapter.boolean_or(&off, SETTING_AGENT_AUTH, true).unwrap());
    }

    #[test]
    fn a_named_agent_identity_is_read_from_the_settings() {
        let adapter = adapter();
        let config = effective(settings_from(
            NodeId::new(),
            [(SETTING_AGENT_IDENTITY, "  ada@work  ")],
        ));
        assert_eq!(
            adapter
                .string(&config, SETTING_AGENT_IDENTITY)
                .map(str::trim),
            Some("ada@work")
        );
        // Blank means "no preference", not "an identity called nothing".
        let blank = effective(settings_from(
            NodeId::new(),
            [(SETTING_AGENT_IDENTITY, "   ")],
        ));
        assert_eq!(
            adapter
                .string(&blank, SETTING_AGENT_IDENTITY)
                .map(str::trim)
                .filter(|filter| !filter.is_empty()),
            None
        );
    }

    #[tokio::test]
    async fn a_server_that_stalls_after_authenticating_does_not_hold_the_tab_open() {
        // Channel open, `pty-req` and `shell` are all round trips with the far
        // end. Before this, none of them was bounded by anything: a server
        // that authenticated and then stopped answering left the session
        // hanging with no deadline and no way to cancel out of it.
        let target = remoter_proto::HostPort::new("db-01.internal", 22).unwrap();
        // Bounded well past the deadline under test: without one the open
        // never returns, and a hanging test says nothing.
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            open_session_within(
                &CancellationToken::new(),
                Duration::from_millis(200),
                &target,
                None,
                async { std::future::pending::<Result<SshSession, ProtocolError>>().await },
            ),
        )
        .await
        .expect("the post-authentication phase had no deadline")
        .unwrap_err();

        let ProtocolError::ConnectTimeout {
            target: named,
            timeout_ms,
        } = error
        else {
            panic!("expected ConnectTimeout, got {error:?}");
        };
        assert_eq!(named, target);
        assert_eq!(timeout_ms, 200);
    }

    #[tokio::test]
    async fn closing_the_tab_stops_a_stalled_post_authentication_phase() {
        let target = remoter_proto::HostPort::new("db-01.internal", 22).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            open_session_within(&cancel, Duration::from_secs(3600), &target, None, async {
                std::future::pending::<Result<SshSession, ProtocolError>>().await
            }),
        )
        .await
        .expect("the post-authentication phase ignored the cancellation token")
        .unwrap_err();
        assert!(matches!(error, ProtocolError::Cancelled));
    }

    #[test]
    fn the_adapter_reports_the_documented_identity_and_capabilities() {
        struct NoTrust;
        impl TrustStore for NoTrust {
            fn lookup(
                &self,
                _host: &remoter_proto::HostPort,
                _algorithm: &str,
            ) -> Option<remoter_proto::KnownKey> {
                None
            }
            fn remember(
                &self,
                _host: &remoter_proto::HostPort,
                _key: &remoter_proto::KnownKey,
            ) -> Result<(), ProtocolError> {
                Ok(())
            }
        }

        let protocol = SshProtocol::new(Arc::new(NoTrust)).unwrap();
        assert_eq!(remoter_proto::Protocol::id(&protocol).as_str(), "ssh");
        assert_eq!(
            remoter_proto::Protocol::capabilities(&protocol),
            capabilities()
        );
        assert_eq!(
            remoter_proto::Protocol::settings_schema(&protocol)
                .fields()
                .len(),
            schema().fields().len()
        );
        assert_eq!(format!("{protocol:?}"), "SshProtocol { can_prompt: false }");
    }
}
