//! Authentication, in order of preference.
//!
//! 1. **The platform agent.** The private key never enters this process, so a
//!    memory-disclosure bug here cannot yield one. Tried first, always, when
//!    the connection allows it.
//! 2. **A public key from the vault**, in whichever of OpenSSH, PKCS#8 or
//!    PuTTY's format the file happens to be ([`crate::keyfmt`]). A
//!    passphrase-protected key raises a prompt and is retried.
//! 3. **A password.**
//! 4. **Keyboard-interactive** (RFC 4256), which is where 2FA codes and
//!    expired-password changes arrive. Every challenge is relayed to the user;
//!    see [`answer_challenge`] for why none of them is auto-answered when
//!    there is an interface to ask.
//!
//! The ladder starts with a `none` request, which is what OpenSSH does and
//! what makes a server name its methods (RFC 4252 §5.2). That list is what
//! turns "authentication failed" into "the server does not accept password
//! authentication; it offers: publickey, keyboard-interactive".

use std::sync::Arc;

use remoter_proto::{
    CredentialKind, CredentialProvider, CredentialProviderExt, EventSink, HostPort, PromptKind,
    ProtocolError, SessionEvent, SessionWarning,
};
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{MethodKind, MethodSet};
use zeroize::Zeroizing;

use crate::agent;
use crate::error::map_russh;
use crate::handler::SshHandler;
use crate::keyfmt::parse_private_key;
use crate::prompt::PromptChannel;

/// Which method actually succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshAuthMethod {
    /// The server accepted `none`. Rare, and worth surfacing.
    None,
    /// The platform SSH agent signed the challenge.
    Agent,
    /// A key from the vault signed the challenge.
    PublicKey,
    /// A password was sent.
    Password,
    /// The server's challenges were answered (RFC 4256).
    KeyboardInteractive,
}

impl SshAuthMethod {
    /// A stable ASCII name for the message catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Agent => "agent",
            Self::PublicKey => "publickey",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }

    /// The taxonomy's credential kind, for error reporting.
    #[must_use]
    pub const fn credential_kind(self) -> CredentialKind {
        match self {
            Self::Agent => CredentialKind::Agent,
            Self::PublicKey => CredentialKind::PrivateKey,
            Self::Password | Self::KeyboardInteractive => CredentialKind::Password,
            Self::None => CredentialKind::None,
        }
    }
}

/// What happened during authentication. Shown in the session panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReport {
    /// The method that succeeded.
    pub method: SshAuthMethod,
    /// Which agent signed, when one did. The interface says "your key never
    /// left <agent>", which is only reassuring if it names one.
    pub agent: Option<String>,
    /// What the server said it accepts. Empty when it never said.
    pub offered: Vec<String>,
    /// Whether the server wants another factor as well.
    pub partial_success: bool,
}

/// Everything one authentication attempt needs.
pub struct AuthContext<'a> {
    /// The account to log in as.
    pub username: &'a str,
    /// The credential, borrowed rather than held.
    pub credentials: &'a dyn CredentialProvider,
    /// Whether the platform agent may be used.
    pub allow_agent: bool,
    /// Which agent identity to use, by comment substring.
    ///
    /// Overrides [`CredentialProvider::agent_filter`], because the connection
    /// may name an identity where the credential does not — an agent-only
    /// connection has no stored credential to carry the choice.
    pub agent_filter: Option<&'a str>,
    /// Where prompts and warnings go.
    pub events: &'a EventSink,
    /// How to ask the user something. `None` for a session with no interface,
    /// which then cannot answer a challenge and says so.
    pub prompts: Option<&'a PromptChannel>,
    /// The machine being authenticated to, for the failure message.
    pub target: &'a HostPort,
}

/// Walks the ladder.
///
/// # Errors
///
/// [`ProtocolError::AuthMethodUnavailable`] when the credential's method is
/// not one the server offers — the message that names what it does offer;
/// [`ProtocolError::AuthRejected`] when a method was tried and refused;
/// [`ProtocolError::AuthCancelled`] when the user dismissed a prompt;
/// [`ProtocolError::CredentialRequired`] when nothing was available to try.
pub async fn authenticate(
    handle: &mut Handle<SshHandler>,
    context: &AuthContext<'_>,
) -> Result<AuthReport, ProtocolError> {
    // RFC 4252 §5.2: the `none` request is how a client learns which methods
    // are available. A server that accepts it wants no authentication at all.
    let mut state = match handle
        .authenticate_none(context.username)
        .await
        .map_err(|error| map_russh(&error, "start authentication"))?
    {
        AuthResult::Success => {
            return Ok(AuthReport {
                method: SshAuthMethod::None,
                agent: None,
                offered: Vec::new(),
                partial_success: false,
            });
        }
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => Ladder::new(remaining_methods, partial_success),
    };

    if context.allow_agent && state.allows(MethodKind::PublicKey) {
        if let Some(report) = try_agent(handle, context, &mut state).await? {
            return Ok(report);
        }
    }

    if has_private_key(context.credentials) {
        if state.allows(MethodKind::PublicKey) {
            if let Some(report) = try_private_key(handle, context, &mut state).await? {
                return Ok(report);
            }
        } else {
            state.unavailable(SshAuthMethod::PublicKey);
        }
    }

    if has_password(context.credentials) {
        if state.allows(MethodKind::Password) {
            if let Some(report) = try_password(handle, context, &mut state).await? {
                return Ok(report);
            }
        } else {
            state.unavailable(SshAuthMethod::Password);
        }
    }

    if state.allows(MethodKind::KeyboardInteractive) {
        if let Some(report) = try_keyboard_interactive(handle, context, &mut state).await? {
            return Ok(report);
        }
    }

    Err(state.give_up(context.target))
}

/// The ladder's running state: what the server offers, and what we have tried.
struct Ladder {
    offered: MethodSet,
    partial_success: bool,
    attempted: Option<SshAuthMethod>,
    unavailable: Option<SshAuthMethod>,
}

impl Ladder {
    fn new(offered: MethodSet, partial_success: bool) -> Self {
        Self {
            offered,
            partial_success,
            attempted: None,
            unavailable: None,
        }
    }

    /// Whether a method is worth trying.
    ///
    /// An empty list is treated as "the server did not say" rather than "the
    /// server offers nothing": several implementations answer a `none` request
    /// with an empty name-list, and refusing to try anything would make this
    /// client unable to reach them at all.
    fn allows(&self, method: MethodKind) -> bool {
        self.offered.is_empty() || self.offered.contains(&method)
    }

    fn attempted(&mut self, method: SshAuthMethod) {
        self.attempted = Some(method);
    }

    fn unavailable(&mut self, method: SshAuthMethod) {
        if self.unavailable.is_none() {
            self.unavailable = Some(method);
        }
    }

    fn refused(&mut self, remaining: MethodSet, partial_success: bool) {
        self.offered = remaining;
        self.partial_success = partial_success;
    }

    fn names(&self) -> Vec<String> {
        self.offered
            .iter()
            .map(|kind| <&str>::from(kind).to_owned())
            .collect()
    }

    fn report(&self, method: SshAuthMethod, agent: Option<String>) -> AuthReport {
        AuthReport {
            method,
            agent,
            offered: self.names(),
            partial_success: self.partial_success,
        }
    }

    /// The failure the tab shows.
    fn give_up(self, target: &HostPort) -> ProtocolError {
        let offered = self.names();
        // "The server does not accept password authentication. It offers:
        // public key, keyboard-interactive." — the taxonomy's exact case.
        if let Some(method) = self.unavailable {
            return ProtocolError::AuthMethodUnavailable {
                attempted: method.credential_kind(),
                offered,
            };
        }
        if let Some(method) = self.attempted {
            return ProtocolError::AuthRejected {
                attempted: method.credential_kind(),
            };
        }
        // Nothing was even attempted: there was no credential and no way to
        // ask for one. That is an Acquire-stage failure, not an authentication
        // one, and the next action is to choose or enter a credential.
        ProtocolError::CredentialRequired {
            target: target.clone(),
        }
    }
}

/// Whether the provider holds a key, without reading it.
fn has_private_key(credentials: &dyn CredentialProvider) -> bool {
    credentials
        .with_private_key(&mut |_key, _passphrase| ())
        .is_some()
}

/// Whether the provider holds a password, without reading it.
fn has_password(credentials: &dyn CredentialProvider) -> bool {
    credentials.with_password(&mut |_password| ()).is_some()
}

/// Offers every identity the agent holds.
async fn try_agent(
    handle: &mut Handle<SshHandler>,
    context: &AuthContext<'_>,
    state: &mut Ladder,
) -> Result<Option<AuthReport>, ProtocolError> {
    let (mut client, endpoint) = match agent::connect().await {
        Ok(found) => found,
        Err(_) => {
            // No agent is not a failure: it is one method of several being
            // unavailable, and the ladder moves on.
            tracing::debug!("no SSH agent is available");
            return Ok(None);
        }
    };

    let identities = client
        .request_identities()
        .await
        .map_err(|error| crate::error::map_key_error(&error))?;
    let filter = context
        .agent_filter
        .or_else(|| context.credentials.agent_filter());
    let identities = agent::filter_identities(identities, filter);
    if identities.is_empty() {
        tracing::debug!(
            agent = endpoint.kind(),
            "the agent holds no usable identity"
        );
        return Ok(None);
    }

    for identity in identities {
        state.attempted(SshAuthMethod::Agent);
        let public = identity.public_key().into_owned();
        let hash_alg = rsa_hash(handle, public.algorithm().is_rsa()).await;

        let outcome = handle
            .authenticate_publickey_with(context.username, public, hash_alg, &mut client)
            .await;
        match outcome {
            Ok(AuthResult::Success) => {
                tracing::info!(
                    agent = endpoint.kind(),
                    "authenticated through the SSH agent"
                );
                return Ok(Some(
                    state.report(SshAuthMethod::Agent, Some(endpoint.kind().to_owned())),
                ));
            }
            Ok(AuthResult::Failure {
                remaining_methods,
                partial_success,
            }) => state.refused(remaining_methods, partial_success),
            Err(error) => {
                // An agent that fails mid-signature — the user declined a
                // confirmation on a hardware key, say — is not a reason to
                // abandon the remaining methods.
                tracing::debug!(agent = endpoint.kind(), error = %error, "an agent identity was not accepted");
                break;
            }
        }
    }
    Ok(None)
}

/// Reads a key from the vault, prompting for its passphrase where needed.
async fn try_private_key(
    handle: &mut Handle<SshHandler>,
    context: &AuthContext<'_>,
    state: &mut Ladder,
) -> Result<Option<AuthReport>, ProtocolError> {
    let key = obtain_private_key(context).await?;

    state.attempted(SshAuthMethod::PublicKey);
    let hash_alg = rsa_hash(handle, key.algorithm().is_rsa()).await;
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);

    match handle
        .authenticate_publickey(context.username, key)
        .await
        .map_err(|error| map_russh(&error, "offer a public key"))?
    {
        AuthResult::Success => Ok(Some(state.report(SshAuthMethod::PublicKey, None))),
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            state.refused(remaining_methods, partial_success);
            Ok(None)
        }
    }
}

/// Reads the vault's key, asking for a passphrase when the stored one will
/// not open it.
///
/// Two failures mean "ask the user", not "give up":
///
/// - `CredentialMissing` — the key is encrypted and no passphrase is stored.
/// - `AuthRejected` — a passphrase *is* stored and it did not work. An
///   authenticated cipher cannot tell a wrong passphrase from a corrupt file
///   ([`crate::keyfmt::parse_private_key`]), so this is the only shape a stale
///   stored passphrase can arrive in. Treating it as final made a rotated
///   passphrase permanently unusable: every attempt re-read the key with the
///   same stale value and the user was never asked.
///
/// The file is consulted for whether it is encrypted at all, so a genuinely
/// corrupt key still fails rather than raising a passphrase dialog that cannot
/// help.
async fn obtain_private_key(context: &AuthContext<'_>) -> Result<PrivateKey, ProtocolError> {
    let error = match read_key(context.credentials, None) {
        Ok(key) => return Ok(key),
        Err(
            error @ (ProtocolError::CredentialMissing { .. }
            | ProtocolError::AuthRejected {
                attempted: CredentialKind::PrivateKey,
            }),
        ) => error,
        Err(error) => return Err(error),
    };

    if !key_is_encrypted(context.credentials) {
        return Err(error);
    }
    let Some(prompts) = context.prompts else {
        return Err(ProtocolError::CredentialMissing {
            name: "key passphrase".to_owned(),
        });
    };

    // Ask, then read it again with the answer — the passphrase is borrowed for
    // that second read and dropped. A typed one wins over the stored one; see
    // `read_key`.
    let passphrase = prompts
        .ask(
            context.events,
            PromptKind::KeyPassphrase,
            context.target.to_string(),
            false,
        )
        .await?;
    read_key(context.credentials, Some(&passphrase))
}

/// Whether the stored key file is encrypted, without reading its material.
///
/// Read from the file's own headers ([`crate::keyfmt::needs_passphrase`]),
/// which is what tells "the passphrase is wrong" apart from "the file is not a
/// key".
fn key_is_encrypted(credentials: &dyn CredentialProvider) -> bool {
    credentials
        .with_private_key(&mut |key: &[u8], _stored: Option<&[u8]>| {
            crate::keyfmt::needs_passphrase(key)
        })
        .unwrap_or(false)
}

/// Borrows the key bytes and parses them. The material never leaves the
/// closure; only the parsed key, which zeroizes itself, comes out.
fn read_key(
    credentials: &dyn CredentialProvider,
    passphrase: Option<&[u8]>,
) -> Result<PrivateKey, ProtocolError> {
    credentials
        .with_private_key(&mut |key: &[u8], stored: Option<&[u8]>| {
            // A passphrase typed just now wins over one the vault stored: the
            // stored one is what failed a moment ago.
            parse_private_key(key, passphrase.or(stored))
        })
        .unwrap_or(Err(ProtocolError::CredentialMissing {
            name: "private key".to_owned(),
        }))
}

/// Sends a password.
async fn try_password(
    handle: &mut Handle<SshHandler>,
    context: &AuthContext<'_>,
    state: &mut Ladder,
) -> Result<Option<AuthReport>, ProtocolError> {
    // RFC 4252 §8 puts the password on the wire as UTF-8. A credential that is
    // not UTF-8 cannot be sent, and guessing an encoding would send the wrong
    // bytes to a server that will log the failure.
    let password = context
        .credentials
        .with_password(&mut |bytes: &[u8]| {
            std::str::from_utf8(bytes)
                .map(|text| Zeroizing::new(text.to_owned()))
                .map_err(|_| ProtocolError::AuthRejected {
                    attempted: CredentialKind::Password,
                })
        })
        .unwrap_or(Err(ProtocolError::CredentialMissing {
            name: "password".to_owned(),
        }))?;

    state.attempted(SshAuthMethod::Password);
    // `russh` takes the password by value and owns it from here; this copy is
    // wiped when `password` drops, which is as far as this crate's control
    // over the buffer reaches.
    match handle
        .authenticate_password(context.username, password.as_str())
        .await
        .map_err(|error| map_russh(&error, "send a password"))?
    {
        AuthResult::Success => Ok(Some(state.report(SshAuthMethod::Password, None))),
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            state.refused(remaining_methods, partial_success);
            Ok(None)
        }
    }
}

/// How many `SSH_MSG_USERAUTH_INFO_REQUEST` rounds one keyboard-interactive
/// attempt may take.
///
/// RFC 4256 §3.2 puts no limit on how often a server may ask, so a hostile one
/// (threat model T4) can keep this loop — and a dialog in front of the user —
/// going for the whole handshake window, or for as long as the user keeps
/// answering. No real PAM stack needs more than a handful of rounds.
pub const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 16;

/// The half of `russh`'s keyboard-interactive exchange the loop below drives.
///
/// Behind a trait so the round cap can be exercised against a server that
/// never stops asking, which is the only case the cap exists for.
trait InfoRequestResponder {
    fn respond(
        &mut self,
        answers: Vec<String>,
    ) -> impl Future<Output = Result<KeyboardInteractiveAuthResponse, ProtocolError>>;
}

impl InfoRequestResponder for Handle<SshHandler> {
    async fn respond(
        &mut self,
        answers: Vec<String>,
    ) -> Result<KeyboardInteractiveAuthResponse, ProtocolError> {
        self.authenticate_keyboard_interactive_respond(answers)
            .await
            .map_err(|error| map_russh(&error, "answer a keyboard-interactive challenge"))
    }
}

/// Runs RFC 4256 keyboard-interactive, relaying each challenge to the user.
async fn try_keyboard_interactive(
    handle: &mut Handle<SshHandler>,
    context: &AuthContext<'_>,
    state: &mut Ladder,
) -> Result<Option<AuthReport>, ProtocolError> {
    let response = handle
        .authenticate_keyboard_interactive_start(context.username, None)
        .await
        .map_err(|error| map_russh(&error, "start keyboard-interactive authentication"))?;
    drive_keyboard_interactive(handle, context, state, response).await
}

/// Answers challenges until the server stops asking, or asks too often.
async fn drive_keyboard_interactive<R: InfoRequestResponder>(
    responder: &mut R,
    context: &AuthContext<'_>,
    state: &mut Ladder,
    start: KeyboardInteractiveAuthResponse,
) -> Result<Option<AuthReport>, ProtocolError> {
    let mut response = start;
    let mut rounds = 0usize;

    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(Some(state.report(SshAuthMethod::KeyboardInteractive, None)));
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                state.attempted(SshAuthMethod::KeyboardInteractive);
                state.refused(remaining_methods, partial_success);
                return Ok(None);
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                rounds = rounds.saturating_add(1);
                if rounds > MAX_KEYBOARD_INTERACTIVE_ROUNDS {
                    // Not "the credentials were rejected": the server never
                    // decided. It is a peer abusing an unbounded exchange, and
                    // the ladder stops here rather than spinning.
                    return Err(ProtocolError::ProtocolViolation {
                        detail: "the server asked more keyboard-interactive rounds than the limit of 16",
                    });
                }
                state.attempted(SshAuthMethod::KeyboardInteractive);
                let answers = answer_challenge(context, &name, &instructions, prompts).await?;
                // `russh` takes the answers by value and owns them from here.
                // This is the last copy under this crate's control and it is
                // wiped when `answers` drops — the same boundary the password
                // path documents.
                let wire = answers
                    .iter()
                    .map(|answer| answer.as_str().to_owned())
                    .collect();
                response = responder.respond(wire).await?;
            }
        }
    }
}

/// Turns one `SSH_MSG_USERAUTH_INFO_REQUEST` into answers.
///
/// **Nothing is auto-answered while there is an interface to ask.** A stored
/// password could be sent to the first non-echo prompt — several clients do —
/// but the prompt text is written by the server, so that would mean answering
/// a question the user never saw with a secret they did not choose to send in
/// that moment. When there is no interface at all (a scripted connect), a
/// single non-echo prompt is answered from the stored password, because the
/// alternative is that such a connection cannot authenticate at all.
///
/// A request with no prompts is a message for the user, not a question:
/// RFC 4256 §3.3 requires an empty response, and the text is surfaced as a
/// warning so it is not simply swallowed.
///
/// Every answer is a credential typed a moment ago, so it lives in a
/// [`Zeroizing`] buffer exactly as the password path's does; nothing here
/// makes a plain `String` copy of a stored password or of a 2FA code.
async fn answer_challenge(
    context: &AuthContext<'_>,
    name: &str,
    instructions: &str,
    prompts: Vec<russh::client::Prompt>,
) -> Result<Vec<Zeroizing<String>>, ProtocolError> {
    let instruction = [name.trim(), instructions.trim()]
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    if prompts.is_empty() {
        if !instruction.is_empty() {
            let _ = context
                .events
                .send(SessionEvent::Warning(SessionWarning::Banner {
                    text: instruction,
                }))
                .await;
        }
        return Ok(Vec::new());
    }

    let Some(channel) = context.prompts else {
        return scripted_answers(context, &prompts);
    };

    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in prompts {
        // `prompt.prompt` is text the server wrote. It is passed through as
        // data — the interface renders it as text, never as markup — and
        // `echo` is honoured, because RFC 4256 §3.3 carries that flag per
        // prompt precisely so a client knows which answers are secret.
        let answer = channel
            .ask(
                context.events,
                PromptKind::KeyboardInteractive {
                    instruction: instruction.clone(),
                },
                prompt.prompt,
                prompt.echo,
            )
            .await?;
        // RFC 4256 §3.4 puts the responses on the wire as UTF-8 strings.
        // `from_utf8_lossy` would replace whatever did not decode with U+FFFD
        // and send *that* — a different answer from the one the user typed, to
        // a server that will log the failure. Refused instead, exactly as the
        // password path refuses a non-UTF-8 credential.
        let text = std::str::from_utf8(&answer).map_err(|_| ProtocolError::AuthRejected {
            attempted: CredentialKind::Password,
        })?;
        answers.push(Zeroizing::new(text.to_owned()));
    }
    Ok(answers)
}

/// The no-interface case: one hidden prompt may be answered from the stored
/// password, and anything else is refused rather than guessed at.
fn scripted_answers(
    context: &AuthContext<'_>,
    prompts: &[russh::client::Prompt],
) -> Result<Vec<Zeroizing<String>>, ProtocolError> {
    let single_hidden = prompts.len() == 1 && prompts.first().is_some_and(|p| !p.echo);
    if !single_hidden {
        return Err(ProtocolError::AuthCancelled);
    }
    context
        .credentials
        .with_password(&mut |bytes: &[u8]| {
            // The vault lends the password inside this closure and takes it
            // back; the copy made here zeroes itself, which is the borrow
            // contract the password path honours and a plain `String` breaks.
            std::str::from_utf8(bytes)
                .map(|text| vec![Zeroizing::new(text.to_owned())])
                .map_err(|_| ProtocolError::AuthRejected {
                    attempted: CredentialKind::Password,
                })
        })
        .unwrap_or(Err(ProtocolError::AuthCancelled))
}

/// The signature hash to use for an RSA key.
///
/// RFC 8332 added `rsa-sha2-256` and `rsa-sha2-512`; which of them a server
/// will accept is advertised through `server-sig-algs`, which arrives only
/// because `ext-info-c` is in the key exchange list ([`crate::algorithms`]).
async fn rsa_hash(handle: &Handle<SshHandler>, is_rsa: bool) -> Option<HashAlg> {
    if !is_rsa {
        return None;
    }
    handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten()
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
    use remoter_proto::{KeyBorrow, NoCredentials};

    /// A provider that lends whatever it was built with.
    struct Fixture {
        password: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        passphrase: Option<Vec<u8>>,
        filter: Option<String>,
    }

    impl Fixture {
        const fn empty() -> Self {
            Self {
                password: None,
                key: None,
                passphrase: None,
                filter: None,
            }
        }
    }

    impl CredentialProvider for Fixture {
        fn username(&self) -> Option<&str> {
            Some("ada")
        }

        fn kind(&self) -> CredentialKind {
            if self.key.is_some() {
                CredentialKind::PrivateKey
            } else if self.password.is_some() {
                CredentialKind::Password
            } else {
                CredentialKind::None
            }
        }

        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            match &self.password {
                Some(password) => {
                    f(password);
                    true
                }
                None => false,
            }
        }

        fn borrow_private_key(&self, f: &mut KeyBorrow<'_>) -> bool {
            match &self.key {
                Some(key) => {
                    f(key, self.passphrase.as_deref());
                    true
                }
                None => false,
            }
        }

        fn agent_filter(&self) -> Option<&str> {
            self.filter.as_deref()
        }
    }

    fn methods(kinds: &[MethodKind]) -> MethodSet {
        MethodSet::from(kinds)
    }

    fn target() -> HostPort {
        HostPort::new("db-01.internal", 22).unwrap()
    }

    #[test]
    fn presence_is_probed_without_reading_the_secret() {
        let with_password = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        assert!(has_password(&with_password));
        assert!(!has_private_key(&with_password));

        let with_key = Fixture {
            key: Some(b"-----BEGIN OPENSSH PRIVATE KEY-----".to_vec()),
            ..Fixture::empty()
        };
        assert!(has_private_key(&with_key));
        assert!(!has_password(&with_key));

        assert!(!has_password(&NoCredentials::new()));
        assert!(!has_private_key(&NoCredentials::new()));
    }

    #[test]
    fn a_server_that_named_its_methods_is_believed() {
        let state = Ladder::new(
            methods(&[MethodKind::PublicKey, MethodKind::KeyboardInteractive]),
            false,
        );
        assert!(state.allows(MethodKind::PublicKey));
        assert!(state.allows(MethodKind::KeyboardInteractive));
        assert!(!state.allows(MethodKind::Password));
    }

    #[test]
    fn a_server_that_named_nothing_is_not_taken_to_offer_nothing() {
        // Some implementations answer a `none` request with an empty
        // name-list. Reading that as "no methods" would make this client
        // unable to reach them at all.
        let state = Ladder::new(MethodSet::empty(), false);
        assert!(state.allows(MethodKind::Password));
        assert!(state.allows(MethodKind::PublicKey));
    }

    #[test]
    fn an_unoffered_method_produces_the_message_that_names_what_is_offered() {
        let mut state = Ladder::new(
            methods(&[MethodKind::PublicKey, MethodKind::KeyboardInteractive]),
            false,
        );
        state.unavailable(SshAuthMethod::Password);

        let error = state.give_up(&target());
        let ProtocolError::AuthMethodUnavailable { attempted, offered } = error else {
            panic!("expected AuthMethodUnavailable, got {error:?}");
        };
        assert_eq!(attempted, CredentialKind::Password);
        assert_eq!(
            offered,
            vec!["publickey".to_owned(), "keyboard-interactive".to_owned()]
        );
    }

    #[test]
    fn a_refused_attempt_reports_what_was_attempted() {
        let mut state = Ladder::new(methods(&[MethodKind::Password]), false);
        state.attempted(SshAuthMethod::Password);
        state.refused(methods(&[MethodKind::Password]), false);

        let error = state.give_up(&target());
        assert!(matches!(
            error,
            ProtocolError::AuthRejected {
                attempted: CredentialKind::Password
            }
        ));
        // The taxonomy: a rejected credential is not something to retry
        // automatically, because retrying locks accounts out.
        assert!(!error.is_retryable());
    }

    #[test]
    fn nothing_to_try_is_an_acquire_failure_not_an_authentication_one() {
        let state = Ladder::new(methods(&[MethodKind::PublicKey]), false);
        let error = state.give_up(&target());
        let ProtocolError::CredentialRequired { target: named } = error else {
            panic!("expected CredentialRequired, got {error:?}");
        };
        assert_eq!(named, target());
    }

    #[test]
    fn an_unavailable_method_outranks_a_rejection_in_the_message() {
        // "The server does not accept password authentication" is more useful
        // than "the server rejected these credentials" when both are true.
        let mut state = Ladder::new(methods(&[MethodKind::PublicKey]), false);
        state.attempted(SshAuthMethod::Agent);
        state.unavailable(SshAuthMethod::Password);
        assert!(matches!(
            state.give_up(&target()),
            ProtocolError::AuthMethodUnavailable { .. }
        ));
    }

    #[test]
    fn the_method_names_are_stable_and_map_to_the_taxonomy() {
        assert_eq!(SshAuthMethod::Agent.as_str(), "agent");
        assert_eq!(
            SshAuthMethod::Agent.credential_kind(),
            CredentialKind::Agent
        );
        assert_eq!(
            SshAuthMethod::PublicKey.credential_kind(),
            CredentialKind::PrivateKey
        );
        assert_eq!(
            SshAuthMethod::KeyboardInteractive.credential_kind(),
            CredentialKind::Password
        );
        assert_eq!(SshAuthMethod::None.credential_kind(), CredentialKind::None);
    }

    #[test]
    fn a_report_carries_what_the_panel_shows() {
        let mut state = Ladder::new(methods(&[MethodKind::PublicKey]), true);
        state.attempted(SshAuthMethod::Agent);
        let report = state.report(SshAuthMethod::Agent, Some("ssh-auth-sock".to_owned()));
        assert_eq!(report.method, SshAuthMethod::Agent);
        assert_eq!(report.agent.as_deref(), Some("ssh-auth-sock"));
        assert!(report.partial_success);
        assert_eq!(report.offered, vec!["publickey".to_owned()]);
    }

    #[test]
    fn no_failure_the_ladder_can_produce_carries_a_credential() {
        // The most likely way to leak a password from this crate is an error
        // that quotes the credential it just failed with. Every terminal
        // outcome is formatted and swept.
        const PASSWORD: &str = "correct-horse-battery-staple";
        const PASSPHRASE: &str = "the-key-passphrase";

        let credentials = Fixture {
            password: Some(PASSWORD.as_bytes().to_vec()),
            key: Some(b"-----BEGIN OPENSSH PRIVATE KEY-----".to_vec()),
            passphrase: Some(PASSPHRASE.as_bytes().to_vec()),
            filter: Some("ada@work".to_owned()),
        };

        let mut refused = Ladder::new(methods(&[MethodKind::Password]), false);
        refused.attempted(SshAuthMethod::Password);
        let report = refused.report(SshAuthMethod::Password, Some("ssh-auth-sock".to_owned()));

        let mut unavailable = Ladder::new(methods(&[MethodKind::PublicKey]), false);
        unavailable.unavailable(SshAuthMethod::Password);

        let errors = vec![
            refused.give_up(&target()),
            unavailable.give_up(&target()),
            Ladder::new(MethodSet::empty(), false).give_up(&target()),
            read_key(&credentials, None).unwrap_err(),
            read_key(&credentials, Some(PASSPHRASE.as_bytes())).unwrap_err(),
            ProtocolError::AuthCancelled,
        ];

        for error in &errors {
            let rendered = format!("{error} {error:?}");
            for secret in [PASSWORD, PASSPHRASE] {
                assert!(!rendered.contains(secret), "rendered: {rendered}");
            }
        }

        // And the report the session panel shows.
        let rendered = format!("{report:?}");
        for secret in [PASSWORD, PASSPHRASE] {
            assert!(!rendered.contains(secret), "rendered: {rendered}");
        }
    }

    #[test]
    fn a_key_that_cannot_be_read_reports_a_missing_credential_not_a_panic() {
        let error = read_key(&NoCredentials::new(), None).unwrap_err();
        assert!(matches!(error, ProtocolError::CredentialMissing { .. }));
    }

    #[test]
    fn a_typed_passphrase_wins_over_a_stored_one() {
        // The stored one is what just failed; re-using it would loop.
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let encrypted = key
            .encrypt(&mut russh::keys::key::safe_rng(), "the right one")
            .unwrap();
        let pem = encrypted
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        let credentials = Fixture {
            key: Some(pem.into_bytes()),
            passphrase: Some(b"the wrong one".to_vec()),
            ..Fixture::empty()
        };

        assert!(read_key(&credentials, None).is_err());
        let read = read_key(&credentials, Some(b"the right one")).unwrap();
        assert_eq!(
            read.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn a_password_that_is_not_utf8_is_refused_rather_than_mangled() {
        // RFC 4252 §8 puts the password on the wire as UTF-8. Guessing an
        // encoding would send the wrong bytes and lock the account.
        let credentials = Fixture {
            password: Some(vec![0xff, 0xfe]),
            ..Fixture::empty()
        };
        let outcome = credentials
            .with_password(&mut |bytes: &[u8]| std::str::from_utf8(bytes).is_ok())
            .unwrap();
        assert!(!outcome);
    }

    #[tokio::test]
    async fn a_message_with_no_prompts_is_surfaced_and_answered_empty() {
        // RFC 4256 §3.3: a request with no prompts is the server saying
        // something, and requires an empty response.
        let (events, mut rx) = remoter_proto::event_channel(8);
        let credentials = Fixture::empty();
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: None,
            target: &target,
        };

        let answers = answer_challenge(&context, "PAM", "Password expires in 3 days", Vec::new())
            .await
            .unwrap();
        assert!(answers.is_empty());

        let SessionEvent::Warning(SessionWarning::Banner { text }) = rx.recv().await.unwrap()
        else {
            panic!("expected the instruction to be surfaced");
        };
        assert!(text.contains("expires"));
    }

    #[tokio::test]
    async fn a_challenge_is_relayed_to_the_user_rather_than_auto_answered() {
        // The prompt text is written by the server. Answering it from a stored
        // password would send a secret to a question the user never saw.
        let (events, mut rx) = remoter_proto::event_channel(8);
        let (tx, channel) = PromptChannel::new();
        let credentials = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        let target = target();

        let answering = tokio::spawn({
            let events = events.clone();
            let channel = Arc::clone(&channel);
            async move {
                let context = AuthContext {
                    username: "ada",
                    credentials: &credentials,
                    allow_agent: false,
                    agent_filter: None,
                    events: &events,
                    prompts: Some(&channel),
                    target: &target,
                };
                answer_challenge(
                    &context,
                    "",
                    "Two-factor authentication",
                    vec![russh::client::Prompt {
                        prompt: "Verification code: ".to_owned(),
                        echo: false,
                    }],
                )
                .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        let PromptKind::KeyboardInteractive { instruction } = &prompt.kind else {
            panic!("expected a keyboard-interactive prompt");
        };
        assert_eq!(instruction, "Two-factor authentication");
        assert_eq!(prompt.text, "Verification code: ");
        assert!(!prompt.echo, "the server said this answer is secret");

        tx.send(remoter_proto::PromptAnswer::new(
            prompt.id,
            b"123456".to_vec(),
        ))
        .await
        .unwrap();
        let answers = answering.await.unwrap().unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].as_str(), "123456");
    }

    #[tokio::test]
    async fn a_2fa_answer_that_is_not_utf8_is_refused_rather_than_mangled() {
        // RFC 4256 §3.4 puts the responses on the wire as UTF-8.
        // `from_utf8_lossy` would substitute U+FFFD and send a *different*
        // answer than the user typed — to a server that will log the failure
        // and, on a second factor, may lock the account. The password path
        // forty lines earlier already refuses this.
        let (events, mut rx) = remoter_proto::event_channel(8);
        let (tx, channel) = PromptChannel::new();
        let credentials = Fixture::empty();
        let target = target();

        let answering = tokio::spawn({
            let events = events.clone();
            let channel = Arc::clone(&channel);
            async move {
                let context = AuthContext {
                    username: "ada",
                    credentials: &credentials,
                    allow_agent: false,
                    agent_filter: None,
                    events: &events,
                    prompts: Some(&channel),
                    target: &target,
                };
                answer_challenge(
                    &context,
                    "",
                    "",
                    vec![russh::client::Prompt {
                        prompt: "Verification code: ".to_owned(),
                        echo: false,
                    }],
                )
                .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        // A keyboard with a non-UTF-8 layout, or an interface that sent raw
        // bytes: either way this is not a string.
        tx.send(remoter_proto::PromptAnswer::new(
            prompt.id,
            vec![0xff, 0xfe, 0x00],
        ))
        .await
        .unwrap();

        let error = answering.await.unwrap().unwrap_err();
        assert!(
            matches!(
                error,
                ProtocolError::AuthRejected {
                    attempted: CredentialKind::Password
                }
            ),
            "expected the answer to be refused, got {error:?}"
        );
    }

    #[test]
    fn keyboard_interactive_answers_are_zeroizing_buffers() {
        // The type is the guarantee: a plain `String` copy of a stored vault
        // password or of a typed 2FA code would break the borrow contract the
        // password path honours (CLAUDE.md §0.2, §5).
        fn assert_wiped_on_drop(_: &Vec<Zeroizing<String>>) {}

        let credentials = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        let (events, _rx) = remoter_proto::event_channel(8);
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: None,
            target: &target,
        };
        let answers = scripted_answers(
            &context,
            &[russh::client::Prompt {
                prompt: "Password: ".to_owned(),
                echo: false,
            }],
        )
        .unwrap();
        assert_wiped_on_drop(&answers);
        assert_eq!(answers[0].as_str(), "hunter2");
    }

    /// A server that keeps asking, which is what the round cap is for.
    struct AlwaysAsks {
        rounds: usize,
    }

    impl InfoRequestResponder for AlwaysAsks {
        async fn respond(
            &mut self,
            _answers: Vec<String>,
        ) -> Result<KeyboardInteractiveAuthResponse, ProtocolError> {
            self.rounds = self.rounds.saturating_add(1);
            // A real server round trip yields to the runtime; without one the
            // uncapped loop would spin so tightly that the test's own timer
            // never fires, and a failure would look like a hang.
            tokio::task::yield_now().await;
            Ok(info_request())
        }
    }

    fn info_request() -> KeyboardInteractiveAuthResponse {
        KeyboardInteractiveAuthResponse::InfoRequest {
            name: String::new(),
            instructions: String::new(),
            prompts: vec![russh::client::Prompt {
                prompt: "Password: ".to_owned(),
                echo: false,
            }],
        }
    }

    #[tokio::test]
    async fn a_server_that_never_stops_asking_is_cut_off() {
        // RFC 4256 §3.2 puts no limit on the number of rounds, so a hostile
        // server (threat model T4) can spin this loop — and a dialog in front
        // of the user — for the whole handshake window.
        let credentials = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        let (events, _rx) = remoter_proto::event_channel(8);
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            // No interface: every round is answered from the stored password
            // without waiting for anyone, so nothing but the cap stops it.
            prompts: None,
            target: &target,
        };
        let mut state = Ladder::new(methods(&[MethodKind::KeyboardInteractive]), false);
        let mut server = AlwaysAsks { rounds: 0 };

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            drive_keyboard_interactive(&mut server, &context, &mut state, info_request()),
        )
        .await
        .expect("the ladder span forever");

        let error = outcome.unwrap_err();
        let ProtocolError::ProtocolViolation { detail } = error else {
            panic!("expected ProtocolViolation, got {error:?}");
        };
        assert!(
            detail.contains(&MAX_KEYBOARD_INTERACTIVE_ROUNDS.to_string()),
            "the failure should name the limit: {detail}"
        );
        assert_eq!(server.rounds, MAX_KEYBOARD_INTERACTIVE_ROUNDS);
    }

    #[tokio::test]
    async fn a_server_that_asks_a_reasonable_number_of_times_still_succeeds() {
        // The cap must not break two-factor authentication, which is several
        // rounds by design.
        struct AsksThenAccepts {
            left: usize,
        }
        impl InfoRequestResponder for AsksThenAccepts {
            async fn respond(
                &mut self,
                _answers: Vec<String>,
            ) -> Result<KeyboardInteractiveAuthResponse, ProtocolError> {
                if self.left == 0 {
                    return Ok(KeyboardInteractiveAuthResponse::Success);
                }
                self.left -= 1;
                Ok(info_request())
            }
        }

        let credentials = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        let (events, _rx) = remoter_proto::event_channel(8);
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: None,
            target: &target,
        };
        let mut state = Ladder::new(methods(&[MethodKind::KeyboardInteractive]), false);
        let report = drive_keyboard_interactive(
            &mut AsksThenAccepts { left: 3 },
            &context,
            &mut state,
            info_request(),
        )
        .await
        .unwrap()
        .expect("the ladder should report a success");
        assert_eq!(report.method, SshAuthMethod::KeyboardInteractive);
    }

    #[tokio::test]
    async fn a_stale_stored_passphrase_still_lets_the_user_open_the_key() {
        // The vault holds a passphrase that no longer opens the key — it was
        // rotated. `parse_private_key` cannot tell that from a corrupt file,
        // so it reports `AuthRejected`, and the prompt-and-retry arm used to
        // trigger only on `CredentialMissing`. The key became permanently
        // unusable: every attempt re-read it with the same stale value.
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pem = key
            .encrypt(&mut russh::keys::key::safe_rng(), "the new passphrase")
            .unwrap()
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        let credentials = Fixture {
            key: Some(pem.into_bytes()),
            passphrase: Some(b"the old passphrase".to_vec()),
            ..Fixture::empty()
        };
        let (events, mut rx) = remoter_proto::event_channel(8);
        let (tx, channel) = PromptChannel::new();
        let target = target();

        let reading = tokio::spawn({
            let events = events.clone();
            let channel = Arc::clone(&channel);
            async move {
                let context = AuthContext {
                    username: "ada",
                    credentials: &credentials,
                    allow_agent: false,
                    agent_filter: None,
                    events: &events,
                    prompts: Some(&channel),
                    target: &target,
                };
                obtain_private_key(&context).await
            }
        });

        // Bounded: without the re-prompt the read never returns at all, and a
        // test that hangs says nothing.
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("the user was never asked for a passphrase")
            .expect("the event stream closed");
        let SessionEvent::Prompt(prompt) = event else {
            panic!("expected a passphrase prompt");
        };
        assert!(matches!(prompt.kind, PromptKind::KeyPassphrase));
        assert!(!prompt.echo, "a passphrase must not be echoed");
        tx.send(remoter_proto::PromptAnswer::new(
            prompt.id,
            b"the new passphrase".to_vec(),
        ))
        .await
        .unwrap();

        let opened = reading.await.unwrap().unwrap();
        assert_eq!(
            opened.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[tokio::test]
    async fn a_key_that_is_simply_not_a_key_is_not_answered_with_a_passphrase_dialog() {
        // The other half: re-prompting on every parse failure would put a
        // passphrase dialog in front of a corrupt or truncated file, where no
        // answer can help.
        let credentials = Fixture {
            key: Some(
                b"-----BEGIN OPENSSH PRIVATE KEY-----
not a key
"
                .to_vec(),
            ),
            ..Fixture::empty()
        };
        let (events, mut rx) = remoter_proto::event_channel(8);
        let (_tx, channel) = PromptChannel::new();
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: Some(&channel),
            target: &target,
        };

        let error = obtain_private_key(&context).await.unwrap_err();
        assert!(
            matches!(
                error,
                ProtocolError::AuthRejected {
                    attempted: CredentialKind::PrivateKey
                }
            ),
            "expected the key to be rejected, got {error:?}"
        );
        assert!(rx.try_recv().is_err(), "nothing should have been asked");
    }

    #[tokio::test]
    async fn a_scripted_session_answers_one_hidden_prompt_and_refuses_the_rest() {
        let (events, _rx) = remoter_proto::event_channel(8);
        let credentials = Fixture {
            password: Some(b"hunter2".to_vec()),
            ..Fixture::empty()
        };
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: None,
            target: &target,
        };

        let single = answer_challenge(
            &context,
            "",
            "",
            vec![russh::client::Prompt {
                prompt: "Password: ".to_owned(),
                echo: false,
            }],
        )
        .await
        .unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].as_str(), "hunter2");

        // Two prompts, or an echoed one, mean something other than a password
        // is being asked for, and a machine has no business guessing.
        let two = answer_challenge(
            &context,
            "",
            "",
            vec![
                russh::client::Prompt {
                    prompt: "Password: ".to_owned(),
                    echo: false,
                },
                russh::client::Prompt {
                    prompt: "Code: ".to_owned(),
                    echo: false,
                },
            ],
        )
        .await;
        assert!(matches!(two, Err(ProtocolError::AuthCancelled)));

        let echoed = answer_challenge(
            &context,
            "",
            "",
            vec![russh::client::Prompt {
                prompt: "Which token? ".to_owned(),
                echo: true,
            }],
        )
        .await;
        assert!(matches!(echoed, Err(ProtocolError::AuthCancelled)));
    }

    #[tokio::test]
    async fn a_scripted_session_with_no_password_cannot_answer() {
        let (events, _rx) = remoter_proto::event_channel(8);
        let credentials = Fixture::empty();
        let target = target();
        let context = AuthContext {
            username: "ada",
            credentials: &credentials,
            allow_agent: false,
            agent_filter: None,
            events: &events,
            prompts: None,
            target: &target,
        };
        let outcome = answer_challenge(
            &context,
            "",
            "",
            vec![russh::client::Prompt {
                prompt: "Password: ".to_owned(),
                echo: false,
            }],
        )
        .await;
        assert!(matches!(outcome, Err(ProtocolError::AuthCancelled)));
    }
}
