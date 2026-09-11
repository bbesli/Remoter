//! The platform SSH agent.
//!
//! **This is the most secure way to authenticate and the interface says so.**
//! The private key never enters this process's address space: Remoter sends
//! the agent a challenge, the agent signs it, and what comes back is a
//! signature. A memory-disclosure bug in a protocol decoder — the thing
//! ADR-0003 is written about — cannot yield a key that was never here.
//!
//! Discovery, in order:
//!
//! 1. `SSH_AUTH_SOCK`. On Unix a socket path; on Windows recent OpenSSH builds
//!    put a named pipe path there, so it is honoured on both.
//! 2. Windows only: `\\.\pipe\openssh-ssh-agent`, the fixed path the Windows
//!    OpenSSH agent service listens on.
//! 3. Windows only: Pageant, which is what a PuTTY user will have running.
//!
//! A missing agent is not an error at this layer — it is one method of several
//! not being available, and the ladder in [`crate::auth`] moves on.

use std::fmt;

use remoter_proto::ProtocolError;
use russh::keys::agent::client::{AgentClient, AgentStream};

/// An agent client whose stream type has been erased, so that a Unix socket
/// and a Windows pipe are the same value to everything downstream.
pub type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

/// Where an agent was found.
///
/// Carried for the interface, which tells the user *which* agent is signing —
/// "the key never leaves your agent" is only reassuring if it names one.
#[derive(Clone, PartialEq, Eq)]
pub enum AgentEndpoint {
    /// A socket or pipe path taken from `SSH_AUTH_SOCK`.
    AuthSock(String),
    /// The Windows OpenSSH agent's well-known named pipe.
    WindowsOpenSsh,
    /// Pageant, PuTTY's agent.
    Pageant,
}

impl AgentEndpoint {
    /// A stable ASCII name for the message catalogue.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AuthSock(_) => "ssh-auth-sock",
            Self::WindowsOpenSsh => "windows-openssh",
            Self::Pageant => "pageant",
        }
    }
}

impl fmt::Display for AgentEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthSock(path) => write!(f, "{path}"),
            Self::WindowsOpenSsh => f.write_str("\\\\.\\pipe\\openssh-ssh-agent"),
            Self::Pageant => f.write_str("Pageant"),
        }
    }
}

impl fmt::Debug for AgentEndpoint {
    /// A path, not a secret — but written out by hand so that a future variant
    /// carrying something else does not become printable by default.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentEndpoint({}, {self})", self.kind())
    }
}

/// The Windows OpenSSH agent's fixed pipe name.
#[cfg(windows)]
const WINDOWS_OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// The endpoints worth trying, most preferred first.
///
/// Reads `SSH_AUTH_SOCK` and touches no socket. The decision itself lives in
/// [`candidates_from`] so that the ordering is testable without an agent
/// running and without writing to the process environment.
#[must_use]
pub fn candidates() -> Vec<AgentEndpoint> {
    candidates_from(std::env::var("SSH_AUTH_SOCK").ok().as_deref())
}

/// The endpoints implied by an `SSH_AUTH_SOCK` value.
///
/// `SSH_AUTH_SOCK` wins because the user set it deliberately — often to point
/// at a forwarded agent, a hardware token's agent, or `gpg-agent`. An empty
/// value is treated as unset: an exported-but-empty variable is common inside
/// containers, and honouring it would cost a doomed connect on every session.
#[must_use]
pub fn candidates_from(auth_sock: Option<&str>) -> Vec<AgentEndpoint> {
    let mut out = Vec::new();
    if let Some(path) = auth_sock.map(str::trim).filter(|path| !path.is_empty()) {
        out.push(AgentEndpoint::AuthSock(path.to_owned()));
    }
    #[cfg(windows)]
    {
        out.push(AgentEndpoint::WindowsOpenSsh);
        out.push(AgentEndpoint::Pageant);
    }
    out
}

/// Connects to the first agent that answers.
///
/// # Errors
///
/// [`ProtocolError::AgentUnavailable`] when no agent could be reached. The
/// underlying reason is logged and not returned: an agent socket path is a
/// filesystem detail the user cannot act on, and the actionable message is
/// "no agent is running".
pub async fn connect() -> Result<(Agent, AgentEndpoint), ProtocolError> {
    for endpoint in candidates() {
        match open(&endpoint).await {
            Ok(agent) => {
                tracing::debug!(agent = endpoint.kind(), "connected to an SSH agent");
                return Ok((agent, endpoint));
            }
            Err(error) => {
                tracing::debug!(
                    agent = endpoint.kind(),
                    error = %error,
                    "an SSH agent did not answer"
                );
            }
        }
    }
    Err(ProtocolError::AgentUnavailable)
}

#[cfg(unix)]
async fn open(endpoint: &AgentEndpoint) -> Result<Agent, russh::keys::Error> {
    match endpoint {
        AgentEndpoint::AuthSock(path) => Ok(AgentClient::connect_uds(path).await?.dynamic()),
        // Neither exists on Unix; `candidates` never produces them there.
        AgentEndpoint::WindowsOpenSsh | AgentEndpoint::Pageant => {
            Err(russh::keys::Error::BadAuthSock)
        }
    }
}

#[cfg(windows)]
async fn open(endpoint: &AgentEndpoint) -> Result<Agent, russh::keys::Error> {
    match endpoint {
        // On Windows `SSH_AUTH_SOCK` holds a named pipe path, not a socket.
        AgentEndpoint::AuthSock(path) => Ok(AgentClient::connect_named_pipe(path.as_str())
            .await?
            .dynamic()),
        AgentEndpoint::WindowsOpenSsh => Ok(AgentClient::connect_named_pipe(WINDOWS_OPENSSH_PIPE)
            .await?
            .dynamic()),
        AgentEndpoint::Pageant => Ok(AgentClient::connect_pageant().await?.dynamic()),
    }
}

#[cfg(not(any(unix, windows)))]
async fn open(_endpoint: &AgentEndpoint) -> Result<Agent, russh::keys::Error> {
    Err(russh::keys::Error::BadAuthSock)
}

/// Keeps only the identities whose comment contains `filter`.
///
/// A substring match on the comment, because that is what an agent exposes and
/// what a user recognises: `id_ed25519_work`, `cardno:12345678`. An empty or
/// absent filter keeps everything.
#[must_use]
pub fn filter_identities(
    identities: Vec<russh::keys::agent::AgentIdentity>,
    filter: Option<&str>,
) -> Vec<russh::keys::agent::AgentIdentity> {
    let Some(filter) = filter.map(str::trim).filter(|f| !f.is_empty()) else {
        return identities;
    };
    let needle = filter.to_lowercase();
    identities
        .into_iter()
        .filter(|identity| identity.comment().to_lowercase().contains(&needle))
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
    use russh::keys::agent::AgentIdentity;
    use russh::keys::ssh_key::{Algorithm, PrivateKey, PublicKey};

    fn identity(comment: &str) -> AgentIdentity {
        let key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let public: PublicKey = key.public_key().clone();
        AgentIdentity::PublicKey {
            key: public,
            comment: comment.to_owned(),
        }
    }

    #[test]
    fn a_filter_matches_a_comment_substring_case_insensitively() {
        let identities = vec![
            identity("ada@work"),
            identity("ada@home"),
            identity("cardno:12345678"),
        ];
        let kept = filter_identities(identities, Some("WORK"));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].comment(), "ada@work");
    }

    #[test]
    fn no_filter_keeps_every_identity() {
        let identities = vec![identity("a"), identity("b")];
        assert_eq!(filter_identities(identities, None).len(), 2);
        let identities = vec![identity("a"), identity("b")];
        assert_eq!(filter_identities(identities, Some("   ")).len(), 2);
    }

    #[test]
    fn a_filter_that_matches_nothing_keeps_nothing() {
        // Better than silently falling back to every key: a user who named a
        // specific identity does not want a different one used.
        let identities = vec![identity("ada@work")];
        assert!(filter_identities(identities, Some("bob")).is_empty());
    }

    #[test]
    fn the_endpoint_renders_without_surprises() {
        let sock = AgentEndpoint::AuthSock("/run/user/1000/keyring/ssh".to_owned());
        assert_eq!(sock.to_string(), "/run/user/1000/keyring/ssh");
        assert_eq!(sock.kind(), "ssh-auth-sock");
        assert!(format!("{sock:?}").contains("ssh-auth-sock"));
        assert_eq!(AgentEndpoint::Pageant.kind(), "pageant");
        assert_eq!(AgentEndpoint::WindowsOpenSsh.kind(), "windows-openssh");
    }

    #[test]
    fn an_empty_auth_sock_is_not_a_candidate() {
        // An exported-but-empty `SSH_AUTH_SOCK` is common in containers, and
        // treating it as an endpoint costs a doomed connect per session.
        for empty in [None, Some(""), Some("   ")] {
            assert!(
                !candidates_from(empty)
                    .iter()
                    .any(|endpoint| matches!(endpoint, AgentEndpoint::AuthSock(_))),
                "{empty:?} produced a socket endpoint"
            );
        }
    }

    #[test]
    fn a_set_auth_sock_is_tried_first() {
        let found = candidates_from(Some(" /run/user/1000/keyring/ssh "));
        assert_eq!(
            found.first(),
            Some(&AgentEndpoint::AuthSock(
                "/run/user/1000/keyring/ssh".to_owned()
            ))
        );
    }
}
