//! Integration tests against a real RDP host.
//!
//! There is no substitute for one, and the unit tests in this crate say so:
//! they drive the connection sequence against scripted PDUs, which proves the
//! ordering and the parsing and proves nothing at all about whether a Windows
//! Server accepts what this client sends. This file is the other half, and it
//! needs a machine.
//!
//! ```text
//! # A Windows host, or the xrdp fixture from
//! # docs/development/getting-started.md.
//! export REMOTER_RDP_HOST=ts-01.corp.example
//! export REMOTER_RDP_USER='CORP\ada'
//! export REMOTER_RDP_PASSWORD=...
//! cargo test -p remoter-proto-rdp --features integration-tests -- --nocapture
//! ```
//!
//! `REMOTER_RDP_PORT` defaults to 3389 and `REMOTER_RDP_NLA` to `true`; set the
//! latter to `false` for a host that has Network Level Authentication turned
//! off, which is what `xrdp` is out of the box.
//!
//! **The password is read from the environment and nowhere else.** It is never
//! written to a file in this repository, and `.gitignore` would not save
//! anyone who did.
//!
//! **These were written but not run.** No Windows host and no `xrdp` container
//! was reachable from the environment this crate was implemented in, so
//! everything below is untested against a server. That is the single largest
//! gap in this crate and it is stated here rather than left to be discovered.

#![cfg(feature = "integration-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test code, per the workspace convention"
)]

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use remoter_proto::{
    CredentialKind, CredentialProvider, HostPort, KeyBorrow, KnownKey, PromptAnswer, PromptKind,
    ProtocolError, Session as _, SessionEvent, TcpTransport, Transport, TrustStore, event_channel,
};
use remoter_proto_rdp::{
    CertificateChecker, ConnectionConfig, PromptChannel, RdpSession, connect, static_channels,
};
use tokio_util::sync::CancellationToken;

/// Where the tests connect. `None` skips them, which is what happens on a
/// machine with no host to point at.
fn target() -> Option<HostPort> {
    let host = std::env::var("REMOTER_RDP_HOST").ok()?;
    let port = std::env::var("REMOTER_RDP_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3389);
    HostPort::new(host, port).ok()
}

fn nla() -> bool {
    std::env::var("REMOTER_RDP_NLA").is_ok_and(|value| value != "false")
        || std::env::var("REMOTER_RDP_NLA").is_err()
}

/// The account, as the vault would supply it.
struct Account;

impl CredentialProvider for Account {
    fn username(&self) -> Option<&str> {
        // Leaked once, for the life of the process. A test binary is not a
        // place to be clever about lifetimes.
        std::env::var("REMOTER_RDP_USER")
            .ok()
            .map(|value| &*Box::leak(value.into_boxed_str()))
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::Password
    }

    fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        match std::env::var("REMOTER_RDP_PASSWORD") {
            Ok(password) => {
                f(password.as_bytes());
                true
            }
            Err(_) => false,
        }
    }

    fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
        false
    }
}

/// An in-memory trust store. A real run pins into it once and matches on the
/// second connection, which is the property being checked.
#[derive(Default)]
struct Memory {
    keys: Mutex<Vec<(String, String, KnownKey)>>,
}

impl TrustStore for Memory {
    fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
        self.keys
            .lock()
            .iter()
            .find(|(h, a, _)| h == &host.canonical() && a == algorithm)
            .map(|(_, _, key)| key.clone())
    }

    fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
        let mut keys = self.keys.lock();
        keys.retain(|(h, a, _)| !(h == &host.canonical() && a == &key.algorithm));
        keys.push((host.canonical(), key.algorithm.clone(), key.clone()));
        Ok(())
    }
}

/// Connects, answering the certificate prompt with `answer`.
async fn establish(
    trust: Arc<Memory>,
    answer: &'static str,
) -> Result<(RdpSession, HostPort), ProtocolError> {
    let target = target().expect("REMOTER_RDP_HOST must be set");
    let (sender, prompts) = PromptChannel::new();
    let (events, mut rx) = event_channel(64);

    // The interface's half of the prompt round trip: forward every question's
    // answer back into the channel.
    let pump = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                SessionEvent::Prompt(prompt) => {
                    println!("prompt: {:?}", prompt.kind);
                    let reply = match &prompt.kind {
                        // A changed certificate is answered with nothing: this
                        // harness must never be the thing that replaces a pin.
                        PromptKind::HostKey {
                            previously_trusted: Some(_),
                            ..
                        } => PromptAnswer::cancelled(prompt.id),
                        _ => PromptAnswer::new(prompt.id, answer.as_bytes().to_vec()),
                    };
                    let _ = sender.send(reply).await;
                }
                SessionEvent::Warning(warning) => println!("warning: {warning:?}"),
                SessionEvent::Closed(reason) => {
                    println!("closed: {reason:?}");
                    break;
                }
                _ => {}
            }
        }
    });

    let transport: Box<dyn Transport> = Box::new(
        TcpTransport::connect(&target, Duration::from_secs(10))
            .await
            .expect("the host did not answer"),
    );

    let mut config = ConnectionConfig::new(target.clone(), "");
    let account = Account;
    if let Some(user) = account.username() {
        let (username, domain) = remoter_proto_rdp::split_account(user);
        config.username = username;
        config.domain = domain.unwrap_or_default();
    }
    config.network_level_authentication = nla();

    let checker = CertificateChecker::new(
        target.clone(),
        trust as Arc<dyn TrustStore>,
        events.clone(),
        Some(Arc::clone(&prompts)),
    );

    let connected = connect(
        transport,
        &config,
        &account,
        &checker,
        static_channels(),
        &events,
        Some(prompts),
        &CancellationToken::new(),
    )
    .await?;

    pump.abort();
    let session = RdpSession::attach(
        connected,
        events,
        remoter_proto::SessionId::from_raw(1),
        target.clone(),
    )?;
    Ok((session, target))
}

#[tokio::test]
async fn a_real_host_reaches_the_active_state_and_reports_its_desktop_size() {
    let Some(_) = target() else {
        println!("REMOTER_RDP_HOST is not set; skipping");
        return;
    };

    let trust = Arc::new(Memory::default());
    let (session, target) = establish(Arc::clone(&trust), "yes")
        .await
        .expect("the connection sequence did not complete");

    let desktop = session.desktop();
    println!("{target} is {}x{}", desktop.width, desktop.height);
    assert!(desktop.width >= 200 && desktop.height >= 200);

    // The certificate was pinned, which is what makes the second connection
    // silent.
    assert_eq!(trust.keys.lock().len(), 1);

    Box::new(session)
        .disconnect()
        .await
        .expect("the clean disconnect failed");
}

#[tokio::test]
async fn a_second_connection_matches_the_pinned_certificate_and_asks_nothing() {
    let Some(_) = target() else {
        println!("REMOTER_RDP_HOST is not set; skipping");
        return;
    };

    let trust = Arc::new(Memory::default());
    let (first, _) = establish(Arc::clone(&trust), "yes").await.unwrap();
    Box::new(first).disconnect().await.ok();

    // "no" would decline any prompt, so a second connection that succeeds
    // proves none was raised.
    let (second, _) = establish(Arc::clone(&trust), "no")
        .await
        .expect("the pinned certificate was not recognised on the second connection");
    Box::new(second).disconnect().await.ok();
    assert_eq!(trust.keys.lock().len(), 1);
}

#[tokio::test]
async fn the_wrong_password_is_reported_as_a_rejection_and_not_as_a_handshake_failure() {
    let Some(target) = target() else {
        println!("REMOTER_RDP_HOST is not set; skipping");
        return;
    };
    if !nla() {
        println!("without NLA the password is checked by the remote login screen; skipping");
        return;
    }

    /// The right account, the wrong password.
    struct WrongPassword;
    impl CredentialProvider for WrongPassword {
        fn username(&self) -> Option<&str> {
            Account.username()
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::Password
        }
        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            f(b"not-the-password-either");
            true
        }
        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    // The certificate has to be pinned first, or the failure under test is
    // hidden behind a prompt.
    let trust = Arc::new(Memory::default());
    let (session, _) = establish(Arc::clone(&trust), "yes").await.unwrap();
    Box::new(session).disconnect().await.ok();

    let (events, _rx) = event_channel(16);
    let transport: Box<dyn Transport> = Box::new(
        TcpTransport::connect(&target, Duration::from_secs(10))
            .await
            .unwrap(),
    );
    let checker = CertificateChecker::new(
        target.clone(),
        trust as Arc<dyn TrustStore>,
        events.clone(),
        None,
    );
    let mut config = ConnectionConfig::new(target.clone(), "");
    if let Some(user) = Account.username() {
        let (username, domain) = remoter_proto_rdp::split_account(user);
        config.username = username;
        config.domain = domain.unwrap_or_default();
    }

    let error = connect(
        transport,
        &config,
        &WrongPassword,
        &checker,
        static_channels(),
        &events,
        None,
        &CancellationToken::new(),
    )
    .await
    .expect_err("the wrong password connected");

    // The distinction the whole error taxonomy exists for: a user who cannot
    // tell "wrong password" from "certificate not trusted" cannot fix either.
    assert!(
        matches!(error, ProtocolError::AuthRejected { .. }),
        "expected an authentication rejection, got {error:?}"
    );
    assert_eq!(error.stage(), remoter_proto::Stage::Authenticate);
    assert!(
        !error.is_retryable(),
        "retrying a rejected password is a lockout"
    );
}

#[tokio::test]
async fn a_cancelled_attempt_against_a_real_host_frees_its_socket() {
    let Some(target) = target() else {
        println!("REMOTER_RDP_HOST is not set; skipping");
        return;
    };

    let (events, _rx) = event_channel(16);
    let trust = Arc::new(Memory::default());
    let checker = CertificateChecker::new(
        target.clone(),
        trust as Arc<dyn TrustStore>,
        events.clone(),
        None,
    );
    let transport: Box<dyn Transport> = Box::new(
        TcpTransport::connect(&target, Duration::from_secs(10))
            .await
            .unwrap(),
    );

    let cancel = CancellationToken::new();
    cancel.cancel();
    let error = connect(
        transport,
        &ConnectionConfig::new(target, "ada"),
        &Account,
        &checker,
        static_channels(),
        &events,
        None,
        &cancel,
    )
    .await
    .expect_err("a cancelled attempt connected");
    assert!(matches!(error, ProtocolError::Cancelled));
}
