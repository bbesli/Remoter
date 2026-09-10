//! Integration tests against the Docker fixtures.
//!
//! These need real servers, so they are compiled only with the
//! `integration-tests` feature and are skipped entirely without it:
//!
//! ```text
//! docker compose -f tests/fixtures/compose.yaml up -d
//! cargo test -p remoter-proto-ssh --features integration-tests
//! ```
//!
//! The fixtures and their credentials are listed in
//! `docs/development/getting-started.md`: OpenSSH on 2222, a second SSH host on
//! 2224 for jump chains, and `testuser` / `testpass` on both. Those credentials
//! are deliberately trivial and belong to a throwaway container network; they
//! must never be pointed at a real host.
//!
//! **These were written but not run.** No Docker daemon was available in the
//! environment this crate was implemented in.

#![cfg(feature = "integration-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use remoter_proto::{
    CredentialKind, CredentialProvider, EventSink, HostPort, KeyBorrow, KnownKey, ProtocolError,
    Session as _, SessionEvent, TcpTransport, Transport, TrustSource, TrustStore, event_channel,
};
use remoter_proto_ssh::{
    SftpBrowser, SshConnection, SshConnectionConfig, TerminalSettings, TransferDirection,
    TransferQueue, TransferRequest,
};
use tokio_util::sync::CancellationToken;

const SSH_PORT: u16 = 2222;
const SECOND_SSH_PORT: u16 = 2224;
const USER: &str = "testuser";
const PASSWORD: &str = "testpass";

/// A password provider, as the vault would supply one.
struct Fixture;

impl CredentialProvider for Fixture {
    fn username(&self) -> Option<&str> {
        Some(USER)
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::Password
    }

    fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        f(PASSWORD.as_bytes());
        true
    }

    fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
        false
    }
}

/// A trust store that remembers in memory and never auto-accepts.
#[derive(Default)]
struct Memory {
    keys: Mutex<Vec<(String, KnownKey)>>,
}

impl Memory {
    /// Pre-trusts whatever the fixture offers, by connecting once and reading
    /// the prompt. Used where the test is not about the host key check.
    fn trust_everything(&self, host: &HostPort, key: &KnownKey) {
        self.keys.lock().push((host.to_string(), key.clone()));
    }
}

impl TrustStore for Memory {
    fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
        self.keys
            .lock()
            .iter()
            .find(|(stored, key)| stored == &host.to_string() && key.algorithm == algorithm)
            .map(|(_, key)| key.clone())
    }

    fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
        self.keys.lock().push((host.to_string(), key.clone()));
        Ok(())
    }
}

fn target(port: u16) -> HostPort {
    HostPort::new("127.0.0.1", port).unwrap()
}

async fn transport(port: u16) -> Box<dyn Transport> {
    Box::new(
        TcpTransport::connect(&target(port), Duration::from_secs(5))
            .await
            .expect("the fixture container is not running"),
    )
}

/// Answers every prompt with `yes`, which accepts a first-use host key.
fn accepting_prompts(
    mut events: tokio::sync::mpsc::Receiver<SessionEvent>,
    answers: tokio::sync::mpsc::Sender<remoter_proto::PromptAnswer>,
) {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let SessionEvent::Prompt(prompt) = event {
                let _ = answers
                    .send(remoter_proto::PromptAnswer::new(prompt.id, b"yes".to_vec()))
                    .await;
            }
        }
    });
}

async fn connect(port: u16) -> (Arc<SshConnection>, EventSink) {
    let (events, rx) = event_channel(64);
    let (tx, prompts) = remoter_proto_ssh::PromptChannel::new();
    accepting_prompts(rx, tx);

    let config = SshConnectionConfig::new(target(port), USER);
    let connection = SshConnection::establish(
        transport(port).await,
        &config,
        &Fixture,
        Arc::new(Memory::default()),
        events.clone(),
        Some(prompts),
        &CancellationToken::new(),
    )
    .await
    .expect("the fixture refused the connection");

    (Arc::new(connection), events)
}

#[tokio::test]
async fn a_password_login_reaches_a_shell() {
    let (connection, events) = connect(SSH_PORT).await;
    assert_eq!(connection.username(), USER);

    let session =
        remoter_proto_ssh::SshSession::open_shell(connection, &TerminalSettings::default(), events)
            .await
            .expect("the fixture refused a shell");
    Box::new(session).disconnect().await.unwrap();
}

#[tokio::test]
async fn an_exec_returns_the_command_output() {
    let (connection, events) = connect(SSH_PORT).await;
    let session = remoter_proto_ssh::SshSession::open_exec(
        connection,
        "echo remoter-integration",
        &TerminalSettings::default(),
        events,
    )
    .await
    .expect("the fixture refused an exec");
    Box::new(session).disconnect().await.unwrap();
}

#[tokio::test]
async fn a_changed_host_key_is_a_hard_failure() {
    // The check that matters most: a key that contradicts the stored one must
    // not be acceptable through the first-use path.
    let store = Memory::default();
    store.trust_everything(
        &target(SSH_PORT),
        &KnownKey::new("ssh-ed25519", vec![0xde; 51], 0, TrustSource::Prompted),
    );

    let (events, rx) = event_channel(64);
    let (tx, prompts) = remoter_proto_ssh::PromptChannel::new();
    accepting_prompts(rx, tx);

    let config = SshConnectionConfig::new(target(SSH_PORT), USER);
    let error = SshConnection::establish(
        transport(SSH_PORT).await,
        &config,
        &Fixture,
        Arc::new(store),
        events,
        Some(prompts),
        &CancellationToken::new(),
    )
    .await
    .expect_err("a changed host key must not connect");

    // `yes` is what accepts a *new* key; a changed one needs the confirmation
    // word, so answering `yes` must leave the session refused.
    assert!(
        matches!(
            error,
            ProtocolError::ConfirmationMismatch | ProtocolError::HostKeyChanged { .. }
        ),
        "got {error:?}"
    );
}

#[tokio::test]
async fn sftp_reuses_the_connection_the_shell_is_on() {
    let (connection, events) = connect(SSH_PORT).await;
    let session = remoter_proto_ssh::SshSession::open_shell(
        Arc::clone(&connection),
        &TerminalSettings::default(),
        events,
    )
    .await
    .unwrap();

    // No second authentication: the browser is opened on the same connection.
    let browser = SftpBrowser::open(Arc::clone(&connection))
        .await
        .expect("the fixture refused the SFTP subsystem");
    let home = browser.canonicalize(".").await.unwrap();
    // The cancellation token is not optional here: a hostile server can
    // return an unbounded directory listing, so `list` takes a token and a
    // cap. See the review finding that added it.
    let entries = browser
        .list(&home, &tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert!(entries.iter().any(|entry| entry.name == "."
        || entry.kind == remoter_proto_ssh::EntryKind::Directory
        || entry.kind == remoter_proto_ssh::EntryKind::File));

    Box::new(session).disconnect().await.unwrap();
}

#[tokio::test]
async fn a_transfer_round_trips_a_file() {
    let (connection, events) = connect(SSH_PORT).await;
    let browser = SftpBrowser::open(connection).await.unwrap();
    let home = browser.canonicalize(".").await.unwrap();
    let remote = format!("{home}/remoter-integration.bin");

    let local = std::env::temp_dir().join("remoter-integration.bin");
    let payload = vec![0x5a_u8; 3 * 1024 * 1024];
    tokio::fs::write(&local, &payload).await.unwrap();

    let queue = TransferQueue::new(2);
    queue.enqueue(TransferRequest {
        direction: TransferDirection::Upload,
        remote: remote.clone(),
        local: local.clone(),
        resume: false,
    });
    remoter_proto_ssh::run_queue(&browser, &queue, Some(&events), &CancellationToken::new()).await;
    assert!(
        queue.list().iter().all(|status| matches!(
            status.state,
            remoter_proto_ssh::TransferState::Completed { .. }
        )),
        "{:?}",
        queue.list()
    );

    let back = std::env::temp_dir().join("remoter-integration-back.bin");
    let queue = TransferQueue::new(1);
    queue.enqueue(TransferRequest {
        direction: TransferDirection::Download,
        remote: remote.clone(),
        local: back.clone(),
        resume: false,
    });
    remoter_proto_ssh::run_queue(&browser, &queue, Some(&events), &CancellationToken::new()).await;

    assert_eq!(tokio::fs::read(&back).await.unwrap(), payload);
    browser.remove_file(&remote).await.unwrap();
    let _ = tokio::fs::remove_file(local).await;
    let _ = tokio::fs::remove_file(back).await;
}

#[tokio::test]
async fn a_local_forward_carries_a_connection_to_the_second_host() {
    use remoter_proto_ssh::{ForwardBind, ForwardSpec};

    let (connection, _events) = connect(SSH_PORT).await;
    let cancel = CancellationToken::new();
    let handle = remoter_proto_ssh::start_local(
        Arc::clone(&connection),
        ForwardSpec::Local {
            // Port 0: the operating system chooses, so a busy port on the
            // developer's machine cannot make this test flap.
            bind: ForwardBind::loopback(0).unwrap(),
            destination: HostPort::new("127.0.0.1", 22).unwrap(),
        },
        cancel.clone(),
    )
    .await
    .expect("the forward did not bind");

    let listening = handle.status().listening.expect("no bound address");
    let mut stream = tokio::net::TcpStream::connect(listening).await.unwrap();

    // The far end announces itself first (RFC 4253 §4.2), which is proof the
    // bytes reached a real SSH server through the tunnel.
    use tokio::io::AsyncReadExt as _;
    let mut banner = [0u8; 4];
    stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-");

    handle.stop();
    cancel.cancel();
}

#[tokio::test]
async fn a_jump_chain_reaches_the_second_host_through_the_first() {
    use remoter_core::{NodeId, ProtocolId};
    use remoter_proto::{ChainBuilder, GatewayChainPlan, HopConfig, TcpDialer};

    let (events, rx) = event_channel(64);
    let (tx, prompts) = remoter_proto_ssh::PromptChannel::new();
    accepting_prompts(rx, tx);

    let dialer = remoter_proto_ssh::SshHopDialer::new(events, CancellationToken::new())
        .with_prompts(prompts);
    let entry = TcpDialer;
    let builder = ChainBuilder::new(&entry, &dialer);

    let plan = GatewayChainPlan::new(
        target(SECOND_SSH_PORT),
        None,
        vec![HopConfig {
            node: NodeId::new(),
            label: "bastion-1".to_owned(),
            endpoint: target(SSH_PORT),
            protocol: ProtocolId::new("ssh").unwrap(),
            credentials: Arc::new(Fixture),
            trust: Arc::new(Memory::default()),
            timeout: Duration::from_secs(10),
        }],
    )
    .unwrap();

    let transport = builder
        .build(&plan, &CancellationToken::new())
        .await
        .expect("the chain did not build");
    assert_eq!(transport.peer().hop_count(), 1);
}
