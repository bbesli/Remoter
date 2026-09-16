//! Sessions against a real SSH server.
//!
//! These need one, so they are compiled only with the `integration-tests`
//! feature and are skipped entirely without it:
//!
//! ```text
//! scripts/dev-sshd.sh start
//! cargo test -p remoter-ipc --features integration-tests -- --test-threads=4
//! ```
//!
//! **The thread cap is not optional.** `sshd`'s default `MaxStartups` is
//! `10:30:100`: past ten *unauthenticated* connections at once it starts
//! dropping them, and a dropped connection arrives here as a session that
//! failed before it could ask anything — which reads exactly like a real
//! defect. The suite opens one connection per test and the default harness runs
//! every test at once, so it sits right on the limit. Raising `MaxStartups` in
//! `scripts/dev-sshd.sh` would fix it at the other end.
//!
//! The server is the user-mode `sshd` that `scripts/dev-sshd.sh` runs on
//! 127.0.0.1:2222 as the current account, with public key authentication only.
//! Its keys live under `/tmp/remoter-dev-sshd` and are throwaway; nothing here
//! may be pointed at a real host.
//!
//! They live in the library rather than in `tests/` because they drive the
//! command surface through the same fixtures the unit tests use, and
//! `test_support` is compiled for the library's own tests only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
#![allow(
    clippy::print_stderr,
    reason = "a live test that hangs has to be able to say where it got to, and a test binary \
              installs no tracing subscriber"
)]

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::mpsc;

use crate::commands::node_create_impl;
use crate::dto::{CreateNodeDto, CredentialInputDto};
use crate::error::IpcError;
use crate::session::{
    HostKeyDecisionDto, SessionMessageDto, SessionOpenedDto, host_key_decide_impl,
    session_close_impl, session_input_impl, session_list_impl, session_open_impl,
    session_resize_impl,
};
use crate::sftp::{
    EnqueueReportDto, SftpPaneDto, TransferRequestDto, TransferStateDto, TransferStatusDto,
    sftp_close_impl, sftp_delete_impl, sftp_enqueue_impl, sftp_list_impl, sftp_mkdir_impl,
    sftp_open_impl, sftp_preflight_impl, sftp_rename_impl, sftp_set_permissions_impl,
    sftp_stat_impl, sftp_transfer_cancel_impl, sftp_transfer_retry_impl, sftp_transfers_impl,
};
use crate::state::AppState;
use crate::test_support::{Scratch, open_vault};
use crate::tunnel::{TunnelSpecDto, tunnel_close_impl, tunnel_list_impl, tunnel_open_impl};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 2222;
const KEY: &str = "/tmp/remoter-dev-sshd/client_ed25519";
const ENCRYPTED_KEY: &str = "/tmp/remoter-dev-sshd/client_pass";
const KEY_PASSPHRASE: &str = "testpassphrase";

/// The account the development server accepts, which is whoever is running the
/// tests.
fn account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("root"))
}

/// Everything one test needs: an open vault holding a credential and a
/// connection pointing at the development server.
struct Fixture {
    _scratch: Scratch,
    /// Behind an `Arc` so the task that answers the host key prompt can hold
    /// it too. This crate forbids `unsafe`, so a borrow that outlives the frame
    /// is not an option — and should not be.
    state: Arc<AppState>,
    node_id: String,
}

fn fixture(key_path: &str, passphrase: Option<&str>) -> Fixture {
    fixture_for("ssh", key_path, passphrase)
}

fn fixture_for(protocol: &str, key_path: &str, passphrase: Option<&str>) -> Fixture {
    let scratch = Scratch::new();
    let Some(state) = open_vault(&scratch) else {
        panic!("the fixture vault could not be created");
    };

    let state = Arc::new(state);
    let credential = node_create_impl(
        &state,
        &mut CreateNodeDto {
            parent_id: None,
            kind: String::from("credential"),
            name: String::from("dev sshd key"),
            protocol: None,
            host: None,
            port: None,
            username: Some(account()),
            password: None,
            credential: Some(CredentialInputDto::PrivateKey {
                path: String::from(key_path),
                passphrase: passphrase.map(ToOwned::to_owned),
            }),
            credential_id: None,
            gateway: None,
        },
    )
    .expect("the credential node should be created");

    let connection = node_create_impl(
        &state,
        &mut CreateNodeDto {
            parent_id: None,
            kind: String::from("connection"),
            name: String::from("dev sshd"),
            protocol: Some(String::from(protocol)),
            host: Some(String::from(HOST)),
            port: Some(PORT),
            username: None,
            password: None,
            credential: None,
            credential_id: Some(credential.id.clone()),
            gateway: None,
        },
    )
    .expect("the connection node should be created");

    Fixture {
        _scratch: scratch,
        state,
        node_id: connection.id,
    }
}

/// What came out of one session's channel.
#[derive(Default)]
struct Collected {
    /// Terminal bytes, concatenated in arrival order. Raw payloads, never JSON.
    output: Vec<u8>,
    /// Control events, in arrival order.
    control: Vec<SessionMessageDto>,
}

/// A channel that records everything, and a handle to read it back.
fn recording_channel() -> (
    Channel<InvokeResponseBody>,
    Arc<Mutex<Collected>>,
    mpsc::UnboundedReceiver<SessionMessageDto>,
) {
    let collected = Arc::new(Mutex::new(Collected::default()));
    let (tx, rx) = mpsc::unbounded_channel();
    let sink = Arc::clone(&collected);
    let channel = Channel::new(move |body| {
        match body {
            InvokeResponseBody::Raw(bytes) => sink.lock().output.extend_from_slice(&bytes),
            InvokeResponseBody::Json(json) => {
                let message: SessionMessageDto =
                    serde_json::from_str(&json).expect("a control event should parse");
                sink.lock().control.push(message.clone());
                let _ = tx.send(message);
            }
        }
        Ok(())
    });
    (channel, collected, rx)
}

/// Opens a session, accepting the first-use host key when it is offered.
async fn open_accepting(
    state: &Arc<AppState>,
    node_id: &str,
) -> (Result<SessionOpenedDto, IpcError>, Arc<Mutex<Collected>>) {
    let (channel, collected, mut control) = recording_channel();
    let answering = tokio::spawn({
        let state = Arc::clone(state);
        async move {
            let mut session_id = None;
            while let Some(message) = control.recv().await {
                match message {
                    SessionMessageDto::Opening { session_id: id } => session_id = Some(id),
                    SessionMessageDto::HostKey(prompt) => {
                        let Some(id) = session_id else { continue };
                        assert_eq!(prompt.status, "unknown", "the dev server is a first use");
                        let _ = host_key_decide_impl(
                            &state,
                            id,
                            HostKeyDecisionDto::Accept {
                                prompt_id: prompt.prompt_id,
                            },
                        )
                        .await;
                    }
                    SessionMessageDto::Ready(_) => break,
                    _ => {}
                }
            }
        }
    });

    let opened = session_open_impl(state, node_id.to_owned(), channel).await;
    answering.abort();
    (opened, collected)
}

/// Waits until the collected output contains `needle`, or gives up.
async fn wait_for(collected: &Arc<Mutex<Collected>>, needle: &str) -> bool {
    for _ in 0..100 {
        {
            let seen = collected.lock();
            if String::from_utf8_lossy(&seen.output).contains(needle) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// ============================================================== the tests ==

/// The whole pipeline: connect, run a command, read its output, resize, close.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_opens_runs_a_command_resizes_and_closes() {
    let fixture = fixture(KEY, None);
    let (opened, collected) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the session did not open: {} — {}",
            error.code, error.message
        ),
    };

    assert_eq!(opened.target, format!("{HOST}:{PORT}"));
    assert_eq!(opened.username, account());
    assert_eq!(opened.protocol, "ssh");
    // The dev server offers public key only, and the vault holds the key.
    assert_eq!(opened.auth_method, "publickey");
    assert!(opened.via.is_empty(), "a direct connection has no hops");
    assert_eq!(opened.capabilities.kind, "terminal");
    assert!(opened.capabilities.resizable);

    // The session list agrees with what was just opened.
    let listed = session_list_impl(&fixture.state).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].session_id, opened.session_id);
    assert_eq!(listed[0].state, "running");
    assert!(!listed[0].frozen);

    // A command, and its output.
    session_input_impl(
        &fixture.state,
        opened.session_id,
        b"echo remoter-marker-4242\n".to_vec(),
    )
    .await
    .expect("input should reach the shell");
    assert!(
        wait_for(&collected, "remoter-marker-4242").await,
        "the command's output never arrived: {:?}",
        String::from_utf8_lossy(&collected.lock().output)
    );

    // A resize, proved by asking the remote PTY what size it is.
    session_resize_impl(&fixture.state, opened.session_id, 120, 40)
        .await
        .expect("a resize should reach the PTY");
    tokio::time::sleep(Duration::from_millis(200)).await;
    session_input_impl(&fixture.state, opened.session_id, b"stty size\n".to_vec())
        .await
        .expect("input should reach the shell");
    assert!(
        wait_for(&collected, "40 120").await,
        "the remote PTY did not report the new size: {:?}",
        String::from_utf8_lossy(&collected.lock().output)
    );

    // The close releases everything and deregisters.
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .expect("closing should succeed");
    assert!(session_list_impl(&fixture.state).unwrap().is_empty());

    // And the tab was told, over the same channel.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let control = &collected.lock().control;
    assert!(
        control
            .iter()
            .any(|m| matches!(m, SessionMessageDto::Closed { .. })),
        "no close event reached the channel: {control:?}"
    );
}

/// A key stored with a passphrase opens the same session: the passphrase is
/// lent alongside the key, never fetched separately.
#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_key_authenticates_with_its_stored_passphrase() {
    let fixture = fixture(ENCRYPTED_KEY, Some(KEY_PASSPHRASE));
    let (opened, _collected) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the session did not open: {} — {}",
            error.code, error.message
        ),
    };
    assert_eq!(opened.auth_method, "publickey");
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .expect("closing should succeed");
}

/// Declining a first-use host key refuses the session, and says which host and
/// which key type — never "connection failed".
#[tokio::test(flavor = "multi_thread")]
async fn declining_a_host_key_refuses_the_session() {
    let fixture = fixture(KEY, None);
    let (channel, _collected, mut control) = recording_channel();

    let answering = tokio::spawn({
        let state = Arc::clone(&fixture.state);
        async move {
            let mut session_id = None;
            while let Some(message) = control.recv().await {
                match message {
                    SessionMessageDto::Opening { session_id: id } => session_id = Some(id),
                    SessionMessageDto::HostKey(prompt) => {
                        let Some(id) = session_id else { continue };
                        let _ = host_key_decide_impl(
                            &state,
                            id,
                            HostKeyDecisionDto::Reject {
                                prompt_id: prompt.prompt_id,
                            },
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        }
    });

    let refused = session_open_impl(&fixture.state, fixture.node_id.clone(), channel).await;
    answering.abort();

    let Err(error) = refused else {
        panic!("a declined host key must not open a session");
    };
    assert_eq!(error.code, "session.host-key-rejected");
    assert!(error.message.contains(HOST), "{}", error.message);
    assert!(session_list_impl(&fixture.state).unwrap().is_empty());
}

/// An accepted host key is remembered **inside the vault**, so the second
/// connection asks nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_host_key_is_remembered_in_the_vault() {
    let fixture = fixture(KEY, None);
    let (first, _) = open_accepting(&fixture.state, &fixture.node_id).await;
    let first = first.expect("the first session should open");
    session_close_impl(&fixture.state, first.session_id)
        .await
        .expect("closing should succeed");

    // Second time: no prompt answerer at all. If the key were not remembered,
    // the handshake would have nobody to ask and would refuse.
    let (channel, collected, _control) = recording_channel();
    let second = session_open_impl(&fixture.state, fixture.node_id.clone(), channel).await;
    let second = match second {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the remembered host key was not used: {} — {}",
            error.code, error.message
        ),
    };
    assert!(
        !collected
            .lock()
            .control
            .iter()
            .any(|m| matches!(m, SessionMessageDto::HostKey(_))),
        "a remembered host key must not be asked about again"
    );
    session_close_impl(&fixture.state, second.session_id)
        .await
        .expect("closing should succeed");
}

/// A local forward carries real traffic: the SSH banner of the server it is
/// tunnelled through comes back down a plain TCP socket on this machine.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_forward_carries_traffic() {
    use tokio::io::AsyncReadExt as _;

    let fixture = fixture(KEY, None);
    // A tunnel has no window, so the key must already be trusted. Opening a
    // session once is how that happens.
    let (opened, _) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = opened.expect("the session should open");
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .expect("closing should succeed");

    let tunnel = tunnel_open_impl(
        &fixture.state,
        fixture.node_id.clone(),
        TunnelSpecDto::Local {
            bind_address: None,
            // Port 0: the operating system picks, and the status reports what
            // it picked, so the test cannot collide with anything.
            bind_port: 0,
            destination_host: String::from(HOST),
            destination_port: PORT,
            exposed: false,
        },
    )
    .await;
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(error) => panic!(
            "the tunnel did not open: {} — {}",
            error.code, error.message
        ),
    };
    assert_eq!(tunnel.direction, "local");
    assert_eq!(tunnel.exposure, "loopback");
    let listening = tunnel
        .listening
        .clone()
        .expect("a local forward binds here");

    let mut stream = tokio::net::TcpStream::connect(&listening)
        .await
        .expect("the forward should accept a connection");
    let mut banner = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut banner))
        .await
        .expect("the banner should arrive within ten seconds");
    read.expect("the banner should be readable");
    assert_eq!(&banner, b"SSH-", "the far end is not an SSH server");

    let listed = tunnel_list_impl(&fixture.state).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].running);
    assert!(listed[0].connections >= 1);

    tunnel_close_impl(&fixture.state, tunnel.tunnel_id).expect("closing should succeed");
    assert!(tunnel_list_impl(&fixture.state).unwrap().is_empty());
}

/// Locking the vault with `disconnect_all` closes every session.
#[tokio::test(flavor = "multi_thread")]
async fn locking_the_vault_disconnects_sessions_when_the_policy_says_so() {
    let fixture = fixture(KEY, None);

    {
        let mut guard = fixture.state.lock();
        let vault = guard.vault_mut().expect("the vault is open");
        let mut settings = vault.settings().expect("settings should read");
        settings.session_on_lock = remoter_vault::SessionOnLock::DisconnectAll;
        vault
            .set_settings(&settings)
            .expect("settings should write");
        vault.save().expect("the vault should save");
    }

    let (opened, _) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = opened.expect("the session should open");
    assert_eq!(session_list_impl(&fixture.state).unwrap().len(), 1);

    fixture.state.lock().close_vault();

    // The cancellation is fired synchronously; the tasks release themselves.
    for _ in 0..50 {
        if session_list_impl(&fixture.state).unwrap().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "session {} survived a lock that was supposed to disconnect it",
        opened.session_id
    );
}

/// The path that matters most. A key that contradicts the one in the vault is a
/// possible man-in-the-middle: it cannot be accepted the way a first use is, the
/// confirmation is checked, and only the deliberate replacement gets through.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_host_key_is_a_hard_failure_with_its_own_path() {
    use remoter_proto::{HostPort, KnownKey, TrustSource, TrustStore as _};

    let fixture = fixture(KEY, None);

    // Pin something that is emphatically not the server's key, under the
    // algorithm the server will offer.
    let store = crate::bridge::VaultTrustStore::new(fixture.state.inner_handle());
    let host = HostPort::new(HOST, PORT).unwrap();
    store
        .remember(
            &host,
            &KnownKey::new(
                "ssh-ed25519",
                b"not the server's key".to_vec(),
                1,
                TrustSource::Prompted,
            ),
        )
        .expect("the trust store should accept a pin");
    assert!(
        store.lookup(&host, "ssh-ed25519").is_some(),
        "the pin should be readable back"
    );

    // ── the prompt is the changed one, and `accept` is refused ─────────────
    // Nothing is asserted inside the answering task: an assertion that fires
    // there leaves the handshake suspended on a question nobody will answer,
    // and the test hangs instead of failing. Observations are recorded and
    // checked on the way out.
    let (channel, _collected, mut control) = recording_channel();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let answering = tokio::spawn({
        let state = Arc::clone(&fixture.state);
        let seen = Arc::clone(&seen);
        async move {
            let mut session_id = None;
            while let Some(message) = control.recv().await {
                match message {
                    SessionMessageDto::Opening { session_id: id } => session_id = Some(id),
                    SessionMessageDto::HostKey(prompt) => {
                        let Some(id) = session_id else { continue };
                        seen.lock().push(format!("status={}", prompt.status));
                        seen.lock().push(format!(
                            "previously_trusted={}",
                            prompt.previously_trusted.is_some()
                        ));
                        seen.lock()
                            .push(format!("confirmation_len={:?}", prompt.confirmation_len));

                        // The unknown-key path must not accept it.
                        let refused = host_key_decide_impl(
                            &state,
                            id,
                            HostKeyDecisionDto::Accept {
                                prompt_id: prompt.prompt_id,
                            },
                        )
                        .await;
                        seen.lock().push(format!(
                            "accept={}",
                            refused
                                .err()
                                .map_or_else(|| String::from("ACCEPTED"), |e| e.code)
                        ));

                        // The wrong confirmation leaves the stored key alone.
                        let _ = host_key_decide_impl(
                            &state,
                            id,
                            HostKeyDecisionDto::Replace {
                                prompt_id: prompt.prompt_id,
                                confirmation: String::from("wrongone"),
                            },
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        }
    });

    eprintln!("PHASE1 start");
    let refused = tokio::time::timeout(
        Duration::from_secs(45),
        session_open_impl(&fixture.state, fixture.node_id.clone(), channel),
    )
    .await;
    answering.abort();
    let observed = seen.lock().clone();
    let Ok(refused) = refused else {
        panic!("phase 1 never settled; the prompt said {observed:?}");
    };
    eprintln!("PHASE1 done: {observed:?}");
    assert!(
        observed.contains(&String::from("status=changed")),
        "the prompt was not the changed one: {observed:?}"
    );
    assert!(
        observed.contains(&String::from("previously_trusted=true")),
        "a changed-key dialog must show both keys: {observed:?}"
    );
    assert!(
        observed.contains(&String::from("confirmation_len=Some(8)")),
        "{observed:?}"
    );
    assert!(
        observed.contains(&String::from("accept=session.host-key-changed")),
        "accepting a changed key through the first-use path must be refused: {observed:?}"
    );
    let Err(error) = refused else {
        panic!("a mistyped confirmation must not replace a trusted host key");
    };
    assert_eq!(error.code, "session.confirmation-mismatch");

    // ── the deliberate replacement, with the fingerprint copied off screen ──
    let (channel, _collected, mut control) = recording_channel();
    let answering = tokio::spawn({
        let state = Arc::clone(&fixture.state);
        async move {
            let mut session_id = None;
            while let Some(message) = control.recv().await {
                match message {
                    SessionMessageDto::Opening { session_id: id } => session_id = Some(id),
                    SessionMessageDto::HostKey(prompt) => {
                        let Some(id) = session_id else { continue };
                        // The tail of the *offered* fingerprint, which is the
                        // value the dialog is showing.
                        eprintln!(
                            "PHASE2 prompt status={} id={}",
                            prompt.status, prompt.prompt_id
                        );
                        let body = prompt
                            .fingerprint
                            .strip_prefix("SHA256:")
                            .unwrap_or(&prompt.fingerprint);
                        let tail: String = body
                            .chars()
                            .skip(body.chars().count().saturating_sub(8))
                            .collect();
                        let _ = host_key_decide_impl(
                            &state,
                            id,
                            HostKeyDecisionDto::Replace {
                                prompt_id: prompt.prompt_id,
                                confirmation: tail,
                            },
                        )
                        .await;
                    }
                    SessionMessageDto::Ready(_) => break,
                    _ => {}
                }
            }
        }
    });
    eprintln!("PHASE2 start");
    let replaced = tokio::time::timeout(
        Duration::from_secs(45),
        session_open_impl(&fixture.state, fixture.node_id.clone(), channel),
    )
    .await;
    answering.abort();
    let Ok(replaced) = replaced else {
        panic!("phase 2 never settled");
    };
    eprintln!("PHASE2 done");
    let replaced = match replaced {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the deliberate replacement should have connected: {} — {}",
            error.code, error.message
        ),
    };
    session_close_impl(&fixture.state, replaced.session_id)
        .await
        .expect("closing should succeed");

    // And the vault now holds the server's real key: a third connection asks
    // nothing at all.
    eprintln!("PHASE3 start");
    let (channel, collected, mut control3) = recording_channel();
    let watcher = tokio::spawn(async move {
        while let Some(message) = control3.recv().await {
            eprintln!("PHASE3 event: {message:?}");
        }
    });
    let third = tokio::time::timeout(
        Duration::from_secs(45),
        session_open_impl(&fixture.state, fixture.node_id.clone(), channel),
    )
    .await
    .unwrap_or_else(|_| panic!("phase 3 never settled"))
    .expect("the replaced key should be trusted");
    watcher.abort();
    assert!(
        !collected
            .lock()
            .control
            .iter()
            .any(|m| matches!(m, SessionMessageDto::HostKey(_))),
        "the replacement was not recorded"
    );
    session_close_impl(&fixture.state, third.session_id)
        .await
        .expect("closing should succeed");
}

// ================================================================== SFTP ==
//
// The development server serves *this* account, so the "remote" filesystem is
// this machine's. That is what makes these assertions possible: a transfer can
// be checked byte for byte, and a name a hostile server would send can be
// created with `std::fs` and then read back over the wire.

/// Somewhere on the far side to work in, removed when the test ends.
fn remote_dir() -> (Scratch, String) {
    let scratch = Scratch::new();
    let path = scratch.join("tree");
    std::fs::create_dir_all(&path).expect("the remote working directory should be created");
    let text = path.to_str().expect("a UTF-8 path").to_owned();
    (scratch, text)
}

/// A session with a file pane already open on it.
async fn open_pane(fixture: &Fixture) -> (SessionOpenedDto, SftpPaneDto, Arc<Mutex<Collected>>) {
    let (opened, collected) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the session did not open: {} — {}",
            error.code, error.message
        ),
    };
    let pane = match sftp_open_impl(&fixture.state, opened.session_id).await {
        Ok(pane) => pane,
        Err(error) => panic!(
            "the file pane did not open: {} — {}",
            error.code, error.message
        ),
    };
    (opened, pane, collected)
}

/// The ids from an enqueue, with the report asserted complete.
///
/// A batch that skipped an entry or stopped at its own limit is not what any of
/// these tests asked for, and letting one through would turn a partial result
/// into a green tick — the exact defect the report exists to prevent.
fn report_ids(report: EnqueueReportDto) -> Vec<u64> {
    assert!(
        report.is_complete(),
        "the batch was queued only in part: skipped {:?}, limit reached {}",
        report.skipped,
        report.limit_reached
    );
    report.transfer_ids
}

/// Waits for a transfer to reach a terminal state.
async fn await_transfer(state: &Arc<AppState>, pane: u64, id: u64) -> TransferStatusDto {
    for _ in 0..600 {
        let listed = sftp_transfers_impl(state, pane).expect("the queue should be readable");
        let found = listed
            .into_iter()
            .find(|status| status.transfer_id == id)
            .expect("the transfer should be in the queue");
        if !matches!(
            found.state,
            TransferStateDto::Queued | TransferStateDto::Running { .. }
        ) {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("transfer {id} never finished");
}

fn download(remote: &str, local: &str, resume: bool) -> TransferRequestDto {
    TransferRequestDto {
        direction: String::from("download"),
        remote: remote.to_owned(),
        local: Some(local.to_owned()),
        local_directory: None,
        resume,
    }
}

/// Browsing: the whole set of things a file manager does to a directory, on
/// the connection a shell is already using.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_pane_browses_on_the_connection_the_shell_is_already_using() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_scratch, root) = remote_dir();

    assert!(!pane.home.is_empty(), "the server named no home directory");
    assert_eq!(pane.session_id, opened.session_id);

    // No second session: the pane is a channel on the one that is open.
    assert_eq!(session_list_impl(&fixture.state).unwrap().len(), 1);

    let made = format!("{root}/reports");
    sftp_mkdir_impl(&fixture.state, pane.pane_id, made.clone())
        .await
        .expect("the directory should be created");

    let listed = sftp_list_impl(&fixture.state, pane.pane_id, root.clone())
        .await
        .expect("the directory should list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "reports");
    assert_eq!(listed[0].display_name, "reports");
    assert_eq!(listed[0].kind, "directory");
    assert!(listed[0].risks.clean());
    // The ownership and permission columns a file manager shows.
    assert!(
        listed[0]
            .mode
            .as_deref()
            .unwrap_or_default()
            .starts_with('d')
    );
    assert!(listed[0].uid.is_some(), "no owner was reported");
    assert!(listed[0].gid.is_some(), "no group was reported");

    sftp_set_permissions_impl(&fixture.state, pane.pane_id, made.clone(), 0o700)
        .await
        .expect("the mode should be settable");
    let stat = sftp_stat_impl(&fixture.state, pane.pane_id, made.clone())
        .await
        .expect("the directory should stat");
    assert_eq!(stat.mode.as_deref(), Some("drwx------"));
    assert_eq!(stat.permissions.map(|mode| mode & 0o777), Some(0o700));

    let moved = format!("{root}/archive");
    sftp_rename_impl(&fixture.state, pane.pane_id, made, moved.clone())
        .await
        .expect("the rename should succeed");
    assert!(std::path::Path::new(&moved).is_dir());

    let report = sftp_delete_impl(&fixture.state, pane.pane_id, moved.clone(), false)
        .await
        .expect("an empty directory should be removable");
    assert!(report.complete);
    assert_eq!(report.directories_removed, 1);
    assert!(!std::path::Path::new(&moved).exists());

    sftp_close_impl(&fixture.state, pane.pane_id)
        .await
        .expect("the pane should close");
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .expect("closing should succeed");
}

/// An `sftp` connection opens a session of its own: same pipeline, same host
/// key check, same credential — a file tab rather than a shell.
#[tokio::test(flavor = "multi_thread")]
async fn an_sftp_connection_opens_a_file_session_of_its_own() {
    let fixture = fixture_for("sftp", KEY, None);
    let (opened, _collected) = open_accepting(&fixture.state, &fixture.node_id).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => panic!(
            "the SFTP session did not open: {} — {}",
            error.code, error.message
        ),
    };

    assert_eq!(opened.protocol, "sftp");
    assert_eq!(opened.auth_method, "publickey");
    assert_eq!(opened.capabilities.kind, "file_transfer");
    assert!(!opened.capabilities.resizable, "a file pane has no grid");
    assert_eq!(opened.capabilities.clipboard, "none");
    assert!(opened.capabilities.file_transfer);

    // It is an ordinary session: in the list, against the cap, closed by the
    // same supervisor as everything else.
    let listed = session_list_impl(&fixture.state).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].protocol, "sftp");
    assert_eq!(listed[0].state, "running");
    assert_eq!(listed[0].capabilities.kind, "file_transfer");

    let pane = sftp_open_impl(&fixture.state, opened.session_id)
        .await
        .expect("a file session should open a pane");
    let (_scratch, root) = remote_dir();
    assert!(
        sftp_list_impl(&fixture.state, pane.pane_id, root)
            .await
            .expect("the pane should browse")
            .is_empty()
    );

    // Closing the session takes its panes with it: a pane on a connection that
    // has gone has nothing to browse.
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .expect("closing should succeed");
    assert_eq!(
        sftp_list_impl(&fixture.state, pane.pane_id, String::from("/"))
            .await
            .err()
            .map(|e| e.code),
        Some(String::from("sftp.no-such-pane"))
    );
}

/// A transfer in both directions, byte for byte, with the progress a 2 GB
/// transfer would be indistinguishable from a hang without.
#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_moves_every_byte_and_reports_progress_as_it_goes() {
    let fixture = fixture(KEY, None);
    let (opened, pane, collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    // Big enough to cross `PROGRESS_INTERVAL_BYTES` several times; the bytes
    // vary so a transfer that repeated a block would not go unnoticed.
    let source: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let local_source = local_scratch.join("payload.bin");
    std::fs::write(&local_source, &source).expect("the local file should be written");
    let remote_target = format!("{root}/payload.bin");

    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![TransferRequestDto {
                direction: String::from("upload"),
                remote: remote_target.clone(),
                local: Some(local_source.display().to_string()),
                local_directory: None,
                resume: false,
            }],
        )
        .await
        .expect("the upload should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    match status.state {
        TransferStateDto::Completed { bytes } => assert_eq!(bytes, source.len() as u64),
        other => panic!("the upload did not complete: {other:?}"),
    }
    assert_eq!(
        std::fs::read(&remote_target).expect("the uploaded file should exist"),
        source,
        "a transfer may not drop or reorder a byte"
    );

    // Progress arrived on the session's own channel, which is what a bar is
    // driven by; `sftp_transfers` is for reconciliation, not for polling.
    let progress: Vec<_> = collected
        .lock()
        .control
        .iter()
        .filter_map(|message| match message {
            SessionMessageDto::Progress(update) => Some(update.clone()),
            _ => None,
        })
        .collect();
    assert!(
        progress.len() >= 2,
        "a 1.5 MB transfer reported no progress: {progress:?}"
    );
    assert!(progress.iter().all(|p| p.operation == "sftp.upload"));
    assert_eq!(progress.last().map(|p| p.done), Some(source.len() as u64));

    // And back the other way, into a folder — where the file name comes from
    // `local_name_for` rather than from anything the server said.
    let into = local_scratch.join("incoming");
    std::fs::create_dir_all(&into).expect("the download folder should be created");
    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![TransferRequestDto {
                direction: String::from("download"),
                remote: remote_target,
                local: None,
                local_directory: Some(into.display().to_string()),
                resume: false,
            }],
        )
        .await
        .expect("the download should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    assert!(
        matches!(status.state, TransferStateDto::Completed { .. }),
        "the download did not complete: {:?}",
        status.state
    );
    assert_eq!(status.local, into.join("payload.bin").display().to_string());
    assert_eq!(
        std::fs::read(into.join("payload.bin")).expect("the downloaded file should exist"),
        source
    );

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// Resume, which is the reason a queue is worth having — and the refusal,
/// which is why it is worth saying out loud when it does not happen.
#[tokio::test(flavor = "multi_thread")]
async fn a_resume_continues_a_partial_file_and_says_so_when_it_will_not() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    let source: Vec<u8> = (0..900_000u32).map(|i| (i % 253) as u8).collect();
    let remote_path = format!("{root}/archive.bin");
    std::fs::write(&remote_path, &source).expect("the remote file should be written");

    // A download that was interrupted: the first 400 000 bytes are on disk.
    let partial = local_scratch.join("archive.bin");
    std::fs::write(&partial, &source[..400_000]).expect("the partial file should be written");

    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![download(&remote_path, &partial.display().to_string(), true)],
        )
        .await
        .expect("the resume should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    assert!(
        matches!(status.state, TransferStateDto::Completed { .. }),
        "the resumed download did not complete: {:?}",
        status.state
    );
    let start = status
        .start
        .expect("a started transfer reports what it decided");
    assert_eq!(start.resume_from, 400_000, "the resume started over");
    assert!(!start.resume_declined);
    assert!(start.note.is_none());
    assert_eq!(
        std::fs::read(&partial).expect("the resumed file should exist"),
        source,
        "a resume must not corrupt the file it continues"
    );

    // Now the file is already whole. `resume_offset` refuses anything that is
    // not strictly shorter, and the refusal is a sentence the user can act on
    // rather than a bar that silently restarts.
    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![download(&remote_path, &partial.display().to_string(), true)],
        )
        .await
        .expect("the second attempt should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    let start = status
        .start
        .expect("a started transfer reports what it decided");
    assert_eq!(start.resume_from, 0);
    assert!(start.resume_declined, "the refusal was not reported");
    let note = start.note.expect("a refused resume must say why");
    assert!(note.contains("not shorter"), "{note}");
    // And it started over rather than appending, so the file is still right.
    assert_eq!(std::fs::read(&partial).unwrap(), source);

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// A queue of several, each stopped on its own — and a retry, which queues a
/// new transfer rather than resurrecting a finished one.
#[tokio::test(flavor = "multi_thread")]
async fn transfers_are_cancellable_one_at_a_time_and_retryable_afterwards() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    // Large enough that it cannot finish before the cancellation lands: at
    // 32 KiB a round trip this is more than a thousand of them, and the first
    // progress report arrives after the first 512 KiB.
    let source: Vec<u8> = (0..48u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let remote_path = format!("{root}/big.bin");
    std::fs::write(&remote_path, &source).expect("the remote file should be written");

    let destination = local_scratch.join("big.bin");
    let queued_destination = local_scratch.join("never.bin");
    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![
                download(&remote_path, &destination.display().to_string(), false),
                download(
                    &remote_path,
                    &queued_destination.display().to_string(),
                    false,
                ),
            ],
        )
        .await
        .expect("both should queue"),
    );
    assert_eq!(ids.len(), 2);

    // Stop the second one while it is still waiting for a slot: it must never
    // start at all.
    sftp_transfer_cancel_impl(&fixture.state, pane.pane_id, ids[1])
        .expect("a queued transfer should be cancellable");

    // Stop the first one while it is genuinely moving bytes.
    let mut moving = false;
    for _ in 0..2_000 {
        let listed = sftp_transfers_impl(&fixture.state, pane.pane_id).unwrap();
        let first = listed
            .iter()
            .find(|status| status.transfer_id == ids[0])
            .expect("the transfer should be in the queue");
        if let TransferStateDto::Running { done, .. } = first.state
            && done > 0
        {
            moving = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(moving, "the download never reported moving a byte");
    sftp_transfer_cancel_impl(&fixture.state, pane.pane_id, ids[0])
        .expect("a running transfer should be cancellable");

    let stopped = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    assert!(
        matches!(stopped.state, TransferStateDto::Cancelled),
        "the running transfer was not stopped: {:?}",
        stopped.state
    );
    let written = std::fs::metadata(&destination)
        .map(|meta| meta.len())
        .unwrap_or(0);
    assert!(
        written < source.len() as u64,
        "a cancelled transfer finished anyway"
    );
    // What was written stays on disk: its length is what makes a resume
    // possible.
    assert!(written > 0, "the partial file was thrown away");
    assert!(
        !queued_destination.exists(),
        "a transfer cancelled while queued still ran"
    );

    // A retry is a new transfer. The old row stays exactly as it was, so the
    // history of what happened stays readable.
    let retried = sftp_transfer_retry_impl(&fixture.state, pane.pane_id, ids[1])
        .expect("a cancelled transfer should be retryable");
    assert!(!ids.contains(&retried));
    let finished = await_transfer(&fixture.state, pane.pane_id, retried).await;
    assert!(
        matches!(finished.state, TransferStateDto::Completed { .. }),
        "the retry did not complete: {:?}",
        finished.state
    );
    assert_eq!(std::fs::read(&queued_destination).unwrap(), source);
    assert!(matches!(
        sftp_transfers_impl(&fixture.state, pane.pane_id)
            .unwrap()
            .into_iter()
            .find(|status| status.transfer_id == ids[1])
            .map(|status| status.state),
        Some(TransferStateDto::Cancelled)
    ));

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// The names a hostile server sends, over a real wire.
///
/// Every one of these is a legal POSIX file name, which is the point: the pane
/// has to show them without being fooled by them, and still address the exact
/// file the user clicked on.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_file_name_is_shown_safely_and_still_addresses_the_right_file() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    // A right-to-left override, which renders this `.exe` as `annexe.txt`.
    let trojan = "annex\u{202E}txt.exe";
    // A control byte, which truncates a log line and moves a terminal cursor.
    let noisy = "notes\u{0007}\u{001B}[2K.txt";
    std::fs::write(format!("{root}/{trojan}"), b"payload").expect("the trojan name should write");
    std::fs::write(format!("{root}/{noisy}"), b"noise").expect("the noisy name should write");

    let listed = sftp_list_impl(&fixture.state, pane.pane_id, root.clone())
        .await
        .expect("the directory should list");
    assert_eq!(listed.len(), 2);

    let shown = listed
        .iter()
        .find(|entry| entry.name == trojan)
        .expect("the raw name must survive the round trip exactly");
    assert!(shown.risks.bidi, "the override was not noticed");
    assert!(!shown.risks.clean());
    assert!(
        !shown.display_name.contains('\u{202E}'),
        "the override reached the display: {:?}",
        shown.display_name
    );
    assert!(!shown.display_path.contains('\u{202E}'));

    let noisy_row = listed
        .iter()
        .find(|entry| entry.name == noisy)
        .expect("the raw name must survive the round trip exactly");
    assert!(noisy_row.risks.control);
    assert!(!noisy_row.display_name.contains('\u{001B}'));
    assert!(!noisy_row.display_name.contains('\u{0007}'));

    // The raw name still addresses the file, which is the other half of the
    // rule: the display form is never used to reach anything.
    assert_eq!(
        sftp_stat_impl(&fixture.state, pane.pane_id, shown.path.clone())
            .await
            .expect("the file the user clicked on should stat")
            .size,
        Some(7)
    );

    // Downloading it into a folder puts it inside that folder and nowhere
    // else, under the name the server chose.
    let into = local_scratch.join("incoming");
    std::fs::create_dir_all(&into).expect("the folder should be created");
    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![TransferRequestDto {
                direction: String::from("download"),
                remote: shown.path.clone(),
                local: None,
                local_directory: Some(into.display().to_string()),
                resume: false,
            }],
        )
        .await
        .expect("the download should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    assert!(
        matches!(status.state, TransferStateDto::Completed { .. }),
        "{:?}",
        status.state
    );
    assert_eq!(status.local, into.join(trojan).display().to_string());
    assert!(
        status.local.starts_with(&into.display().to_string()),
        "the download escaped the folder it was pointed at: {}",
        status.local
    );
    assert!(!status.remote_display.contains('\u{202E}'));

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// Removing a tree: what was removed, what was not, and what was deliberately
/// not followed.
#[tokio::test(flavor = "multi_thread")]
async fn a_recursive_delete_reports_what_it_removed_and_does_not_follow_links() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (scratch, root) = remote_dir();

    // Something outside the tree, which a walk that followed the link below
    // would destroy.
    let outside = scratch.join("outside.txt");
    std::fs::write(&outside, b"untouched").expect("the outside file should write");

    std::fs::create_dir_all(format!("{root}/sub/deep")).expect("the tree should be created");
    std::fs::write(format!("{root}/a.txt"), b"a").unwrap();
    std::fs::write(format!("{root}/sub/b.txt"), b"b").unwrap();
    std::fs::write(format!("{root}/sub/deep/c.txt"), b"c").unwrap();
    std::os::unix::fs::symlink(&outside, format!("{root}/link")).expect("the link should be made");

    // Not recursive first: §6.11 says a directory has to be empty, and the
    // message has to say that rather than reporting a permission problem.
    let refused = sftp_delete_impl(&fixture.state, pane.pane_id, root.clone(), false).await;
    assert_eq!(
        refused.err().map(|error| error.code),
        Some(String::from("sftp.directory-not-empty"))
    );

    let report = sftp_delete_impl(&fixture.state, pane.pane_id, root.clone(), true)
        .await
        .expect("the tree should be removable");
    assert!(report.complete, "left behind: {:?}", report.failures);
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    // Three files and the link, which is unlinked rather than followed.
    assert_eq!(report.files_removed, 4);
    assert_eq!(report.directories_removed, 3);
    assert!(!std::path::Path::new(&root).exists());
    assert!(
        outside.exists(),
        "the walk followed a symbolic link out of the tree"
    );

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// A queue of several, all on the one SFTP session.
///
/// `TransferQueue::concurrency` is what makes a queue of small files usable on
/// a high-latency link, and it means two transfers share one subsystem channel
/// — the case where a request identifier mixed up between them would show as a
/// file with somebody else's bytes in it.
#[tokio::test(flavor = "multi_thread")]
async fn a_queue_of_several_transfers_arrives_intact() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    // Distinguishable contents: a file that received another transfer's bytes
    // would not compare equal.
    let payloads: Vec<Vec<u8>> = (0..6u32)
        .map(|n| (0..300_000u32).map(|i| ((i + n * 7) % 251) as u8).collect())
        .collect();

    let mut requests = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let source = local_scratch.join(&format!("send-{index}.bin"));
        std::fs::write(&source, payload).expect("the local file should be written");
        requests.push(TransferRequestDto {
            direction: String::from("upload"),
            remote: format!("{root}/sent-{index}.bin"),
            local: Some(source.display().to_string()),
            local_directory: None,
            resume: false,
        });
    }

    let ids = report_ids(
        sftp_enqueue_impl(&fixture.state, pane.pane_id, requests)
            .await
            .expect("the batch should queue"),
    );
    assert_eq!(ids.len(), payloads.len());
    for id in &ids {
        let status = await_transfer(&fixture.state, pane.pane_id, *id).await;
        assert!(
            matches!(status.state, TransferStateDto::Completed { .. }),
            "transfer {id} did not complete: {:?}",
            status.state
        );
    }

    for (index, payload) in payloads.iter().enumerate() {
        assert_eq!(
            std::fs::read(format!("{root}/sent-{index}.bin")).expect("the file should exist"),
            *payload,
            "file {index} did not arrive intact"
        );
    }

    sftp_close_impl(&fixture.state, pane.pane_id).await.unwrap();
    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// Closing a pane stops what it was doing, and does not wait for a 48 MB
/// download to finish to do it.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_pane_stops_a_transfer_that_is_in_flight() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    let source: Vec<u8> = (0..48u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let remote_path = format!("{root}/big.bin");
    std::fs::write(&remote_path, &source).expect("the remote file should be written");
    let destination = local_scratch.join("big.bin");

    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![download(
                &remote_path,
                &destination.display().to_string(),
                false,
            )],
        )
        .await
        .expect("the download should queue"),
    );

    let mut moving = false;
    for _ in 0..2_000 {
        let listed = sftp_transfers_impl(&fixture.state, pane.pane_id).unwrap();
        if let Some(TransferStateDto::Running { done, .. }) =
            listed.first().map(|status| status.state.clone())
            && done > 0
        {
            moving = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(moving, "the download never reported moving a byte");

    // "The pane is closed" and "nothing is still writing to disk" are the same
    // moment, and it arrives well inside the grace period rather than when the
    // file happens to finish.
    let closing = std::time::Instant::now();
    sftp_close_impl(&fixture.state, pane.pane_id)
        .await
        .expect("the pane should close");
    let took = closing.elapsed();
    assert!(
        took < Duration::from_secs(5),
        "closing the pane waited for the transfer: {took:?}"
    );

    let written = std::fs::metadata(&destination)
        .map(|meta| meta.len())
        .unwrap_or(0);
    assert!(
        written < source.len() as u64,
        "the transfer ran on after its pane was closed"
    );
    assert_eq!(
        sftp_transfers_impl(&fixture.state, pane.pane_id)
            .err()
            .map(|error| error.code),
        Some(String::from("sftp.no-such-pane"))
    );
    assert_eq!(ids.len(), 1);

    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// A whole directory, down and back up again, against a real server.
///
/// The commonest job anyone opens a file manager for, and the one the pane
/// could not do at all: `sftp_enqueue` was synchronous, so it had nowhere to
/// put the walk. This asserts the *effect* — every file present on the other
/// side with its bytes intact, and the nesting preserved — rather than that a
/// walk was called.
#[tokio::test(flavor = "multi_thread")]
async fn a_folder_is_transferred_whole_in_both_directions() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    // A tree with a subdirectory, because a flat folder would pass with a walk
    // that never descends.
    let source_root = format!("{root}/project");
    std::fs::create_dir_all(format!("{source_root}/config/nested"))
        .expect("the remote tree should be created");
    let payloads: [(&str, &[u8]); 3] = [
        ("readme.txt", b"the top level"),
        ("config/app.toml", b"one level down"),
        ("config/nested/deep.bin", b"\x00\x01\x02two levels down"),
    ];
    for (relative, bytes) in payloads {
        std::fs::write(format!("{source_root}/{relative}"), bytes)
            .expect("a remote file should be written");
    }

    // --- down ---
    let into = local_scratch.join("landing");
    std::fs::create_dir_all(&into).expect("the landing folder should be created");
    let down = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![TransferRequestDto {
                direction: String::from("download"),
                remote: source_root.clone(),
                local: None,
                local_directory: Some(into.display().to_string()),
                resume: false,
            }],
        )
        .await
        .expect("the folder download should queue"),
    );
    assert_eq!(
        down.len(),
        payloads.len(),
        "one transfer per file under the folder"
    );
    for id in &down {
        let status = await_transfer(&fixture.state, pane.pane_id, *id).await;
        assert!(
            matches!(status.state, TransferStateDto::Completed { .. }),
            "transfer {id} did not complete: {:?}",
            status.state
        );
    }
    for (relative, bytes) in payloads {
        let landed = into.join("project").join(relative);
        assert_eq!(
            std::fs::read(&landed).unwrap_or_else(|_| panic!("{} should exist", landed.display())),
            bytes,
            "{relative} did not arrive byte for byte"
        );
    }

    // --- and back up, into a folder of its own on the far side ---
    let up_root = format!("{root}/returned");
    std::fs::create_dir_all(&up_root).expect("the destination should exist");
    let up = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![TransferRequestDto {
                direction: String::from("upload"),
                remote: format!("{up_root}/project"),
                local: Some(into.join("project").display().to_string()),
                local_directory: None,
                resume: false,
            }],
        )
        .await
        .expect("the folder upload should queue"),
    );
    assert_eq!(up.len(), payloads.len());
    for id in &up {
        let status = await_transfer(&fixture.state, pane.pane_id, *id).await;
        assert!(
            matches!(status.state, TransferStateDto::Completed { .. }),
            "transfer {id} did not complete: {:?}",
            status.state
        );
    }
    for (relative, bytes) in payloads {
        assert_eq!(
            std::fs::read(format!("{up_root}/project/{relative}"))
                .unwrap_or_else(|_| panic!("{relative} should have been sent")),
            bytes
        );
    }

    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// A folder walk reports what it refused rather than dropping it.
///
/// A symbolic link inside a transferred folder is not followed — descending one
/// is how a link to `/` becomes a copy of the filesystem — and the caller is
/// told, because a folder transfer that silently arrived four files short is
/// how a backup turns out to be incomplete six months later.
#[tokio::test(flavor = "multi_thread")]
async fn a_folder_transfer_reports_what_it_would_not_take() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    let source_root = format!("{root}/mixed");
    std::fs::create_dir_all(&source_root).expect("the remote tree should be created");
    std::fs::write(format!("{source_root}/real.txt"), b"a real file")
        .expect("the file should be written");
    std::os::unix::fs::symlink("/etc/passwd", format!("{source_root}/link"))
        .expect("the link should be created");

    let into = local_scratch.join("landing");
    std::fs::create_dir_all(&into).expect("the landing folder should be created");
    let report = sftp_enqueue_impl(
        &fixture.state,
        pane.pane_id,
        vec![TransferRequestDto {
            direction: String::from("download"),
            remote: source_root.clone(),
            local: None,
            local_directory: Some(into.display().to_string()),
            resume: false,
        }],
    )
    .await
    .expect("the folder download should queue");

    assert_eq!(report.transfer_ids.len(), 1, "only the real file is queued");
    assert!(
        !report.is_complete(),
        "a walk that left the link behind is not complete"
    );
    assert_eq!(report.skipped.len(), 1);
    let skipped = &report.skipped[0];
    assert!(skipped.path.ends_with("/link"), "{}", skipped.path);
    assert!(!skipped.code.is_empty());
    assert!(!skipped.message.is_empty());

    let status = await_transfer(&fixture.state, pane.pane_id, report.transfer_ids[0]).await;
    assert!(matches!(status.state, TransferStateDto::Completed { .. }));
    assert!(
        !into.join("mixed").join("link").exists(),
        "the link was followed after all"
    );

    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// Preflight answers "is something already there?" without queueing anything.
///
/// Three answers, and the third is the one that matters: "nothing is there",
/// "this is what is there", and "nobody could look". Drawing the third as the
/// first is how a file manager quietly replaces a file it said was absent.
#[tokio::test(flavor = "multi_thread")]
async fn preflight_says_what_a_transfer_would_replace_and_queues_nothing() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    let occupied = format!("{root}/occupied.bin");
    std::fs::write(&occupied, b"0123456789").expect("the remote file should be written");
    let free = format!("{root}/free.bin");
    let local_source = local_scratch.join("send.bin");
    std::fs::write(&local_source, b"payload").expect("the local file should be written");
    let folder = format!("{root}/a-folder");
    std::fs::create_dir_all(&folder).expect("the folder should be created");

    let answers = sftp_preflight_impl(
        &fixture.state,
        pane.pane_id,
        vec![
            TransferRequestDto {
                direction: String::from("upload"),
                remote: occupied.clone(),
                local: Some(local_source.display().to_string()),
                local_directory: None,
                resume: false,
            },
            TransferRequestDto {
                direction: String::from("upload"),
                remote: free.clone(),
                local: Some(local_source.display().to_string()),
                local_directory: None,
                resume: false,
            },
            TransferRequestDto {
                direction: String::from("upload"),
                remote: folder.clone(),
                local: Some(local_source.display().to_string()),
                local_directory: None,
                resume: false,
            },
        ],
    )
    .await
    .expect("the preflight should answer");

    assert_eq!(answers.len(), 3);
    assert!(answers[0].exists, "something is at the occupied path");
    assert_eq!(answers[0].size, Some(10));
    assert!(!answers[0].directory);
    assert!(answers[0].problem.is_none());

    assert!(!answers[1].exists, "nothing is at the free path");
    assert!(
        answers[1].problem.is_none(),
        "an absent file is an answer, not a failure"
    );

    assert!(answers[2].exists);
    assert!(answers[2].directory, "a transfer cannot replace a folder");

    // Nothing was queued, and nothing on either side was touched.
    assert!(
        sftp_transfers_impl(&fixture.state, pane.pane_id)
            .expect("the queue should be readable")
            .is_empty(),
        "preflight queued a transfer"
    );
    assert_eq!(
        std::fs::read(&occupied).expect("the occupied file should be intact"),
        b"0123456789"
    );
    assert!(
        !std::path::Path::new(&free).exists(),
        "preflight created the destination"
    );

    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}

/// A transfer carries the clock the queue needs to say how fast and how long.
///
/// Without these the queue could show a byte count and a percentage and nothing
/// else, and had to measure a rate from its own successive readings — a timer
/// and a piece of derived state where a subtraction would do.
#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_is_timed_from_queued_to_finished() {
    let fixture = fixture(KEY, None);
    let (opened, pane, _collected) = open_pane(&fixture).await;
    let (_remote_scratch, root) = remote_dir();
    let local_scratch = Scratch::new();

    let source: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    let remote_path = format!("{root}/timed.bin");
    std::fs::write(&remote_path, &source).expect("the remote file should be written");
    let destination = local_scratch.join("timed.bin");

    let ids = report_ids(
        sftp_enqueue_impl(
            &fixture.state,
            pane.pane_id,
            vec![download(
                &remote_path,
                &destination.display().to_string(),
                false,
            )],
        )
        .await
        .expect("the download should queue"),
    );
    let status = await_transfer(&fixture.state, pane.pane_id, ids[0]).await;
    assert!(matches!(status.state, TransferStateDto::Completed { .. }));

    assert!(status.queued_at_ms > 0, "a transfer is queued at some time");
    let started = status.started_at_ms.expect("it started");
    let finished = status.finished_at_ms.expect("it finished");
    assert!(started >= status.queued_at_ms, "it started after it queued");
    assert!(finished >= started, "it finished after it started");
    let moved = status
        .progress_at_ms
        .expect("a two-megabyte file reports progress at least once");
    assert!(moved >= started && moved <= finished);

    session_close_impl(&fixture.state, opened.session_id)
        .await
        .unwrap();
}
