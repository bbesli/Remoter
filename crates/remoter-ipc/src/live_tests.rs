//! Sessions against a real SSH server.
//!
//! These need one, so they are compiled only with the `integration-tests`
//! feature and are skipped entirely without it:
//!
//! ```text
//! scripts/dev-sshd.sh start
//! cargo test -p remoter-ipc --features integration-tests
//! ```
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
        },
    )
    .expect("the credential node should be created");

    let connection = node_create_impl(
        &state,
        &mut CreateNodeDto {
            parent_id: None,
            kind: String::from("connection"),
            name: String::from("dev sshd"),
            protocol: Some(String::from("ssh")),
            host: Some(String::from(HOST)),
            port: Some(PORT),
            username: None,
            password: None,
            credential: None,
            credential_id: Some(credential.id.clone()),
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
