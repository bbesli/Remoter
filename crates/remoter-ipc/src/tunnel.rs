//! Port forwarding, without a shell.
//!
//! `docs/features/tunneling.md`: "A tunnel can be defined independently of any
//! session — a tunnel-only connection that establishes forwards and holds them
//! open without a shell." So a tunnel is opened against a *node*, not a
//! session: it runs the same stages 1 to 6 as a session, then starts a forward
//! on the connection instead of a PTY.
//!
//! Two consequences worth stating.
//!
//! **A tunnel has no tab, so it cannot ask anything.** Without a prompt channel
//! an unknown host key is refused rather than accepted — a machine that cannot
//! ask a human has not obtained consent — and the refusal says to open a
//! session to that node first, which is where the fingerprint can be reviewed.
//!
//! **The default bind is loopback.** Binding beyond it exposes the forward to
//! the local network, so it is an explicit per-tunnel opt-in
//! (`docs/security/transport-security.md`), and the exposure is reported back
//! so the interface can carry the warning badge the specification asks for.

use std::sync::Arc;

use remoter_proto::{ChainBuilder, ProtocolError, TcpDialer, TrustStore, event_channel};
use remoter_proto_ssh::{
    AlgorithmPolicy, DEFAULT_HANDSHAKE_TIMEOUT, ForwardBind, ForwardHandle, ForwardSpec,
    SshConnection, SshConnectionConfig, SshHopDialer, start_dynamic, start_local, start_remote,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio_util::sync::CancellationToken;

use crate::bridge::VaultTrustStore;
use crate::error::IpcError;
use crate::session::{ipc_error, plan_for_tunnel};
use crate::state::AppState;

/// A forward the interface asked for.
///
/// `bindAddress` is `null` or absent for the loopback default. Supplying a
/// non-loopback address requires `exposed: true` as well: a warning shown on a
/// listener that is already open has arrived too late, so the setting is
/// checked before the socket is bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "direction",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TunnelSpecDto {
    /// `-L`: a port here reaches a host as the remote sees it.
    Local {
        bind_address: Option<String>,
        bind_port: u16,
        destination_host: String,
        destination_port: u16,
        #[serde(default)]
        exposed: bool,
    },
    /// `-R`: a port on the remote reaches a host as we see it.
    Remote {
        bind_address: Option<String>,
        bind_port: u16,
        destination_host: String,
        destination_port: u16,
        #[serde(default)]
        exposed: bool,
    },
    /// `-D`: a SOCKS5 proxy here, exiting through the remote.
    Dynamic {
        bind_address: Option<String>,
        bind_port: u16,
        #[serde(default)]
        exposed: bool,
    },
}

/// One running forward, as the session panel shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDto {
    pub tunnel_id: u64,
    pub node_id: String,
    /// The connection's name, as the user called it.
    pub name: String,
    /// `"local" | "remote" | "dynamic"`.
    pub direction: String,
    /// Where it listens, as configured.
    pub bind: String,
    /// Where it sends traffic. `null` for a SOCKS5 proxy, which decides per
    /// connection.
    pub destination: Option<String>,
    /// `"loopback" | "network"`. `"network"` carries the warning badge.
    pub exposure: String,
    /// The socket actually bound, once it is. `null` for a remote forward,
    /// whose listener is on the server.
    pub listening: Option<String>,
    /// The port the *server* bound, for a remote forward that asked for 0.
    pub remote_port: Option<u16>,
    /// Connections open right now.
    pub active: u64,
    /// Connections accepted since it started.
    pub connections: u64,
    /// Bytes carried in both directions.
    pub bytes: u64,
    pub running: bool,
}

/// One registered tunnel.
pub(crate) struct TunnelEntry {
    handle: ForwardHandle,
    /// Kept so the SSH session outlives the forward running on it: dropping the
    /// connection closes every channel it carries.
    _connection: Arc<SshConnection>,
    /// Cancels the forward *and* the drain task that keeps its event stream
    /// from filling.
    cancel: CancellationToken,
    node: String,
    name: String,
}

impl TunnelEntry {
    /// Stops the forward and everything opened for it.
    pub(crate) fn stop(&self) {
        self.handle.stop();
        self.cancel.cancel();
    }

    fn to_dto(&self, id: u64) -> TunnelDto {
        let status = self.handle.status();
        TunnelDto {
            tunnel_id: id,
            node_id: self.node.clone(),
            name: self.name.clone(),
            direction: status.direction.as_str().to_owned(),
            bind: status.bind,
            destination: status.destination,
            exposure: status.exposure.as_str().to_owned(),
            listening: status.listening.map(|addr| addr.to_string()),
            remote_port: self.handle.remote_port(),
            active: status.active,
            connections: status.connections,
            bytes: status.bytes,
            running: status.running,
        }
    }
}

impl std::fmt::Debug for TunnelEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelEntry")
            .field("node", &self.node)
            .field("name", &self.name)
            .finish()
    }
}

/// Opens a forward on a connection of its own.
#[tauri::command]
pub(crate) async fn tunnel_open(
    state: State<'_, AppState>,
    node_id: String,
    spec: TunnelSpecDto,
) -> Result<TunnelDto, IpcError> {
    tunnel_open_impl(&state, node_id, spec).await
}

pub(crate) async fn tunnel_open_impl(
    state: &AppState,
    node_id: String,
    spec: TunnelSpecDto,
) -> Result<TunnelDto, IpcError> {
    let forward = build_spec(&spec)?;
    let hub = state.sessions();
    let trust: Arc<dyn TrustStore> = Arc::new(VaultTrustStore::new(state.inner_handle()));

    // Stages 1 to 3, exactly as a session does them.
    let plan = plan_for_tunnel(state, &trust, &node_id)?;

    let cancel = CancellationToken::new();
    // The connection reports through an event stream it must have; nothing
    // renders it, so it is drained rather than left to fill and stall the
    // handshake. Warnings are logged: a weak algorithm on a tunnel is still
    // worth a line in the log even with no tab to show it in.
    let (events, mut incoming) = event_channel(remoter_proto::DEFAULT_EVENT_CAPACITY);
    let drain_name = plan.name.clone();
    let drain_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = drain_cancel.cancelled() => break,
                event = incoming.recv() => {
                    let Some(event) = event else { break };
                    if let remoter_proto::SessionEvent::Warning(warning) = event {
                        tracing::warn!(tunnel = %drain_name, ?warning, "a tunnel raised a warning");
                    }
                }
            }
        }
    });

    // ── 4 · Transport ──────────────────────────────────────────────────────
    // No prompt channel: a tunnel has no tab and therefore cannot obtain
    // consent for an unknown host key. Both the hops and the target refuse
    // rather than accept.
    let entry = TcpDialer;
    let dialer = SshHopDialer::new(events.clone(), cancel.clone());
    let transport = ChainBuilder::new(&entry, &dialer)
        .build(&plan.chain, &cancel)
        .await
        .map_err(|err| tunnel_error(&err, &plan.name))?;

    // ── 5 · Handshake and 6 · Authenticate ─────────────────────────────────
    let mut config = SshConnectionConfig::new(plan.target.clone(), plan.username.clone());
    config.via = plan.labels.clone();
    config.algorithms = AlgorithmPolicy::default();
    config.handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT;
    let connection = SshConnection::establish(
        transport,
        &config,
        &plan.credentials,
        Arc::clone(&trust),
        events.clone(),
        None,
        &cancel,
    )
    .await
    .map_err(|err| tunnel_error(&err, &plan.name))?;
    // The credential has done its work; dropping it zeroizes what it held.
    drop(plan.credentials);

    let connection = Arc::new(connection);
    let handle = match forward {
        ForwardSpec::Local { .. } => {
            start_local(Arc::clone(&connection), forward, cancel.clone()).await
        }
        ForwardSpec::Remote { .. } => {
            start_remote(Arc::clone(&connection), forward, cancel.clone()).await
        }
        ForwardSpec::Dynamic { .. } => {
            start_dynamic(Arc::clone(&connection), forward, cancel.clone()).await
        }
    }
    .map_err(|err| tunnel_error(&err, &plan.name))?;

    let id = hub.next_tunnel_id();
    let entry = TunnelEntry {
        handle,
        _connection: connection,
        cancel,
        node: node_id,
        name: plan.name,
    };
    let dto = entry.to_dto(id);
    hub.tunnels.lock().insert(id, entry);
    Ok(dto)
}

/// Closes a forward and the connection opened for it.
#[tauri::command]
pub(crate) fn tunnel_close(state: State<'_, AppState>, tunnel_id: u64) -> Result<(), IpcError> {
    tunnel_close_impl(&state, tunnel_id)
}

pub(crate) fn tunnel_close_impl(state: &AppState, tunnel_id: u64) -> Result<(), IpcError> {
    let hub = state.sessions();
    let entry = hub.tunnels.lock().remove(&tunnel_id).ok_or_else(|| {
        IpcError::new("tunnel.no-such-tunnel", "That tunnel is not open any more.")
            .with_actions(["Refresh the tunnel list"])
    })?;
    // Stopping cancels the listener and the accept loop; dropping the entry
    // drops the connection, which closes every channel still open on it.
    entry.stop();
    drop(entry);
    Ok(())
}

/// Every running forward, with its live counters.
#[tauri::command]
pub(crate) fn tunnel_list(state: State<'_, AppState>) -> Result<Vec<TunnelDto>, IpcError> {
    tunnel_list_impl(&state)
}

pub(crate) fn tunnel_list_impl(state: &AppState) -> Result<Vec<TunnelDto>, IpcError> {
    let hub = state.sessions();
    let tunnels = hub.tunnels.lock();
    Ok(tunnels
        .iter()
        .map(|(id, entry)| entry.to_dto(*id))
        .collect())
}

/// Validates the requested forward before anything is dialled.
fn build_spec(spec: &TunnelSpecDto) -> Result<ForwardSpec, IpcError> {
    match spec {
        TunnelSpecDto::Local {
            bind_address,
            bind_port,
            destination_host,
            destination_port,
            exposed,
        } => Ok(ForwardSpec::Local {
            bind: local_bind(bind_address.as_deref(), *bind_port, *exposed)?,
            destination: destination(destination_host, *destination_port)?,
        }),
        TunnelSpecDto::Remote {
            bind_address,
            bind_port,
            destination_host,
            destination_port,
            exposed,
        } => Ok(ForwardSpec::Remote {
            // The listener is on the *server*, so every spelling RFC 4254 §7.1
            // defines is legitimate here — including `*`, which no local socket
            // could ever be.
            bind: ForwardBind::new(bind_address.as_deref(), *bind_port, *exposed)
                .map_err(|err| ipc_error(&err))?,
            destination: destination(destination_host, *destination_port)?,
        }),
        TunnelSpecDto::Dynamic {
            bind_address,
            bind_port,
            exposed,
        } => Ok(ForwardSpec::Dynamic {
            bind: local_bind(bind_address.as_deref(), *bind_port, *exposed)?,
        }),
    }
}

fn local_bind(address: Option<&str>, port: u16, exposed: bool) -> Result<ForwardBind, IpcError> {
    ForwardBind::local(address, port, exposed).map_err(|err| {
        if exposed {
            ipc_error(&err)
        } else {
            IpcError::new(
                "tunnel.bind-exposed",
                format!(
                    "`{}` is not a loopback address, so this forward would be reachable from the \
                     local network. Tick the option that says so, or bind it to `localhost`.",
                    address.unwrap_or("")
                ),
            )
            .with_actions(["Bind to localhost", "Expose it deliberately"])
        }
    })
}

fn destination(host: &str, port: u16) -> Result<remoter_proto::HostPort, IpcError> {
    remoter_proto::HostPort::new(host, port).map_err(|err| ipc_error(&err))
}

/// A tunnel's failures, with the one difference from a session's: a tunnel has
/// no tab, so an unknown host key is not a question it can ask.
fn tunnel_error(error: &ProtocolError, name: &str) -> IpcError {
    if matches!(
        error.root_cause(),
        ProtocolError::HostKeyUnknown { .. } | ProtocolError::HostKeyRejected { .. }
    ) {
        return IpcError::new(
            "tunnel.host-key-unknown",
            format!(
                "`{name}` offered a host key Remoter has not been told to trust, and a tunnel has \
                 no window to ask in. Open a session to it first, review the fingerprint, and \
                 accept it there."
            ),
        )
        .with_actions([
            "Open a session to this connection",
            "Review the host key there",
        ]);
    }
    ipc_error(error)
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
    use remoter_proto_ssh::Exposure;

    #[test]
    fn the_default_bind_is_loopback() {
        let spec = TunnelSpecDto::Local {
            bind_address: None,
            bind_port: 5432,
            destination_host: String::from("db-01.internal"),
            destination_port: 5432,
            exposed: false,
        };
        let built = build_spec(&spec).unwrap();
        assert_eq!(built.exposure(), Exposure::Loopback);
        assert_eq!(built.bind().port(), 5432);
        assert_eq!(
            built.destination().map(ToString::to_string),
            Some(String::from("db-01.internal:5432"))
        );
    }

    /// A warning shown on a listener that is already open has arrived too late,
    /// so exposure is refused before the socket is bound rather than reported
    /// after.
    #[test]
    fn binding_beyond_loopback_needs_saying_so() {
        let spec = TunnelSpecDto::Dynamic {
            bind_address: Some(String::from("0.0.0.0")),
            bind_port: 1080,
            exposed: false,
        };
        let refused = build_spec(&spec);
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(String::from("tunnel.bind-exposed"))
        );

        let allowed = build_spec(&TunnelSpecDto::Dynamic {
            bind_address: Some(String::from("0.0.0.0")),
            bind_port: 1080,
            exposed: true,
        })
        .unwrap();
        assert_eq!(allowed.exposure(), Exposure::Network);
    }

    /// A local listener needs a real socket, so `*` — legitimate in a
    /// `tcpip-forward` request, which the *server* interprets — is refused here
    /// and accepted for a remote forward.
    #[test]
    fn a_wildcard_bind_is_a_remote_forwards_business_only() {
        let local = build_spec(&TunnelSpecDto::Local {
            bind_address: Some(String::from("*")),
            bind_port: 8080,
            destination_host: String::from("grafana.internal"),
            destination_port: 3000,
            exposed: true,
        });
        assert!(local.is_err());

        let remote = build_spec(&TunnelSpecDto::Remote {
            bind_address: Some(String::from("*")),
            bind_port: 9000,
            destination_host: String::from("127.0.0.1"),
            destination_port: 9000,
            exposed: true,
        });
        assert!(remote.is_ok());
    }

    #[test]
    fn a_spec_deserialises_from_the_shape_the_interface_sends() {
        let spec: TunnelSpecDto = serde_json::from_str(
            r#"{"direction":"local","bindAddress":null,"bindPort":5432,
                "destinationHost":"db-01","destinationPort":5432}"#,
        )
        .unwrap();
        let TunnelSpecDto::Local {
            bind_port, exposed, ..
        } = spec
        else {
            panic!("expected a local forward");
        };
        assert_eq!(bind_port, 5432);
        // Absent means not exposed. Exposure is never the default.
        assert!(!exposed);
    }

    #[test]
    fn closing_a_tunnel_that_is_already_gone_says_so() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };
        assert!(tunnel_list_impl(&state).unwrap().is_empty());
        assert_eq!(
            tunnel_close_impl(&state, 1).err().map(|e| e.code),
            Some(String::from("tunnel.no-such-tunnel"))
        );
    }
}
