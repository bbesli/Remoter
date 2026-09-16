//! SSH sessions, over `russh`.
//!
//! Pure Rust on purpose: this code parses attacker-controlled bytes from a host
//! that may already be compromised, inside a process holding every credential
//! the user owns. See ADR-0003.
//!
//! # What lives here
//!
//! | Module | Owns |
//! |---|---|
//! | [`protocol`] | [`SshProtocol`] — the `Protocol` implementation the session pipeline calls |
//! | [`connection`] | [`SshConnection`]: one handshake, one authentication, every channel |
//! | [`auth`] | The ladder: agent, then key, then password, then keyboard-interactive |
//! | [`agent`] | Finding and using the platform SSH agent |
//! | [`keyfmt`] | OpenSSH, PKCS#8 and PuTTY `.ppk`, told apart by content |
//! | [`hostkey`] | The mandatory host key check, and what happens when a key changes |
//! | [`prompt`] | Asking the user something mid-handshake, and getting an answer back |
//! | [`algorithms`] | The negotiation policy, and the `legacy-crypto` feature |
//! | [`session`] | The PTY, the shell, `exec`, and the loop that drives them |
//! | [`sftp`] | Browsing and transferring, on the connection that is already open |
//! | [`channel`] | A `direct-tcpip` channel as a [`remoter_proto::Transport`] |
//! | [`dialer`] | [`SshHopDialer`] — one hop of a gateway chain |
//! | [`forward`] | Local, remote and dynamic port forwarding |
//! | [`socks`] | RFC 1928 parsing, for dynamic forwarding |
//! | [`bind`] | Where a forward listens, and why the default is loopback |
//! | [`error`] | `russh`'s failures, mapped onto the taxonomy |
//!
//! # The rules this crate is built around
//!
//! - **The transport is injected, never dialled** (ADR-0003). `russh` will
//!   happily open its own socket and this crate never lets it, which is what
//!   makes a three-hop chain the same code path as a direct connection.
//! - **Host key verification is mandatory**, with no setting to disable it.
//!   An unknown key is a prompt; a *changed* key is a hard failure that can
//!   only be replaced by typing a word off the screen.
//! - **Agent forwarding is off** unless the connection asks for it, and the
//!   handler refuses the channel rather than relying on the request not having
//!   been made.
//! - **No secret is formatted.** Credentials are borrowed inside closures,
//!   prompt answers live in `Zeroizing` buffers, and no error carries a
//!   `russh` message that could have a key in it.
//!
//! # Deviations from the specifications, and why
//!
//! **Forwarding lives here rather than in `remoter-tunnel`.**
//! `docs/architecture/project-structure.md` gives local, remote and dynamic
//! forwarding a crate of their own. Every one of them is an SSH channel: `-L`
//! and `-D` open `direct-tcpip`, and `-R` is a `tcpip-forward` global request
//! answered by channels arriving on this session's own handler. A separate
//! crate would depend on `russh` and on this crate's connection type — a
//! module in a different directory with a circular dependency. The document
//! should be corrected.
//!
//! **The post-quantum hybrid is `mlkem768x25519-sha256`, not
//! `sntrup761x25519-sha512`.** `docs/security/transport-security.md` names the
//! latter, which was OpenSSH's hybrid before 10.0 replaced it with the ML-KEM
//! one standardised as FIPS 203. `russh` 0.63 implements the ML-KEM hybrid and
//! not the sntrup761 one. The intent — a post-quantum hybrid, preferred where
//! the server offers it — is unchanged.
//!
//! **`russh` needs a C-backed crypto backend.** ADR-0003 asks for no C
//! dependency in the network-facing path, and `russh` 0.63 fails to compile
//! without either `ring` or `aws-lc-rs`. `ring` is selected as the smaller of
//! the two: `aws-lc-sys` builds a full C library and needs CMake, while `ring`
//! is a small, widely deployed assembly-and-C core. The protocol *parsers* —
//! the code that reads attacker-controlled bytes — remain pure Rust either
//! way, which is the property ADR-0003 is actually about.
//!
//! **SOCKS5 `UDP ASSOCIATE` is answered `X'07'`, command not supported.**
//! `docs/features/tunneling.md` lists it as supported. RFC 4254 defines
//! `direct-tcpip` and `direct-streamlocal` and nothing that carries a
//! datagram, so a SOCKS server whose only exit is an SSH session has nowhere
//! to put the UDP. It is parsed and refused explicitly rather than ignored, so
//! a client falls back instead of waiting.
//!
//! # A defect worth reporting upstream
//!
//! `ssh-key` 0.7 decodes a PuTTY Ed25519 private exponent with
//! `Mpint::as_bytes`, which keeps the leading zero byte a positive `mpint`
//! carries when the top bit is set (RFC 4251 §5), and then rejects the
//! 33-byte result as too long for a 32-byte scalar. Roughly half of all real
//! `.ppk` Ed25519 keys have that top bit set. The fix upstream is one line —
//! `as_positive_bytes`, as the ECDSA branch beside it already uses. Until it
//! lands, those keys fail to load; nothing in this crate can work around it
//! without reimplementing the format.

#![doc(html_no_source)]
#![forbid(unsafe_code)]

pub mod agent;
pub mod algorithms;
pub mod auth;
pub mod bind;
pub mod channel;
pub mod connection;
pub mod dialer;
pub mod error;
pub mod forward;
pub mod handler;
pub mod hostkey;
pub mod keyfmt;
pub mod prompt;
pub mod protocol;
pub mod session;
pub mod sftp;
pub mod socks;

#[cfg(any(test, feature = "integration-tests"))]
pub mod testing;

pub use agent::{Agent, AgentEndpoint};
pub use algorithms::{AlgorithmPolicy, is_weak};
pub use auth::{AuthContext, AuthReport, SshAuthMethod, authenticate};
pub use bind::{Exposure, ForwardBind, LOOPBACK};
pub use channel::SshChannelTransport;
pub use connection::{DEFAULT_HANDSHAKE_TIMEOUT, SshConnection, SshConnectionConfig};
pub use dialer::SshHopDialer;
pub use error::{SSH_ID, ssh_protocol_id};
pub use forward::{
    ForwardDirection, ForwardHandle, ForwardSpec, ForwardStats, ForwardStatus, RemoteForwards,
    start_dynamic, start_local, start_remote,
};
pub use handler::{SshHandler, SshHandlerError};
pub use hostkey::HostKeyChecker;
pub use keyfmt::{KeyFormat, PpkVersion, detect_key_format, needs_passphrase, parse_private_key};
pub use prompt::PromptChannel;
pub use protocol::{SshProtocol, schema};
pub use session::{
    DEFAULT_COLUMNS, DEFAULT_ROWS, DEFAULT_TERM, SshSession, TerminalSettings, capabilities,
    run_ssh_session,
};
pub use sftp::{
    DirectoryEntry, EntryKind, SftpBrowser, TransferDirection, TransferId, TransferQueue,
    TransferRequest, TransferState, TransferStatus, run_queue, run_queue_reporting,
};
pub use socks::{Socks5Address, Socks5Command, Socks5Error, Socks5Reply, Socks5Request};
