# Session Pipeline

What happens between double-clicking a connection and seeing a shell prompt.

> **What ships.** The pipeline is real and all four adapters run it — including
> the gateway-chain stage, the host-key prompt and the credential borrow that
> never crosses into the WebView. Stage 2's recording notice does not exist,
> and stage 8's clipboard exists for RDP only; both are marked below.

## Stages

```
 1  Resolve      ──▶  EffectiveConnection (inheritance flattened)
 2  Authorise    ──▶  policy checks, confirmations  (⏳ no recording notice —
                      nothing records)
 3  Acquire      ──▶  credentials borrowed from the vault, scoped
 4  Transport    ──▶  gateway chain built hop by hop → Box<dyn Transport>
 5  Handshake    ──▶  protocol adapter negotiates, verifies host identity
 6  Authenticate ──▶  credentials used, then dropped and zeroized
 7  Attach       ──▶  session registered, tab bound, event stream live
 8  Run          ──▶  input/output, resize, clipboard  (◐ RDP only; ⏳ no recording)
 9  Terminate    ──▶  cancellation, cleanup, audit entry
```

Each stage can fail, and each failure has a distinct, actionable user-facing
message. "Connection failed" is not an acceptable outcome anywhere in this
pipeline — see [Failure taxonomy](#failure-taxonomy).

## 1 · Resolve

`remoter-core` flattens the inheritance chain into an `EffectiveConnection`: a
plain struct with no `Inherited<T>` left in it, plus provenance for every field
so the UI can explain where a value came from.

Resolution is a pure function of the tree. It performs no I/O and touches no
secrets, which makes it exhaustively testable — the property tests generate
random trees and assert that resolution is deterministic, terminates, and never
returns a value that does not appear somewhere on the ancestor path.

## 2 · Authorise

Before anything touches the network:

- Gateway chain validated — no cycles, depth ≤ 8, every hop resolvable
- Recording policy evaluated; if the session will be recorded, the user is told
  **before** it starts, never after
- Destructive-context checks: connecting to a node tagged `production` with
  broadcast enabled requires confirmation
- Concurrency limits: per-connection and global session caps

## 3 · Acquire

Credentials are borrowed, not copied:

```rust
let creds = vault.borrow(cred_ref, Purpose::Connect { protocol, host })?;
```

The borrow is scoped to the connection attempt. `Purpose` is recorded in the
audit log and is checked against the credential's own policy — a credential
marked "SSH only" cannot be borrowed for an RDP attempt, which prevents an
importer mistake or a mistyped protocol from spraying a password at the wrong
service.

A credential an importer recorded as a key file on disk —
`SecretKind::External` with the provider `openssh-identity-file` or
`putty-key-file` — is acquired by reading that file, bounded and into a
self-wiping buffer, after the same restriction check; the use is audited as a
borrow is. A file that is not there or not a key is a failure at this stage,
naming the path, never the file's content.

If no credential resolves, the user is prompted, with an option to save the
answer back to the vault at the level they choose (this connection, or the
folder, so it is inherited).

## 4 · Transport

The gateway chain is built outward from the local machine.

```
        Remoter                    bastion-1              bastion-2            target
           │                          │                      │                   │
           │──── TCP ────────────────▶│                      │                   │
           │──── SSH handshake ──────▶│  host key check #1   │                   │
           │──── auth ───────────────▶│  credential #1       │                   │
           │──── direct-tcpip ───────▶│─── TCP ─────────────▶│                   │
           │◀═══ stream A ════════════╡                      │                   │
           │──── SSH handshake over stream A ───────────────▶│  host key check #2│
           │──── auth ──────────────────────────────────────▶│  credential #2    │
           │──── direct-tcpip ──────────────────────────────▶│──── TCP ─────────▶│
           │◀═══ stream B ═══════════════════════════════════╡                   │
           │                                                                     │
           │──── target protocol handshake over stream B ───────────────────────▶│
```

Every hop is authenticated independently with its own credentials and its own
host key verification. The result is a `Box<dyn Transport>` — an
`AsyncRead + AsyncWrite` — that the protocol adapter uses without knowing or
caring how many machines it passes through.

This is why the `Protocol` trait takes an already-connected transport rather
than dialling out itself. **RDP through two SSH bastions is the same code path
as RDP on the LAN.** No protocol needs jump-host logic of its own.

`Transport` implementations:

| Kind | Use |
|---|---|
| `TcpTransport` | Direct |
| `SshChannelTransport` | A hop in a gateway chain |
| `Socks5Transport` | Through a SOCKS proxy |
| `HttpConnectTransport` | Through an HTTP CONNECT proxy |
| `TlsTransport<T>` | Wraps any of the above |
| `PluginTransport` | Provided by a WASM plugin — e.g. a cloud provider's session manager |

## 5 · Handshake

The adapter negotiates and verifies the far end's identity. Any identity
question — unknown SSH host key, untrusted TLS certificate — **suspends** the
pipeline and surfaces to the UI as an event. It is never auto-accepted, and the
decision is recorded in the audit log.

## 6 · Authenticate

Credentials are used and immediately dropped. On success, the `Secret` buffers
go out of scope and are zeroized. Interactive prompts (keyboard-interactive,
2FA, expired-password change) are relayed to the UI as events; the answers
travel back over a dedicated channel and are never held longer than the
challenge requires.

✅ The same holds for a password nothing stored supplies — RDP asks for one —
and for the passphrase of an encrypted key. Each is answered in the tab's
dialog through `session_prompt_answer`, which carries typed text and nothing
else: every open prompt is recorded as a trust decision or as a typed
question, and each of the two commands refuses the other kind, so no password
field can send `yes` to a host key. ⏳ Offering to save a typed answer back to
the vault, which §3 describes, is not built; nothing typed is kept.

## 7 · Attach

The session registers with the `SessionSupervisor`:

```rust
pub struct SessionHandle {
    pub id: SessionId,
    pub node_id: NodeId,
    pub protocol: ProtocolId,
    pub kind: SessionKind,             // Terminal | Framebuffer | FileTransfer
    pub capabilities: Capabilities,
    pub started_at: Timestamp,
    pub cancel: CancellationToken,
    pub events: broadcast::Receiver<SessionEvent>,
}
```

The frontend creates a tab bound to `SessionId` and subscribes to the event
stream. Capabilities determine which controls the tab shows — the UI never
hardcodes "RDP has a clipboard button".

## 8 · Run

```rust
pub enum SessionEvent {
    /// Terminal bytes, or an encoded framebuffer update. Sent as a raw
    /// byte payload, never JSON-encoded — see rendering.md.
    Data(Bytes),
    Resized { width: u16, height: u16 },
    ClipboardOffer(ClipboardFormats),
    /// What the remote copied, for the local clipboard. Redacting `Debug`.
    ClipboardContent(ClipboardData),
    /// Files on either clipboard: offered by the remote, saved from it, or
    /// read by it. Only where the session's policy lets files cross.
    ClipboardFiles(ClipboardFiles),
    /// Server needs something: host key decision, password, 2FA code.
    Prompt(Prompt),
    /// SFTP progress, RDP connection quality, latency samples.
    Progress(ProgressUpdate),
    Warning(SessionWarning),
    Closed(CloseReason),
}
```

Backpressure is explicit. A remote host can produce output faster than a WebView
can render it — `yes` over SSH, or a full-screen video over RDP. Each session
has a bounded output buffer; when it fills:

- **Terminal sessions** coalesce. Intermediate states of a fast-scrolling
  terminal are not worth rendering, so bytes are batched and flushed at the
  frame interval.
- **Framebuffer sessions** drop stale frames and keep the newest, merging dirty
  rectangles. Rendering a frame the user will never see costs latency on the one
  they will.
- **File transfers** apply real backpressure to the socket, because dropping
  data there would corrupt the file.

Auto-reconnect, where enabled, retries with exponential backoff and jitter,
capped, with a visible countdown and a cancel button. Reconnection reuses the
cached credential only if the user enabled that for the connection; otherwise it
prompts.

## 9 · Terminate

### A live session is not disconnected without being asked about

A disconnect cannot be undone, it interrupts whatever is running on the far
machine, and the control that starts it sits a few pixels from the tab the user
meant to switch to. So every route out of a **connected** session asks first,
and they all ask through the same question — a confirmation that one route
respects and another does not is worse than none, because it teaches the user
that closing is guarded and then it is not. The routes are the tab's close
control, a middle click on the tab, the `tab.close` shortcut, Disconnect in the
sessions panel, and the window's own close control. The last of those asks
**once, naming how many sessions would end**, rather than once per tab.

The question names what is at stake — the host, and anything the session knows
it would interrupt, such as a file transfer still moving in a docked pane —
because "are you sure?" tells the user nothing they did not already know.

It deliberately does **not** ask in three places:

- a tab whose session already failed or closed, which holds nothing to lose and
  whose dismissal never reaches the core at all;
- a connect that has not finished, which is cancelled from a button that says
  Cancel and is pressed by someone watching the attempt;
- locking the vault, which closes every session first. That is a security
  action — "I am leaving this machine" — and friction in front of it is friction
  in the wrong direction.

Declining leaves every session connected and nothing is sent to the core.
Accepting runs the teardown below, and the window close, where that is what was
asked, happens only after it returns.

Closing a tab cancels the session's `CancellationToken`. Before the tab
disappears, the session task MUST:

1. Send the protocol's clean-disconnect message where one exists
2. Close all channels and sockets
3. Flush and close recorder files
4. Tear down any tunnels opened for this session alone
5. Zeroize cached secrets
6. Write the audit entry
7. Deregister from the supervisor

A session that fails to terminate within a grace period is aborted forcefully
and logged as a defect. Leaked sessions are a correctness bug: the process holds
credentials, and a lingering task is a lingering exposure.

## Failure taxonomy

Every failure maps to a distinct message with a suggested next step.

| Stage | Failure | User-facing message |
|---|---|---|
| Resolve | No hostname | "This connection has no address. Open its settings to add one." |
| Resolve | Gateway cycle | "The gateway chain loops back on itself: A → B → A." |
| Authorise | Session limit | "You have 32 sessions open. Close one, or raise the limit in settings." |
| Acquire | Credential deleted | "The credential this connection used was deleted. Choose another, or enter one now." |
| Acquire | Purpose mismatch | "This credential is restricted to SSH and cannot be used for RDP." |
| Transport | DNS failure | "`host.example.com` could not be resolved. Check the name or your DNS." |
| Transport | Refused | "`10.0.0.5:22` refused the connection. Is the service running?" |
| Transport | Timeout | "`10.0.0.5:22` did not respond within 30 s. Check the firewall or the gateway." |
| Transport | Hop failed | "Could not reach the target through `bastion-2`. Hop 2 of 3 failed." |
| Handshake | Unknown host key | Prompt with fingerprint and randomart |
| Handshake | **Changed** host key | Blocking warning; possible man-in-the-middle |
| Handshake | No shared algorithm | "The server only offers algorithms Remoter no longer accepts: `ssh-rsa` (SHA-1)." |
| Handshake | TLS validation | "The certificate for `host` is not trusted: self-signed." + pin option |
| Authenticate | Rejected | "The server rejected these credentials." + re-prompt |
| Authenticate | Method unavailable | "The server does not accept password authentication. It offers: public key, keyboard-interactive." |
| Run | Disconnected | "The server closed the connection." + reconnect |
| Run | Network lost | "Network unreachable. Retrying in 4 s." + cancel |
| Run | Path not found | "There is nothing at that path on the server. It may have been moved, renamed or deleted since this folder was last read." |
| Run | Path permission denied | "The server refused access to that path. This is a file-permission refusal, not a sign-in problem." |
| Run | File operation refused | "The server could not complete that operation on this file and did not say why. A full disk, a quota, a read-only filesystem, a lock, or a rename across two filesystems all arrive in exactly this form." |

The pattern: name what failed, name where, and offer the next action. A message
that only says something went wrong forces the user to reproduce the problem
with a command-line tool, which is a small admission that the application is not
doing its job.

### A file-manager failure is not a connection failure

The last three rows are the taxonomy's newest, and they exist because borrowing
a neighbouring variant told the user something false about a connection that was
working perfectly.

`SSH_FX_NO_SUCH_FILE` was reported as `SettingInvalid { key: "path" }`, which
the interface renders as "the setting `path` is not usable" and points at the
connection editor. There is no `path` setting; the file had been moved since the
folder was last listed.

`SSH_FX_PERMISSION_DENIED` was reported as `AuthRejected`, which reads "the
server rejected these credentials" and offers a credential picker — on a session
that authenticated minutes earlier. "Who you are" and "what this file allows"
are different questions, and blurring them sends the reader off to re-check an
SSH key that is fine.

`SSH_FX_FAILURE`, version 3's single catch-all, fell through to
`ProtocolViolation`, which accuses the server of breaking the protocol when all
it did was run out of disk. Its message names the likely causes and admits it
cannot tell them apart, because the protocol genuinely cannot.

None of the three is an identity failure, none suspends the pipeline, and none
offers a credential action. They belong to stage 8 because the connection is up
and one operation on one path failed.
