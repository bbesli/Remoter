# Testing Strategy

> **What ships.** Unit tests, property tests, fuzz targets and the "no secret in
> a log" assertion are real and run. ⏳ **There are no end-to-end tests** — no
> `tauri-driver`, no WebdriverIO, no `tests/e2e` directory. ⏳ Coverage is not
> measured: `cargo-llvm-cov` is not installed or run anywhere, so the targets in
> the table below are aspirations with nothing reporting against them. The
> integration tests that exist run against `scripts/dev-sshd.sh`, not Docker.

## Layers

```
        ╱╲          E2E — WebDriver against a built app
       ╱  ╲         few, slow, high confidence
      ╱────╲
     ╱      ╲       Integration — real servers in Docker
    ╱────────╲
   ╱          ╲     Property + fuzz — generated and hostile input
  ╱────────────╲
 ╱              ╲   Unit — pure logic, crypto known-answer tests
╱────────────────╲  many, fast
```

## Unit tests

Colocated in `#[cfg(test)] mod tests`. Fast, no I/O, no network.

Priority areas:

- **Inheritance resolution** — a pure function, so it is exhaustively testable.
  This is the most behaviour-carrying logic in `remoter-core`
- **Cryptographic primitives** — known-answer tests against published vectors
- **Protocol state machines** — sans-I/O designs make these testable without a
  socket, which is a large part of why IronRDP was chosen
- **Parsers** — every importer, on real files

### Cryptographic known-answer tests

Non-negotiable, sourced from the specifications:

| Primitive | Source |
|---|---|
| Argon2id | RFC 9106 |
| XChaCha20-Poly1305 | `draft-irtf-cfrg-xchacha` |
| HKDF-SHA256 | RFC 5869 appendix A |
| BLAKE3 | Reference implementation test suite |

Plus the vault-level tests listed in
[vault-format.md](../security/vault-format.md#test-vectors) — round trips
through every slot kind, recovery after destroying the password slot, tampered
headers, swapped ciphertexts, rolled-back revisions, and truncation at every
byte offset.

## Property tests

`proptest`, for invariants that must hold across all inputs rather than a few
examples:

```rust
proptest! {
    /// Resolution never invents a value: whatever it returns must appear
    /// somewhere on the path from the node to the root.
    #[test]
    fn resolution_is_grounded(tree in arb_tree(), node in arb_node_index()) {
        let resolved = resolve(&tree, node);
        prop_assert!(tree.path_to_root(node).any(|n| n.provides(&resolved)));
    }

    /// ⏳ Export then import reproduces the original exactly. Does not exist:
    /// neither `export_json` nor `import_json` is a function in this workspace.
    #[test]
    fn export_import_roundtrip(tree in arb_tree()) {
        let exported = export_json(&tree)?;
        let imported = import_json(&exported)?;
        prop_assert_eq!(tree, imported);
    }
}
```

Targets today: ✅ inheritance resolution, tree operations, and the importers.
⏳ Export/import round trips (no export), gateway chain validation and vault
serialise/deserialise have no property test.

## Fuzzing

`cargo-fuzz` on everything that parses untrusted input. This is not optional
here — importers read files from colleagues and old backups, and protocol
decoders read bytes from potentially compromised servers.

What exists:

```
fuzz/fuzz_targets/
  import_csv.rs
  import_mremoteng.rs
  import_sshconfig.rs
```

⏳ What the plan still wants, and does not have — every one of these reads bytes
from a file or a host the user does not control:

```
  import_royalts.rs        no importer to fuzz yet
  import_putty.rs          no importer to fuzz yet
  vault_parse.rs           the container header and body
  rdp_pdu_decode.rs        PDUs from a remote host
  vnc_rect_decode.rs       rectangles from a remote host
  sftp_packet_decode.rs    packets from a remote host
```

Corpora are seeded with real files and grown in CI. Fuzzing runs nightly and on
any pull request touching a parser. A crash is a release blocker, not a bug to
triage later.

## Integration tests

Real servers — a user-mode `sshd`, not Docker (see
[getting-started.md](getting-started.md#live-protocol-tests)). ⏳ There is no
`compose.yaml` and no `tests/fixtures`; the second SSH host a jump-chain test
needs does not exist either, so the example below does not run today.

```rust
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn ssh_connects_through_two_jump_hosts() {
    let chain = GatewayChain::new(vec![hop("localhost:2222"), hop("localhost:2224")]);
    let transport = build_transport(&chain).await.unwrap();
    let session = SshProtocol::new()
        .connect(transport, &config(), &creds(), sink(), token())
        .await
        .unwrap();
    assert_eq!(session.exec("echo ok").await.unwrap().trim(), "ok");
}
```

What is covered today: ✅ SSH connect and authenticate, SFTP browsing, both
transfer directions with progress, resume and its refusal, per-transfer
cancellation, a concurrent queue, recursive removal and a listing of deliberately
hostile file names. ◐ RDP against a server named in the environment. ⏳ VNC, jump
chains, port forwarding, disconnect handling and reconnect have no live test.

## End-to-end tests — ⏳ not built

None of these exist. There is no `tauri-driver` dependency, no WebdriverIO and no
`tests/e2e`. Several of the flows are covered at a lower level — the import
wizard, RTL layout and language switching all have component tests — but nothing
drives a built application.

The plan: `tauri-driver` with WebdriverIO, against a built application. Few in
number and reserved for flows where a break would be severe:

1. Create a vault, add a connection, connect, disconnect
2. Lock and unlock with each slot type
3. Recovery key unlock after the password slot is destroyed
4. Import an mRemoteNG file and verify the resulting tree
5. Open several sessions, switch tabs, close them, verify nothing leaks
6. Change language, including to Arabic, and verify RTL layout

## Security testing

| Check | When | |
|---|---|---|
| `cargo audit` | Every pull request | ✅ |
| `cargo deny check` | Every pull request — licences, bans, sources, advisories | ✅ |
| `gitleaks` | Every pull request — no committed secrets | ✅ |
| Fuzzing | Nightly, and on parser changes | ⏳ targets exist; nothing runs them on a schedule |
| Dependency review | On any `Cargo.lock` or `package-lock.json` change | ⏳ |
| Memory-leak check | Long-running session soak test, weekly | ⏳ |

A dedicated test asserts that **no secret ever appears in a log**: it runs a
full session lifecycle with a tracing subscriber capturing everything at `trace`
level, then greps the output for the known test credentials. It fails if any
appears.

## Coverage — ⏳ not measured

`cargo-llvm-cov` is not run anywhere, in CI or locally, so nothing below is
enforced or even reported. The intent stands: reported but not gated on a global
percentage, because a number invites tests written to move it.

Where coverage would matter and be enforced:

| Area | Target |
|---|---|
| `remoter-vault` crypto | 100 % of branches |
| Inheritance resolution | 100 % |
| Import parsers | 90 %+ |
| Protocol state machines | 80 %+ |
| UI components | Meaningful behaviour, not snapshots |

## What we do not test

- Third-party library internals — that is their job
- Exact rendered pixels. ⏳ There is no visual regression suite at all — no
  screenshot comparison, no Playwright, no image snapshots. RTL and theming are
  tested through the DOM and the computed direction instead, which catches a
  physical CSS property but not a layout that merely looks wrong
- Snapshot tests of component markup, which mostly test that markup has not
  changed and break on every refactor
