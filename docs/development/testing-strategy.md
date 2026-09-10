# Testing Strategy

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

    /// Export then import reproduces the original exactly.
    #[test]
    fn export_import_roundtrip(tree in arb_tree()) {
        let exported = export_json(&tree)?;
        let imported = import_json(&exported)?;
        prop_assert_eq!(tree, imported);
    }
}
```

Targets: inheritance resolution, tree operations (move, copy, delete),
export/import round trips, gateway chain validation, and vault
serialise/deserialise.

## Fuzzing

`cargo-fuzz` on everything that parses untrusted input. This is not optional
here — importers read files from colleagues and old backups, and protocol
decoders read bytes from potentially compromised servers.

```
fuzz/fuzz_targets/
  import_mremoteng.rs
  import_royalts.rs
  import_putty.rs
  import_sshconfig.rs
  vault_parse.rs
  rdp_pdu_decode.rs
  vnc_rect_decode.rs
  sftp_packet_decode.rs
```

Corpora are seeded with real files and grown in CI. Fuzzing runs nightly and on
any pull request touching a parser. A crash is a release blocker, not a bug to
triage later.

## Integration tests

Real servers, in Docker (see
[getting-started.md](getting-started.md#integration-fixtures)):

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

Coverage: connect and authenticate for every protocol, jump chains, port
forwarding, file transfer including resume, disconnect handling, and reconnect.

## End-to-end tests

`tauri-driver` with WebdriverIO, against a built application. Few in number and
reserved for flows where a break would be severe:

1. Create a vault, add a connection, connect, disconnect
2. Lock and unlock with each slot type
3. Recovery key unlock after the password slot is destroyed
4. Import an mRemoteNG file and verify the resulting tree
5. Open several sessions, switch tabs, close them, verify nothing leaks
6. Change language, including to Arabic, and verify RTL layout

## Security testing

| Check | When |
|---|---|
| `cargo audit` | Every pull request and nightly |
| `cargo deny check` | Every pull request — licences, advisories, bans, duplicates |
| `gitleaks` | Every pull request — no committed secrets |
| Fuzzing | Nightly, and on parser changes |
| Dependency review | On any `Cargo.lock` or `package-lock.json` change |
| Memory-leak check | Long-running session soak test, weekly |

A dedicated test asserts that **no secret ever appears in a log**: it runs a
full session lifecycle with a tracing subscriber capturing everything at `trace`
level, then greps the output for the known test credentials. It fails if any
appears.

## Coverage

`cargo-llvm-cov`, reported but not gated on a global percentage — a number
invites tests written to move it.

Where coverage matters and is enforced:

| Area | Target |
|---|---|
| `remoter-vault` crypto | 100 % of branches |
| Inheritance resolution | 100 % |
| Import parsers | 90 %+ |
| Protocol state machines | 80 %+ |
| UI components | Meaningful behaviour, not snapshots |

## What we do not test

- Third-party library internals — that is their job
- Exact rendered pixels, except in the deliberate RTL and theme visual
  regression runs
- Snapshot tests of component markup, which mostly test that markup has not
  changed and break on every refactor
