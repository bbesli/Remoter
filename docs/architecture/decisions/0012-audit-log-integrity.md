# ADR-0012: No hash chain in v1.0; forward-secure sealing when the log has a second reader

- **Status**: Accepted
- **Date**: 2026-09-10
- **Implementation**: ✅ The decision here is to ship *no* hash chain, and that
  is what ships. ⏳ The external audit sink offered as the escape hatch for
  compliance users is not built.
- **Resolves the open question in**: [recording-audit.md](../../features/recording-audit.md)

## Context

The draft raised adding a hash chain to the audit log — each entry committing to
its predecessor — to make tampering detectable. It looked obviously worthwhile:
32 bytes and one hash per entry, for tamper evidence.

On analysis it is not worthwhile, and working out why produces a better answer
than building it.

## The analysis

The audit log lives inside the vault body, which is encrypted and authenticated
as a single unit with XChaCha20-Poly1305
([vault-format.md](../../security/vault-format.md)). So consider who could
tamper with it:

**An attacker without the vault key** cannot modify the log at all. They cannot
modify any byte of the body — the AEAD tag fails and the vault refuses to open.
A hash chain adds nothing here, because the existing construction already
provides strictly stronger protection.

**An attacker with the vault key** can decrypt the body, edit any entry, delete
any entry, recompute every chain link, re-encrypt, and produce a vault that
verifies perfectly. A hash chain keyed under a key they hold is no obstacle
whatsoever.

So a hash chain, in this construction, protects against nobody. It would be
**security theatre**: a mechanism that appears in a feature list, reads well in
documentation, and defends against no adversary in the threat model. Worse than
useless, because a user reading "tamper-evident audit log" would reasonably
believe something that is not true.

## What would actually work, and when it matters

Real tamper evidence against someone holding the key requires the verifier's
trust to rest on something the holder cannot rewrite. Two mechanisms do this:

**Forward-secure sealing** (the Schneier–Kelsey construction). A log key evolves
after every entry — `K_{i+1} = HKDF(K_i)` — and `K_i` is destroyed. Each entry
is authenticated under the key current at the time it was written. An attacker
who compromises the vault at time *t* cannot forge or alter any entry written
before *t*, because the keys that authenticated them no longer exist anywhere.
They can still truncate the tail, which is detectable only with an external
anchor or an expected entry count.

**External anchoring.** Periodically publishing the log head somewhere the vault
holder does not control.

Both are implementable. Neither is useful in v1.0, and the reason is worth
stating precisely: **in a single-user, local-first tool, the vault holder is the
auditor.** There is no second party whose trust the log needs to earn. Building
a mechanism whose entire purpose is to constrain the vault holder, in a product
where the vault holder is the only reader, is solving a problem that does not
yet exist.

It starts to exist the moment a second party reads the log — an organisation
auditing an administrator, or a compliance process treating the log as evidence.
That is the team and synchronisation scenario, which is v2.

## Decision

### v1.0: no hash chain, and precise documentation of the real guarantee

The audit log's integrity comes from the vault body's AEAD, and the
documentation says exactly that and no more:

> The audit log cannot be read or modified by anyone who cannot open the vault.
> It is **not** tamper-evident against someone who can: a person with your
> master password can edit the log, and Remoter cannot detect it. Tamper
> evidence against the vault holder requires forward-secure sealing, which
> Remoter will implement when the log is read by someone other than its owner.

Claiming less than a competitor and being accurate is better than claiming more
and being wrong. A user planning around the log's properties needs the true
ones.

### Specified now, implemented when there is a second reader

The forward-secure construction is specified in this ADR so that it can be
adopted without a format change:

```
K_0        = HKDF(VMK, "remoter:auditlog:v1")
entry_i    : MAC_i = BLAKE3-keyed(K_i, entry_i ‖ MAC_{i-1})
K_{i+1}    = HKDF(K_i, "remoter:auditlog:evolve")
K_i        destroyed immediately after computing MAC_i
```

The log table already carries the columns this needs. It is switched on by a
setting, not a migration.

Trigger conditions, any one of which starts the work:

1. Team synchronisation (v2), where the auditor is not the vault holder
2. A user with a concrete compliance requirement for the log as evidence
3. `Required` recording policy being adopted in an organisational deployment

### An optional external sink, for the users who need it now

For anyone with a compliance need before v2, an **opt-in external audit sink**
writes entries to a destination outside the vault — syslog, or an append-only
file — sealed with the forward-secure scheme above.

This is off by default and carries a plain warning, because an external log is
a copy of the connection inventory (asset A4 in the
[threat model](../../security/threat-model.md)) living outside the vault's
protection. That is a real trade, and it is the user's to make knowingly.

## Consequences

**Positive.** No effort spent on a mechanism that defends against nobody. The
documentation states a guarantee that is true, which is the property that
actually matters for a security tool. The real mechanism is specified and ready.

**Negative.** "Tamper-evident audit log" cannot go in the feature list, and a
competitor claiming it will look better on a comparison table. We accept that;
the alternative is claiming it falsely.

**Neutral.** The external sink gives compliance users a path now without
committing the core to a design before there is a second reader to design for.

## Revisit if

Any trigger condition above is met, or the audit log moves outside the encrypted
body for any reason — which would remove the AEAD protection this decision
depends on, and make the analysis start again from a different place.
